from datetime import datetime


from config import RunConfig
from dataset import find_cve, get_file_combinations, read_file_contents
from prompts import construct_prompt, get_prompts
from llm_runner.runner import send_prompt, setup_client
from llm_runner.logger import save_log


def make_output_filename(
    cve_id: str,
    model: str,
    prompt_name: str,
    language: str,
    timestamp: str | None = None,
) -> str:
    """
    Build a safe output filename for a run log.
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return (
        f"{model}_run_{cve_id}_{prompt_name}_{language}_{timestamp}.json"
        .replace("/", "__")
    )


def save_run_log(
    *,
    config: RunConfig,
    prompt_name: str,
    language: str,
    input_prompt: str,
    input_text: str,
    response: str,
    reasoning_content: str,
    file_combination: list[str],
    usage
) -> None:
    """
    Save one experiment run to disk.
    """
    out_file = make_output_filename(
        cve_id=config.cve,
        model=config.model,
        prompt_name=prompt_name,
        language=language,
    )

    save_log(
        {
            "cve": config.cve,
            "file_combination": file_combination,
            "prompt_name": prompt_name,
            "language": language,
            "model": config.model.replace('/','__'),
            "provider": config.provider,
            "prompt": input_prompt,
            "input": input_text,
            "output": response,
            "reasoning_content": reasoning_content,
            "actual_label": config.actual_label,
            "usage": usage
        },
        out_dir=str(config.out_dir),
        fname=out_file,
    )


def print_prompt_preview(prompt_name: str, input_prompt: str, input_text: str) -> None:
    """
    Print a short preview of the prompt and code input.
    """
    print(f"\n[Prompt: {prompt_name}]")
    print(input_prompt[:200] + "..." if len(input_prompt) > 200 else input_prompt)
    print("==" * 20)
    print(input_text[:500] + "..." if len(input_text) > 500 else input_text)
    print("Sending ...")


def run_experiment(config: RunConfig) -> None:
    """
    Run the RQ1 experiment for a single CVE.
    """
    folder_name, language = find_cve(config.cve, config.dataset_dir)
    if not folder_name or not language:
        raise FileNotFoundError(f"No CVE found for {config.cve}")

    prompt_dict = get_prompts(config)
    if not prompt_dict:
        raise ValueError("No prompts were loaded.")

    file_combinations = get_file_combinations(
        cve_folder=folder_name,
        language=language,
        dataset_dir=config.dataset_dir,
    )
    if not file_combinations:
        raise ValueError("No input file combinations found.")

    source_code_contents = read_file_contents(
        dataset_dir=config.dataset_dir,
        language=language,
        slug=folder_name,
        file_combinations=file_combinations,
    )
    if not source_code_contents:
        raise ValueError("No source files could be read.")

    client = setup_client(config.provider)

    for file_combo in file_combinations:
        raw_code = {
            relative_path: content
            for relative_path, content in source_code_contents.items()
            if relative_path in file_combo
        }

        if not raw_code:
            print(f"[WARN] No readable files found for combination: {file_combo}")
            continue

        for prompt_name, prompt_template in prompt_dict.items():
            input_prompt, input_text = construct_prompt(
                template=prompt_template,
                language=language,
                files=raw_code,
            )

            print_prompt_preview(prompt_name, input_prompt, input_text)

            try:
                response, reasoning_content, usage = send_prompt(
                    client,
                    input_prompt,
                    input_text,
                    config.model,
                )
            except Exception as exc:
                print(f"[ERROR] send_prompt failed with {prompt_name}: {exc}")
                continue

            preview = response[:200] + "..." if len(response) > 200 else response
            print(f"Response: {preview}")

            try:
                save_run_log(
                    config=config,
                    prompt_name=prompt_name,
                    language=language,
                    input_prompt=input_prompt,
                    input_text=input_text,
                    response=response,
                    reasoning_content=reasoning_content,
                    file_combination=file_combo,
                    usage=usage
                )
            except Exception as exc:
                print(f"[ERROR] save_log failed with {prompt_name}: {exc}")
                continue