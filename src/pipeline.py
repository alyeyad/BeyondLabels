from datetime import datetime
from typing import Dict

from src.config import RunConfig
from src.llm_runner.logger import save_log
from src.llm_runner.runner import send_prompt, setup_client

from .dataset import get_file_combinations, list_all_cve_folders, read_file_contents
from .prompts import construct_prompt, get_prompts


def make_output_filename(
    cve: str,
    model: str,
    prompt_name: str,
    language: str,
    timestamp: str | None = None,
) -> str:
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    safe_cve = cve.replace("/", "__")
    safe_model = model.replace("/", "__")

    return f"{safe_cve}_{safe_model}_run_{prompt_name}_{language}_{timestamp}.json"


def save_run_log(
    *,
    cve: str,
    config: RunConfig,
    prompt_name: str,
    language: str,
    input_prompt: str,
    input_text: str,
    response: str,
    reasoning_content: str,
    file_combination: list[str],
    usage: Dict
) -> None:
    out_file = make_output_filename(
        cve=cve,
        model=config.model,
        prompt_name=prompt_name,
        language=language,
    )

    save_log(
        {
            "task": config.task,
            "cve": cve,
            "file_combination": file_combination,
            "prompt_name": prompt_name,
            "language": language,
            "model": config.model,
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
    print(f"\n[Prompt: {prompt_name}]")
    print(input_prompt[:200] + "..." if len(input_prompt) > 200 else input_prompt)
    print("==" * 20)
    print(input_text[:500] + "..." if len(input_text) > 500 else input_text)
    print("Sending ...")


def collect_rq1_targets(config: RunConfig) -> list[tuple[str, str, str]]:
    """
    Returns:
        list of (cve, folder_name, language)
    """
    allowed_languages = set(config.active_languages())
    all_targets = [
        (folder_name.split("_", 1)[0], folder_name, language)
        for folder_name, language in list_all_cve_folders(config.dataset_dir)
        if language in allowed_languages
    ]

    if config.run_all_cves:
        return all_targets

    assert config.cve is not None
    return [
        (cve, folder_name, language)
        for cve, folder_name, language in all_targets
        if cve == config.cve
    ]


def run_single_cve(
    *,
    config: RunConfig,
    cve: str,
    folder_name: str,
    language: str,
    client,
    prompt_dict: dict[str, str],
) -> None:
    print(f"\n=== Running {cve} ({language}) ===")

    file_combinations = get_file_combinations(
        cve_folder=folder_name,
        language=language,
        dataset_dir=config.dataset_dir,
    )
    if not file_combinations:
        print(f"[WARN] No input file combinations found for {cve} ({language})")
        return

    source_code_contents = read_file_contents(
        dataset_dir=config.dataset_dir,
        language=language,
        slug=folder_name,
        file_combinations=file_combinations,
    )
    if not source_code_contents:
        print(f"[WARN] No source files could be read for {cve} ({language})")
        return

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
                print(f"[ERROR] send_prompt failed with {prompt_name} for {cve}: {exc}")
                continue

            preview = response[:200] + "..." if len(response) > 200 else response
            print(f"Response: {preview}")

            try:
                save_run_log(
                    cve=cve,
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
                print(f"[ERROR] save_log failed with {prompt_name} for {cve}: {exc}")
                continue


def run_experiment(config: RunConfig) -> None:
    if config.task != "rq1":
        raise ValueError(f"Expected task='rq1', got {config.task!r}")

    prompt_dict = get_prompts(config)
    if not prompt_dict:
        raise ValueError("No prompts were loaded.")

    targets = collect_rq1_targets(config)
    if not targets:
        if config.run_all_cves:
            raise ValueError(
                f"No CVE folders found in {config.dataset_dir} for languages {config.active_languages()}"
            )
        raise FileNotFoundError(
            f"No CVE found for {config.cve} in languages {config.active_languages()}"
        )

    print(f"Found {len(targets)} RQ1 target(s).")

    client = setup_client(config.provider)

    for cve, folder_name, language in targets:
        run_single_cve(
            config=config,
            cve=cve,
            folder_name=folder_name,
            language=language,
            client=client,
            prompt_dict=prompt_dict,
        )