from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from src.config import RunConfig
from src.llm_runner.logger import save_log
from src.llm_runner.runner import send_prompt, setup_client
from src.negative_dataset import (
    get_sample_record,
    list_sample_folders,
    read_single_source_file,
)
from src.prompts import construct_prompt, get_prompts


def make_output_filename(
    sample_id: str,
    model: str,
    prompt_name: str,
    language: str,
    timestamp: str | None = None,
) -> str:
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    safe_sample_id = sample_id.replace("/", "__")
    safe_model = model.replace("/", "__")

    return f"{safe_sample_id}_{safe_model}_{prompt_name}_{language}_{timestamp}.json"


def print_prompt_preview(prompt_name: str, input_prompt: str, input_text: str) -> None:
    print(f"\n[Prompt: {prompt_name}]")
    print(input_prompt[:200] + "..." if len(input_prompt) > 200 else input_prompt)
    print("==" * 20)
    print(input_text[:500] + "..." if len(input_text) > 500 else input_text)
    print("Sending ...")


def save_negative_run_log(
    *,
    config: RunConfig,
    language: str,
    sample_id: str,
    source_file: str,
    metadata_file: str | None,
    metadata: dict[str, Any] | None,
    prompt_name: str,
    input_prompt: str,
    input_text: str,
    response: str,
    reasoning_content: str,
    usage: Dict
) -> None:
    out_file = make_output_filename(
        sample_id=sample_id,
        model=config.model,
        prompt_name=prompt_name,
        language=language,
    )

    save_log(
        {
            "task": config.task,
            "sample_id": sample_id,
            "language": language,
            "source_file": source_file,
            "metadata_file": metadata_file,
            "metadata": metadata,
            "prompt_name": prompt_name,
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


def run_negative_samples(config: RunConfig) -> None:
    if config.task != "negative":
        raise ValueError(f"Expected task='negative', got {config.task!r}")

    prompt_dict = get_prompts(config)
    if not prompt_dict:
        raise ValueError("No prompts were loaded.")

    client = setup_client(config.provider)

    found_any_samples = False

    for language in config.active_languages():
        sample_dirs = list_sample_folders(Path(config.dataset_dir), language)

        if not sample_dirs:
            print(f"[WARN] No sample folders found for language={language}")
            continue

        found_any_samples = True
        print(f"Found {len(sample_dirs)} sample folders for language={language}.")

        for sample_dir in sample_dirs:
            record = get_sample_record(sample_dir)
            if record is None:
                print(f"[WARN] No source file found in {sample_dir}")
                continue

            sample_id = record["sample_id"]
            source_path: Path = record["source_path"]
            metadata_path: Path | None = record["metadata_path"]
            metadata: dict[str, Any] | None = record["metadata"]

            print(f"\n=== Running sample {sample_id} ({language}) ===")

            try:
                files = read_single_source_file(source_path)
            except Exception as exc:
                print(f"[WARN] Could not read source file for {sample_id}: {exc}")
                continue

            for prompt_name, prompt_template in prompt_dict.items():
                input_prompt, input_text = construct_prompt(
                    template=prompt_template,
                    language=language,
                    files=files,
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
                    print(f"[ERROR] send_prompt failed with {prompt_name} for {sample_id}: {exc}")
                    continue

                preview = response[:200] + "..." if len(response) > 200 else response
                print(f"Response: {preview}")

                try:
                    save_negative_run_log(
                        config=config,
                        language=language,
                        sample_id=sample_id,
                        source_file=source_path.name,
                        metadata_file=metadata_path.name if metadata_path else None,
                        metadata=metadata,
                        prompt_name=prompt_name,
                        input_prompt=input_prompt,
                        input_text=input_text,
                        response=response,
                        reasoning_content=reasoning_content,
                        usage=usage
                    )
                except Exception as exc:
                    print(f"[ERROR] save_log failed with {prompt_name} for {sample_id}: {exc}")
                    continue

    if not found_any_samples:
        raise ValueError(
            f"No sample folders found in {config.dataset_dir} for languages {config.active_languages()}"
        )