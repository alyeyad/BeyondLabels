"""Detection variant of the negative-samples pipeline (R3C12).

This is a *copy* of ``negative_pipeline.py`` adapted for the RQ4 detection
strengthening. It differs from the original only in that it:

  * runs each (sample, prompt) pair ``config.runs`` times (multi-run majority),
  * uses the RQ1 / R2C3 decoding settings per model
    (``temperature = None`` for reasoning models, otherwise ``config.temperature``;
    ``seed = config.seed + run_index`` forwarded for OpenAI chat models),
    * tags the output filename with ``_k{k}_r{run_index}`` and logs the run index,
    seed, temperature, and distractor selection so majority aggregation is auditable.

The original ``negative_pipeline.py`` is left untouched.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from src.detection_parallel import run_parallel
from src.llm_runner.logger import save_log
from src.llm_runner.runner import is_reasoning_model, send_prompt, setup_client

from src.utils.config import DEFAULT_CVEPATH_DATASET_DIR, RunConfig
from src.utils.distractors import (
    build_negative_checkout_index,
    empty_negative_distractor_meta,
    sample_negative_test_docs_distractors,
)
from src.utils.negative_dataset import (
    get_sample_record,
    list_sample_folders,
    read_single_source_file,
)
from src.utils.prompts import construct_prompt, get_prompts


def _k_label(config: RunConfig) -> str:
    return str(config.distractors).strip().lower() or "0"


def make_output_filename(
    sample_id: str,
    model: str,
    prompt_name: str,
    language: str,
    run_index: int,
    k: str = "0",
    timestamp: str | None = None,
) -> str:
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    safe_sample_id = sample_id.replace("/", "__")
    safe_model = model.replace("/", "__")

    return (
        f"{safe_sample_id}_{safe_model}_{prompt_name}_{language}"
        f"_k{k}_r{run_index}_{timestamp}.json"
    )


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
    usage: Dict,
    run_index: int,
    seed_requested: int,
    temperature_requested,
    k: str = "0",
    distractor_meta: dict[str, Any] | None = None,
) -> None:
    out_file = make_output_filename(
        sample_id=sample_id,
        model=config.model,
        prompt_name=prompt_name,
        language=language,
        run_index=run_index,
        k=k,
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
            "run_index": run_index,
            "total_runs": config.runs,
            "seed_requested": seed_requested,
            "temperature_requested": temperature_requested,
            "usage": usage,
            "distractors_k": k,
            "distractor_meta": distractor_meta or empty_negative_distractor_meta(k=k),
        },
        out_dir=str(config.out_dir),
        fname=out_file,
    )


def _run_negative_task(client, config: RunConfig, task: Dict[str, Any]) -> None:
    try:
        response, reasoning_content, usage = send_prompt(
            client,
            task["input_prompt"],
            task["input_text"],
            config.model,
            temperature=task["temperature"],
            seed=task["run_seed"],
        )
    except Exception as exc:
        print(f"[ERROR] send_prompt failed with {task['prompt_name']} "
              f"run {task['run_index']} for {task['sample_id']}: {exc}")
        return

    if response is None:
        print(f"[WARN] empty (None) response for {task['prompt_name']} "
              f"run {task['run_index']} for {task['sample_id']}; treating as ''")
        response = ""

    save_negative_run_log(
        config=config,
        language=task["language"],
        sample_id=task["sample_id"],
        source_file=task["source_file"],
        metadata_file=task["metadata_file"],
        metadata=task["metadata"],
        prompt_name=task["prompt_name"],
        input_prompt=task["input_prompt"],
        input_text=task["input_text"],
        response=response,
        reasoning_content=reasoning_content,
        usage=usage,
        run_index=task["run_index"],
        seed_requested=task["run_seed"],
        temperature_requested=task["temperature"],
        k=task.get("k", "0"),
        distractor_meta=task.get("distractor_meta"),
    )


def _exclude_names(source_path: Path, metadata: dict[str, Any] | None) -> list[str]:
    names = [source_path.name]
    if metadata:
        file_name = metadata.get("file_name")
        if file_name:
            names.append(str(file_name))
    return names


def build_negative_tasks(config: RunConfig, prompt_dict: Dict[str, str]) -> list[Dict[str, Any]]:
    """Assemble one task per (sample, prompt, run). Prompt construction and
    file reads happen here (cheap, local); each task performs one API call."""
    # Reasoning models reject a sampling temperature -> omit it (mirror cvepath).
    temperature = None if is_reasoning_model(config.model) else config.temperature
    k_label = _k_label(config)
    indexes: dict[str, tuple] = {}
    listing_cache: dict[Path, list[str]] = {}
    if config.distractors_enabled():
        cvepath_dir = DEFAULT_CVEPATH_DATASET_DIR
        repos_dir = Path(config.distractor_repos_dir)
        for language in config.active_languages():
            by_project, all_repos = build_negative_checkout_index(
                cvepath_dir, repos_dir, language
            )
            indexes[language] = (by_project, all_repos)
            if not all_repos:
                print(
                    f"[WARN] No cloned checkouts for language={language} under "
                    f"{repos_dir}. Run: python scripts/clone_cvepath_repos.py"
                )

    tasks: list[Dict[str, Any]] = []
    for language in config.active_languages():
        sample_dirs = list_sample_folders(Path(config.dataset_dir), language)
        if not sample_dirs:
            print(f"[WARN] No sample folders found for language={language}")
            continue

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

            try:
                files = read_single_source_file(source_path)
            except Exception as exc:
                print(f"[WARN] Could not read source file for {sample_id}: {exc}")
                continue

            if config.distractors_enabled():
                by_project, all_repos = indexes[language]
                project = (metadata or {}).get("project")
                selected, distractor_meta = sample_negative_test_docs_distractors(
                    language=language,
                    project=project,
                    sample_id=sample_id,
                    model=config.model,
                    k=config.distractors,
                    seed=config.distractor_seed,
                    by_project=by_project,
                    all_repos=all_repos,
                    exclude=_exclude_names(source_path, metadata),
                    listing_cache=listing_cache,
                )
                for key, raw in selected:
                    files[key] = raw
            else:
                distractor_meta = empty_negative_distractor_meta(
                    seed=config.distractor_seed, k=0
                )

            for prompt_name, prompt_template in prompt_dict.items():
                input_prompt, input_text = construct_prompt(
                    template=prompt_template,
                    language=language,
                    files=files,
                )
                for run_index in range(max(1, config.runs)):
                    tasks.append({
                        "language": language,
                        "sample_id": sample_id,
                        "source_file": source_path.name,
                        "metadata_file": metadata_path.name if metadata_path else None,
                        "metadata": metadata,
                        "prompt_name": prompt_name,
                        "input_prompt": input_prompt,
                        "input_text": input_text,
                        "run_index": run_index,
                        "run_seed": config.seed + run_index,
                        "temperature": temperature,
                        "k": k_label,
                        "distractor_meta": distractor_meta,
                    })
    return tasks


def run_negative_samples_detect(config: RunConfig, workers: int = 1) -> None:
    if config.task != "negative":
        raise ValueError(f"Expected task='negative', got {config.task!r}")

    prompt_dict = get_prompts(config)
    if not prompt_dict:
        raise ValueError("No prompts were loaded.")

    tasks = build_negative_tasks(config, prompt_dict)
    if not tasks:
        raise ValueError(
            f"No sample folders found in {config.dataset_dir} "
            f"for languages {config.active_languages()}"
        )

    client = setup_client(config.provider)
    run_parallel(
        tasks,
        lambda task: _run_negative_task(client, config, task),
        workers=workers,
        desc="negative calls",
    )
