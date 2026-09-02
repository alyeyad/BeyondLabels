"""Parallel CVEPath runner for the RQ4 detection strengthening (R3C12).

Copy of the RQ1 ``run_experiment`` loop that parallelizes the per-call network
work with a thread pool (``workers``). It reuses every building block from
``cvepath_pipeline`` (file combinations, distractor selection, input accounting,
log writing) unchanged, so a run here is identical to the sequential pipeline
except that independent (cve, combo, prompt, run) calls execute concurrently.

Used to add the baseline-prompt predictions on the 105 positive CVEs (the
LLMPath positives already exist under output/runs). The original
``cvepath_pipeline.py`` is left untouched.
"""

from __future__ import annotations

from typing import Any, Dict, List

import src.cvepath_pipeline as cp
from src.detection_parallel import run_parallel
from src.llm_runner.runner import is_reasoning_model, send_prompt, setup_client
from src.utils.config import RunConfig
from src.utils.dataset import (
    flatten_file_combinations,
    get_file_combinations,
    read_file_contents,
)
from src.utils.prompts import construct_prompt, get_prompts


def build_positive_tasks(config: RunConfig, prompt_dict: Dict[str, str]) -> List[Dict[str, Any]]:
    """Assemble one task per (cve, file_combo, prompt, run). All local work
    (file reads, distractor selection, prompt construction) happens here; each
    task performs exactly one API call + log write."""
    targets = cp.collect_rq1_targets(config)
    if not targets:
        if config.run_all_cves:
            raise ValueError(
                f"No CVE folders found in {config.dataset_dir} "
                f"for languages {config.active_languages()}"
            )
        raise FileNotFoundError(
            f"No CVE found for {config.cve} in languages {config.active_languages()}"
        )

    print(f"Found {len(targets)} RQ1 target(s).")
    temperature = None if is_reasoning_model(config.model) else config.temperature

    tasks: List[Dict[str, Any]] = []
    for cve, folder_name, language in targets:
        file_combinations = get_file_combinations(
            cve_folder=folder_name,
            language=language,
            dataset_dir=config.dataset_dir,
        )
        if not file_combinations:
            print(f"[WARN] No input file combinations found for {cve} ({language})")
            continue

        source_code_contents = read_file_contents(
            dataset_dir=config.dataset_dir,
            language=language,
            slug=folder_name,
            file_combinations=file_combinations,
        )
        if not source_code_contents:
            print(f"[WARN] No source files could be read for {cve} ({language})")
            continue

        reference_files = sorted(flatten_file_combinations(file_combinations))

        for file_combo in file_combinations:
            needed_code = {
                relative_path: source_code_contents[relative_path]
                for relative_path in file_combo
                if relative_path in source_code_contents
            }
            if not needed_code:
                print(f"[WARN] No readable files found for combination: {file_combo}")
                continue

            distractors, distractor_meta = cp.select_distractors_for_combo(
                config=config,
                language=language,
                folder_name=folder_name,
                needed_files=list(needed_code.keys()),
                needed_code=needed_code,
                reference_files=reference_files,
            )

            raw_code = dict(needed_code)
            for rel_path, rel_code in distractors:
                raw_code[rel_path] = rel_code

            input_accounting = cp.compute_input_accounting(needed_code, distractors)

            for prompt_name, prompt_template in prompt_dict.items():
                input_prompt, input_text = construct_prompt(
                    template=prompt_template,
                    language=language,
                    files=raw_code,
                )
                for run_index in range(max(1, config.runs)):
                    tasks.append({
                        "cve": cve,
                        "language": language,
                        "prompt_name": prompt_name,
                        "input_prompt": input_prompt,
                        "input_text": input_text,
                        "file_combo": file_combo,
                        "run_index": run_index,
                        "run_seed": config.seed + run_index,
                        "temperature": temperature,
                        "distractor_meta": distractor_meta,
                        "input_accounting": input_accounting,
                    })
    return tasks


def _run_positive_task(client, config: RunConfig, task: Dict[str, Any]) -> None:
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
              f"run {task['run_index']} for {task['cve']}: {exc}")
        return

    if response is None:
        print(f"[WARN] empty (None) response for {task['prompt_name']} "
              f"run {task['run_index']} for {task['cve']}; treating as ''")
        response = ""

    cp.save_run_log(
        cve=task["cve"],
        config=config,
        prompt_name=task["prompt_name"],
        language=task["language"],
        input_prompt=task["input_prompt"],
        input_text=task["input_text"],
        response=response,
        reasoning_content=reasoning_content,
        file_combination=task["file_combo"],
        usage=usage,
        run_index=task["run_index"],
        seed_requested=task["run_seed"],
        temperature_requested=task["temperature"],
        distractor_meta=task["distractor_meta"],
        input_accounting=task["input_accounting"],
    )


def run_experiment_parallel(config: RunConfig, workers: int = 1) -> None:
    if config.task != "rq1":
        raise ValueError(f"Expected task='rq1', got {config.task!r}")

    prompt_dict = get_prompts(config)
    if not prompt_dict:
        raise ValueError("No prompts were loaded.")

    tasks = build_positive_tasks(config, prompt_dict)
    client = setup_client(config.provider)
    run_parallel(
        tasks,
        lambda task: _run_positive_task(client, config, task),
        workers=workers,
        desc="positive calls",
    )
