from datetime import datetime
from typing import Dict, List, Tuple

from src.llm_runner.logger import save_log
from src.llm_runner.runner import is_reasoning_model, send_prompt, setup_client

from src.utils.config import RunConfig
from src.utils.dataset import (
    flatten_file_combinations,
    get_file_combinations,
    list_all_cve_folders,
    read_file_contents,
)
from src.utils.distractors import char_budget_for, sample_distractors
from src.utils.prompts import (
    add_line_numbers_to_content,
    build_input_text,
    construct_prompt,
    get_prompts,
)

# Characters reserved for the prompt template when budgeting distractors.
_TEMPLATE_CHAR_RESERVE = 4000


def make_output_filename(
    cve: str,
    model: str,
    prompt_name: str,
    language: str,
    run_index: int = 0,
    k_label: str = "0",
    timestamp: str | None = None,
) -> str:
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    safe_cve = cve.replace("/", "__")
    safe_model = model.replace("/", "__")

    return (
        f"{safe_cve}_{safe_model}_run_{prompt_name}_{language}"
        f"_k{k_label}_r{run_index}_{timestamp}.json"
    )


def compute_input_accounting(
    needed_code: Dict[str, str],
    distractors: List[Tuple[str, str]],
) -> Dict:
    """Split the assembled prompt into reference and distractor contributions.

    Sizes are measured on the line-numbered text actually sent, so
    ``needed_lines`` equals the ``numInputLines`` the same combination would
    produce at k=0 and the two conditions stay directly comparable.
    """
    needed_text = build_input_text(needed_code)
    merged = dict(needed_code)
    for rel_path, rel_code in distractors:
        merged[rel_path] = rel_code
    total_text = build_input_text(merged)

    needed_lines = len(needed_text.splitlines())
    total_lines = len(total_text.splitlines())

    return {
        "needed_file_count": len(needed_code),
        "needed_lines": needed_lines,
        "needed_chars": len(needed_text),
        "distractor_file_count": len(distractors),
        "distractor_lines": total_lines - needed_lines,
        "distractor_chars": len(total_text) - len(needed_text),
        "total_lines": total_lines,
        "total_chars": len(total_text),
        "distractor_char_share": (
            round(1 - len(needed_text) / len(total_text), 4) if total_text else 0.0
        ),
        "per_distractor": [
            {
                "path": rel_path,
                "lines": len(add_line_numbers_to_content(rel_code).splitlines()),
                "chars": len(add_line_numbers_to_content(rel_code)),
            }
            for rel_path, rel_code in distractors
        ],
    }


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
    usage: Dict,
    run_index: int,
    seed_requested: int,
    temperature_requested,
    distractor_meta: Dict,
    input_accounting: Dict,
) -> None:
    k_label = str(config.distractors).strip().lower()
    out_file = make_output_filename(
        cve=cve,
        model=config.model,
        prompt_name=prompt_name,
        language=language,
        run_index=run_index,
        k_label=k_label,
    )

    save_log(
        {
            "task": config.task,
            "cve": cve,
            "file_combination": file_combination,
            # Explicit so downstream analysis never has to infer the reference
            # set from the prompt's file headers, which would also match
            # distractors once k > 0.
            "needed_files": file_combination,
            "prompt_name": prompt_name,
            "language": language,
            "model": config.model,
            "provider": config.provider,
            "prompt": input_prompt,
            "input": input_text,
            "output": response,
            "reasoning_content": reasoning_content,
            "actual_label": config.actual_label,
            "usage": usage,
            "run_index": run_index,
            "total_runs": config.runs,
            "temperature_requested": temperature_requested,
            "seed_requested": seed_requested,
            "distractors_k": k_label,
            "distractors_requested": distractor_meta["distractors_requested"],
            "distractors_used": distractor_meta["distractors_used"],
            "distractor_files": distractor_meta["distractor_files"],
            "distractor_candidate_count": distractor_meta["candidate_count"],
            "distractor_skipped_empty": distractor_meta["skipped_empty"],
            "distractor_min_nonblank_lines": distractor_meta["min_nonblank_lines"],
            "distractor_excluded_reference_files": distractor_meta["excluded_reference_files"],
            "distractor_seed": distractor_meta["distractor_seed"],
            "sampling_scope": distractor_meta["sampling_scope"],
            "budget_truncated": distractor_meta["budget_truncated"],
            "input_accounting": input_accounting,
        },
        out_dir=str(config.out_dir),
        fname=out_file,
    )


def _empty_distractor_meta(config: RunConfig) -> Dict:
    return {
        "distractor_seed": config.distractor_seed,
        "sampling_scope": "count",
        "distractors_requested": 0,
        "distractors_used": 0,
        "distractor_files": [],
        "candidate_count": 0,
        "budget_truncated": False,
        "min_nonblank_lines": 0,
        "skipped_empty": 0,
        "excluded_reference_files": [],
    }


def select_distractors_for_combo(
    *,
    config: RunConfig,
    language: str,
    folder_name: str,
    needed_files: List[str],
    needed_code: Dict[str, str],
    reference_files: List[str],
) -> Tuple[List[Tuple[str, str]], Dict]:
    """Sample distractors once per file combination so every prompt/run variant
    sees an identical, comparable input set."""
    if not config.distractors_enabled():
        return [], _empty_distractor_meta(config)

    repo_dir = config.distractor_repos_dir / language / folder_name
    base_chars = len(build_input_text(needed_code)) + _TEMPLATE_CHAR_RESERVE
    return sample_distractors(
        repo_dir=repo_dir,
        language=language,
        needed_files=needed_files,
        k=config.distractors,
        seed=config.distractor_seed,
        base_chars=base_chars,
        budget_chars=char_budget_for(config.model),
        exclude_paths=reference_files,
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

    # Files on any reference path of this CVE, not just the combination being
    # sent. Scoring matches predictions against every reference path, so these
    # can never serve as distractors.
    reference_files = sorted(flatten_file_combinations(file_combinations))

    for file_combo in file_combinations:
        # Preserve the reference order, then append distractors after it so the
        # needed files keep their positions and line numbers (NOR/LCNR safe).
        needed_code = {
            relative_path: source_code_contents[relative_path]
            for relative_path in file_combo
            if relative_path in source_code_contents
        }

        if not needed_code:
            print(f"[WARN] No readable files found for combination: {file_combo}")
            continue

        distractors, distractor_meta = select_distractors_for_combo(
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

        input_accounting = compute_input_accounting(needed_code, distractors)

        if config.distractors_enabled():
            print(
                f"[k={config.distractors}] {len(needed_code)} reference file(s) + "
                f"{distractor_meta['distractors_used']} distractor(s) "
                f"of {distractor_meta['candidate_count']} candidates"
                f"{' [budget truncated]' if distractor_meta['budget_truncated'] else ''}; "
                f"lines {input_accounting['needed_lines']} -> "
                f"{input_accounting['total_lines']} "
                f"({input_accounting['distractor_char_share']:.0%} of chars are distractor)"
            )
            for rel_path in distractor_meta["distractor_files"]:
                print(f"    + {rel_path}")

        # Reasoning models reject a sampling temperature -> omit it.
        temperature = None if is_reasoning_model(config.model) else config.temperature

        for prompt_name, prompt_template in prompt_dict.items():
            input_prompt, input_text = construct_prompt(
                template=prompt_template,
                language=language,
                files=raw_code,
            )

            print_prompt_preview(prompt_name, input_prompt, input_text)

            for run_index in range(max(1, config.runs)):
                run_seed = config.seed + run_index

                try:
                    response, reasoning_content, usage = send_prompt(
                        client,
                        input_prompt,
                        input_text,
                        config.model,
                        temperature=temperature,
                        seed=run_seed,
                    )
                except Exception as exc:
                    print(f"[ERROR] send_prompt failed with {prompt_name} "
                          f"run {run_index} for {cve}: {exc}")
                    continue

                # Providers can return content=None; never call len() on None.
                if response is None:
                    print(f"[WARN] empty (None) response for {prompt_name} "
                          f"run {run_index} for {cve}; treating as ''")
                    response = ""

                preview = response[:200] + "..." if len(response) > 200 else response
                print(f"Response (run {run_index}): {preview}")

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
                        usage=usage,
                        run_index=run_index,
                        seed_requested=run_seed,
                        temperature_requested=temperature,
                        distractor_meta=distractor_meta,
                        input_accounting=input_accounting,
                    )
                except Exception as exc:
                    print(f"[ERROR] save_log failed with {prompt_name} "
                          f"run {run_index} for {cve}: {exc}")
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