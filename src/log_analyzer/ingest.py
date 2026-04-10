from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from tqdm import tqdm

from .io_utils import (
    build_negative_index,
    build_repo_index,
    extract_cve_id,
    extract_needed_files,
    extract_sample_id,
    find_cve_folder,
    find_negative_sample_folder,
    load_cve_data,
    load_json_file,
    load_negative_sample_data,
    parse_output_json,
)
from .matching import (
    calculate_median_output_path_length,
    calculate_median_path_length,
    determine_output_label,
    get_all_lcs_matches,
    get_real_and_predicted_matches_by_line,
    get_real_and_predicted_matches_standard,
)


def process_output_files(
    logs_dir: Path,
    cvepath_dataset_dir: Path,
    negative_dataset_dir: Path,
    recursive: bool = False,
) -> Tuple[
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]],
    List[str],
    Dict[str, Any],
]:
    cvepath_repos = build_repo_index(cvepath_dataset_dir)
    negative_repos = build_negative_index(negative_dataset_dir)
    output_files = sorted(logs_dir.rglob("*.json") if recursive else logs_dir.glob("*.json"))

    rq1_matches: Dict[str, Dict[str, Any]] = {}
    negative_runs: Dict[str, Dict[str, Any]] = {}
    excluded_files: List[str] = []

    for filepath in tqdm(output_files, desc="Processing logs"):
        if "exception" in filepath.name:
            continue

        full_log = load_json_file(filepath)
        if full_log is None:
            excluded_files.append(filepath.name)
            continue

        task = str(full_log.get("task", "rq1")).strip() or "rq1"
        language = str(full_log.get("language", "")).strip()
        prompt_name = str(full_log.get("prompt_name", "unknown")).strip() or "unknown"
        model_name = str(full_log.get("model", "unknown")).strip() or "unknown"
        run_id = filepath.stem
        usage = full_log.get("usage") or {}

        output_parsed = parse_output_json(str(full_log.get("output", "")))
        if output_parsed is None:
            print(f"[process_output_files] JSON parse error in {filepath.name}")
            excluded_files.append(filepath.name)
            continue

        input_text = str(full_log.get("input", ""))
        needed_files = extract_needed_files(input_text, full_log)

        if task == "negative":
            sample_id = extract_sample_id(full_log)
            if not sample_id or not language:
                excluded_files.append(filepath.name)
                continue

            sample_folder = find_negative_sample_folder(negative_repos, language, sample_id)
            if sample_folder is None:
                print(f"[process_output_files] Could not map negative sample {sample_id} ({language})")
                excluded_files.append(filepath.name)
                continue

            try:
                sample_data = load_negative_sample_data(
                    negative_dataset_dir,
                    language,
                    sample_folder,
                )
            except Exception as exc:
                print(f"[process_output_files] Failed loading negative dataset entry for {sample_folder}: {exc}")
                excluded_files.append(filepath.name)
                continue

            op_label = determine_output_label(output_parsed)
            actual_label = int(
                full_log.get(
                    "actual_label",
                    sample_data["metadata"].get("actual_label", 0),
                )
            )

            negative_runs.setdefault(sample_id, {})[run_id] = {
                "task": "negative",
                "runID": run_id,
                "sampleID": sample_id,
                "prompt_name": prompt_name,
                "model": model_name,
                "language": language,
                "filename": filepath.name,
                "input": input_text,
                "needed_files": needed_files,
                "outputLabel": op_label,
                "actualLabel": actual_label,
                "labelCorrect": int(op_label == actual_label),
                "sourceFiles": sample_data.get("source_files", []),
                "output": str(full_log.get("output", "")),
                "numInputTokens": usage.get("input_tokens"),
                "numOutputTokens": usage.get("output_tokens"),
            }
            continue

        cve_id = extract_cve_id(full_log)
        if not cve_id or not language:
            excluded_files.append(filepath.name)
            continue

        cve_folder = find_cve_folder(cvepath_repos, language, cve_id)
        if cve_folder is None:
            print(f"[process_output_files] Could not uniquely map {cve_id} ({language})")
            excluded_files.append(filepath.name)
            continue

        try:
            real_paths, metadata = load_cve_data(cvepath_dataset_dir, language, cve_folder)
        except Exception as exc:
            print(f"[process_output_files] Failed loading dataset entry for {cve_folder}: {exc}")
            excluded_files.append(filepath.name)
            continue

        median_real_len = calculate_median_path_length(real_paths)
        cwes = metadata.get("cwe_id", [])
        lcs_matches: Dict[Tuple[str, int], Dict[str, Any]] = {}

        if isinstance(output_parsed, dict) and "findings" in output_parsed:
            findings = output_parsed.get("findings", []) or []
            final_matches = get_real_and_predicted_matches_standard(real_paths, findings)
            op_label = determine_output_label(output_parsed)
            median_op_len = calculate_median_output_path_length(findings)
            lcs_matches = get_all_lcs_matches(real_paths, findings)
            output_format = "path"
        elif isinstance(output_parsed, dict):
            final_matches = get_real_and_predicted_matches_by_line(real_paths, output_parsed)
            op_label = determine_output_label(output_parsed)
            median_op_len = -1.0
            output_format = "line"
        else:
            print(f"[process_output_files] Unsupported RQ1 output shape in {filepath.name}")
            excluded_files.append(filepath.name)
            continue

        rq1_matches.setdefault(cve_id, {})[run_id] = {
            "task": "rq1",
            "runID": run_id,
            "prompt_name": prompt_name,
            "model": model_name,
            "language": language,
            "filename": filepath.name,
            "matches": final_matches,
            "lcs_matches": lcs_matches,
            "input": input_text,
            "needed_files": needed_files,
            "outputLabel": op_label,
            "actualLabel": int(full_log.get("actual_label", 1)),
            "cwe_id": cwes,
            "medianRealPathLen": median_real_len,
            "medianOpPathLen": median_op_len,
            "output": str(full_log.get("output", "")),
            "outputFormat": output_format,
            "numInputTokens": usage.get("input_tokens"),
            "numOutputTokens": usage.get("output_tokens"),
        }

    repo_info = {
        "cvepath": cvepath_repos,
        "negative": negative_repos,
    }
    return rq1_matches, negative_runs, excluded_files, repo_info