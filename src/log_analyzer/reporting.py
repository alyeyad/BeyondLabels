from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib.pyplot as plt
import pandas as pd
from tqdm import tqdm

from .io_utils import (
    build_negative_index,
    build_repo_index,
    extract_cve_id,
    extract_needed_files,
    extract_sample_id,
    find_cve_folder,
    find_negative_sample_folder,
    json_ready,
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
    pathvul_dataset_dir: Path,
    negative_dataset_dir: Path,
    recursive: bool = False,
) -> Tuple[
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]],
    List[str],
    Dict[str, Any],
]:
    pathvul_repos = build_repo_index(pathvul_dataset_dir)
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
                print(sample_id)
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

        cve_folder = find_cve_folder(pathvul_repos, language, cve_id)
        if cve_folder is None:
            print(f"[process_output_files] Could not uniquely map {cve_id} ({language})")
            excluded_files.append(filepath.name)
            continue

        try:
            real_paths, metadata = load_cve_data(pathvul_dataset_dir, language, cve_folder)
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
        "pathvul": pathvul_repos,
        "negative": negative_repos,
    }
    return rq1_matches, negative_runs, excluded_files, repo_info


def get_source_sink_detections(all_matches: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    source_sink: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    for cve_id, run_data in all_matches.items():
        source_sink[cve_id] = {}
        for run_id, prompt_result in run_data.items():
            prompt_matches = []
            for match in prompt_result.get("matches", []):
                if "outputPathLen" not in match:
                    continue
                real_path_len = int(match.get("realPathLen", 0))
                output_path_len = int(match.get("outputPathLen", 0))
                real_src_found = False
                real_sink_found = False

                for cur in match.get("matchDetails", []):
                    if not cur.get("fileMatch") or not cur.get("lineMatch"):
                        continue
                    cur_real_ind = int(cur.get("realNodeIndex", -1))
                    if cur_real_ind == 0:
                        real_src_found = True
                    if cur_real_ind in {real_path_len - 1, real_path_len}:
                        real_sink_found = True

                prompt_matches.append(
                    {
                        "pathHash": match.get("pathHash"),
                        "outputPathInd": match.get("outputPathInd", -1),
                        "realPathLen": real_path_len,
                        "outputPathLen": output_path_len,
                        "sourceHit": real_src_found,
                        "sinkHit": real_sink_found,
                    }
                )
            source_sink[cve_id][run_id] = prompt_matches
    return source_sink


def find_best_match(matches: List[Dict[str, Any]], prompt_data: Dict[str, Any]) -> Dict[str, Any]:
    best_match: Dict[str, Any] = {
        "runID": prompt_data.get("runID"),
        "promptType": prompt_data.get("prompt_name", "unknown"),
        "model": prompt_data.get("model", "unknown"),
        "language": prompt_data.get("language", ""),
        "nor": -1.0,
        "pathHash": None,
        "realPathLen": prompt_data.get("medianRealPathLen", 0),
        "numOverlapNodes": -1,
        "outputLabel": prompt_data.get("outputLabel", 0),
        "actualLabel": prompt_data.get("actualLabel", 1),
        "outputPathLen": prompt_data.get("medianOpPathLen", -1),
        "cwes": prompt_data.get("cwe_id", []),
        "neededFiles": prompt_data.get("needed_files", []),
        "input_lines": len(str(prompt_data.get("input", "")).splitlines()),
        "numInputFiles": len(prompt_data.get("needed_files", [])),
        "outputFilesMatched": [],
        "numOutputFilesMatches": -1,
        "numInputTokens": prompt_data.get("numInputTokens", 0),
        "numOutputTokens": prompt_data.get("numOutputTokens", 0),
    }

    for match in matches:
        real_path_len = int(match.get("realPathLen", 0))
        if real_path_len <= 0:
            continue
        num_overlap_nodes = len({item.get("realNodeIndex") for item in match.get("matchDetails", [])})
        overlap_ratio = num_overlap_nodes / real_path_len
        if overlap_ratio > best_match["nor"]:
            best_match.update(
                {
                    "nor": overlap_ratio,
                    "pathHash": match.get("pathHash"),
                    "outputPathInd": match.get("outputPathInd", -1),
                    "realPathLen": real_path_len,
                    "numOverlapNodes": num_overlap_nodes,
                    "outputPathLen": match.get("outputPathLen", -1),
                    "outputFilesMatched": match.get("outputFilesMatched", []),
                    "numOutputFilesMatches": len(match.get("outputFilesMatched", [])),
                    "realPath": match.get("realPath"),
                    "outputPath": match.get("outputPath"),
                    "overlappingNodes": list(
                        {
                            (item.get("realNodeIndex"), item.get("outputNodeIndex"))
                            for item in match.get("matchDetails", [])
                            if "outputNodeIndex" in item
                        }
                    ),
                }
            )
    return best_match


def find_best_lcs_match(lcs_matches: Dict[Tuple[str, int], Dict[str, Any]], prompt_data: Dict[str, Any]) -> Dict[str, Any]:
    best_lcs: Dict[str, Any] = {
        "runID": prompt_data.get("runID"),
        "promptType": prompt_data.get("prompt_name", "unknown"),
        "model": prompt_data.get("model", "unknown"),
        "language": prompt_data.get("language", ""),
        "lcnr": -1.0,
        "lcs_pathHash": None,
        "lcs_outputPathIndex": -1,
        "lcs_length": -1,
        "lcs_realPathLen": prompt_data.get("medianRealPathLen", 0),
        "lcs_outputPathLen": prompt_data.get("medianOpPathLen", -1),
        "outputLabel": prompt_data.get("outputLabel", 0),
        "actualLabel": prompt_data.get("actualLabel", 1),
        "cwes": prompt_data.get("cwe_id", []),
        "neededFiles": prompt_data.get("needed_files", []),
        "input_lines": len(str(prompt_data.get("input", "")).splitlines()),
        "numInputFiles": len(prompt_data.get("needed_files", [])),
        "numInputTokens": prompt_data.get("numInputTokens", 0),
        "numOutputTokens": prompt_data.get("numOutputTokens", 0),
    }

    for (path_hash, output_idx), lcs_match in lcs_matches.items():
        if not lcs_match:
            continue
        lcs_length = int(lcs_match.get("len", 0))
        real_path_len = int(lcs_match.get("realPathLen", best_lcs["lcs_realPathLen"]))
        overlap_ratio = (lcs_length / real_path_len) if real_path_len > 0 else 0.0
        if overlap_ratio > best_lcs["lcnr"]:
            best_lcs.update(
                {
                    "lcnr": overlap_ratio,
                    "lcs_pathHash": path_hash,
                    "lcs_outputPathIndex": output_idx,
                    "lcs_length": lcs_length,
                    "lcs_realPathLen": real_path_len,
                    "lcs_real_range": lcs_match.get("real_range"),
                    "lcs_output_range": lcs_match.get("output_range"),
                }
            )
    return best_lcs


def create_refined_matches(
    all_matches: Dict[str, Dict[str, Any]],
    source_sink_dict: Dict[str, Dict[str, List[Dict[str, Any]]]],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    node_refined: Dict[str, Dict[str, Any]] = {}
    lcs_refined: Dict[str, Dict[str, Any]] = {}

    for cve_id, run_results in all_matches.items():
        for run_id, prompt_data in run_results.items():
            best_node_match = find_best_match(prompt_data.get("matches", []), prompt_data)
            best_node_match["filename"] = prompt_data.get("filename")
            best_node_match["outputFormat"] = prompt_data.get("outputFormat")

            candidates = [
                item
                for item in source_sink_dict.get(cve_id, {}).get(run_id, [])
                if best_node_match.get("pathHash") == item.get("pathHash")
                and best_node_match.get("outputPathInd", -1) == item.get("outputPathInd", -2)
            ]
            best_node_match.update(
                {
                    "sourceHit": any(item.get("sourceHit", False) for item in candidates),
                    "sinkHit": any(item.get("sinkHit", False) for item in candidates),
                }
            )
            node_refined.setdefault(cve_id, {})[run_id] = best_node_match

            if prompt_data.get("lcs_matches"):
                best_lcs_match = find_best_lcs_match(prompt_data["lcs_matches"], prompt_data)
                best_lcs_match["filename"] = prompt_data.get("filename")
                best_lcs_match["outputFormat"] = prompt_data.get("outputFormat")

                lcs_refined.setdefault(cve_id, {})[run_id] = best_lcs_match

    return node_refined, lcs_refined


def convert_to_dataframe(refined_matches: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for cve_id, run_results in refined_matches.items():
        for run_id, values in run_results.items():
            row = {
                "CVE": cve_id,
                "runID": run_id,
                "promptType": values.get("promptType", "unknown"),
                "model": values.get("model", "unknown"),
                "language": values.get("language", ""),
            }
            row.update(values)
            rows.append(row)
    cur_df = pd.DataFrame(rows)
    if not cur_df.empty:
        for col_name in ["outputPathLen", "nor", "numOverlapNodes", "lcs_outputPathLen", "lcnr", "lcs_length"]:
            if col_name in cur_df.columns:
                cur_df[col_name] = cur_df[col_name].replace({-1: 0})
    return cur_df


def create_combined_results_df(
    node_refined_matches: Dict[str, Dict[str, Any]],
    lcs_refined_matches: Dict[str, Dict[str, Any]],
) -> pd.DataFrame:
    df_node = convert_to_dataframe(node_refined_matches)
    df_lcs = convert_to_dataframe(lcs_refined_matches)

    if df_node.empty and df_lcs.empty:
        return pd.DataFrame()
    if df_node.empty:
        return df_lcs.copy()
    if df_lcs.empty:
        return df_node.copy()

    join_keys = [
        col
        for col in ["CVE", "runID", "promptType", "model", "language", "filename", "outputFormat"]
        if col in df_node.columns and col in df_lcs.columns
    ]

    lcs_cols = [
        col for col in df_lcs.columns
        if col in join_keys or col.startswith("lcs_") or "lcnr" in col
    ]

    combined = df_node.merge(df_lcs[lcs_cols], on=join_keys, how="outer")

    if "nor" in combined.columns:
        combined["nor"] = combined["nor"].replace({-1: 0})
    if "lcnr" in combined.columns:
        combined["lcnr"] = combined["lcnr"].replace({-1: 0})
    if "numOverlapNodes" in combined.columns:
        combined["numOverlapNodes"] = combined["numOverlapNodes"].replace({-1: 0})
    if "lcs_length" in combined.columns:
        combined["lcs_length"] = combined["lcs_length"].replace({-1: 0})
    if "outputPathLen" in combined.columns:
        combined["outputPathLen"] = combined["outputPathLen"].replace({-1: 0})
    if "lcs_outputPathLen" in combined.columns:
        combined["lcs_outputPathLen"] = combined["lcs_outputPathLen"].replace({-1: 0})

    preferred_order = [
        "CVE",
        "runID",
        "promptType",
        "model",
        "language",
        "filename",
        "outputFormat",
        "outputLabel",
        "actualLabel",
        "nor",
        "numOverlapNodes",
        "realPathLen",
        "outputPathLen",
        "lcnr",
        "lcs_length",
        "lcs_realPathLen",
        "lcs_outputPathLen",
    ]
    ordered = [col for col in preferred_order if col in combined.columns]
    remaining = [col for col in combined.columns if col not in ordered]
    return combined[ordered + remaining]


def create_negative_results_df(
    negative_runs: Dict[str, Dict[str, Any]],
) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []

    for sample_id, run_results in negative_runs.items():
        for run_id, values in run_results.items():
            row = {
                "task": "negative",
                "sampleID": sample_id,
                "runID": run_id,
                "promptType": values.get("prompt_name", "unknown"),
                "model": values.get("model", "unknown"),
                "language": values.get("language", ""),
                "filename": values.get("filename", ""),
                "outputLabel": values.get("outputLabel", 0),
                "actualLabel": values.get("actualLabel", 0),
                "labelCorrect": values.get("labelCorrect", 0),
                "numInputTokens": values.get("numInputTokens", 0),
                "numOutputTokens": values.get("numOutputTokens", 0),
                "numInputFiles": len(values.get("needed_files", [])),
                "input_lines": len(str(values.get("input", "")).splitlines()),
                "neededFiles": values.get("needed_files", []),
                "sourceFiles": values.get("sourceFiles", []),
            }
            rows.append(row)

    return pd.DataFrame(rows)


def add_overlap_bins(df: pd.DataFrame, score_col: str, out_col: str = "overlap_bin2") -> pd.DataFrame:
    df = df.copy()
    df[out_col] = pd.cut(
        df[score_col].fillna(0),
        bins=[0, 0.25, 0.75, 1.0],
        labels=["Low", "Medium", "High"],
        include_lowest=True,
    )
    return df


def save_scatter_plot(df: pd.DataFrame, score_col: str, output_path: Path, title: str) -> None:
    if df.empty:
        return
    plot_df = add_overlap_bins(df, score_col)
    plot_df = plot_df.sort_values(by=score_col, ascending=False).reset_index(drop=True)

    fig, ax = plt.subplots(figsize=(20, 5))
    label_to_marker = {"Low": "o", "Medium": "^", "High": "s"}
    for label in ["Low", "Medium", "High"]:
        subset = plot_df[plot_df["overlap_bin2"] == label]
        if subset.empty:
            continue
        ax.scatter(subset.index, subset[score_col], label=label, marker=label_to_marker[label], s=40)

    x_label_col = "CVE" if "CVE" in plot_df.columns else ("sampleID" if "sampleID" in plot_df.columns else None)

    for y in [0.0, 0.25, 0.5, 0.75, 1.0]:
        ax.axhline(y=y, linestyle="--", linewidth=1, color="gray", alpha=0.6)

    ax.set_xticks(range(len(plot_df)))
    if x_label_col is not None:
        ax.set_xticklabels(plot_df[x_label_col], rotation=90)
        ax.set_xlabel(x_label_col)
    else:
        ax.set_xticklabels(range(len(plot_df)), rotation=90)
        ax.set_xlabel("index")

    ax.set_ylabel(score_col)
    ax.set_title(title)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_path, dpi=300, bbox_inches="tight", pad_inches=0.1)
    plt.close(fig)


def save_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(json_ready(payload), f, indent=2)