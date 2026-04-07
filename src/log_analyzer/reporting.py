from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import seaborn as sns
import os
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
        "numInputLines": len(str(prompt_data.get("input", "")).splitlines()),
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


def find_best_lcs_match(lcs_matches: Dict[Tuple[str, int], Dict[str, Any]], prompt_data: Dict[str, Any]) -> Dict[
    str, Any]:
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
        "numInputLines": len(str(prompt_data.get("input", "")).splitlines()),
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
    result = combined[ordered + remaining]
    df_unique = result.loc[result.groupby(['CVE', 'promptType', "model"])['nor'].idxmax()].reset_index(drop=True)
    return df_unique


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
                "numInputLines": len(str(values.get("input", "")).splitlines()),
                "neededFiles": values.get("needed_files", []),
                "sourceFiles": values.get("sourceFiles", []),
            }
            rows.append(row)

    return pd.DataFrame(rows)


def add_overlap_bins(df: pd.DataFrame, score_col: str, out_col: str = "overlap_bin") -> pd.DataFrame:
    df = df.copy()
    df[out_col] = pd.cut(
        df[score_col].fillna(0),
        bins=[0, 0.25, 0.75, 1.0],
        labels=["Low", "Medium", "High"],
        include_lowest=True,
    )
    return df


def plot_nor_scatter(
    df,
    output_path=None,
    x_col="CVE",
    overlap_col="nor",
    title="",
    model="claude-sonnet-4-5",
    figsize=(20, 5),
    show=False,
):
    df = df[(df["promptType"] == "llmql")&(df["model"] == model)]
    # Replace -1 with 0
    df[overlap_col] = df[overlap_col].replace({-1: 0})

    # Create categorical bins
    df["overlap_bin"] = pd.cut(
        df[overlap_col],
        bins=[0, 0.25, 0.75, 1.0],
        labels=["Low", "Medium", "High"],
        include_lowest=True
    )

    # Sort descending by overlap
    num_sorted = df.sort_values(by=overlap_col, ascending=False).copy()

    # Rename for plotting
    num_sorted = num_sorted.rename(columns={
        overlap_col: "Node Overlap Ratio",
        "overlap_bin": "NOR Level"
    })

    plt.figure(figsize=figsize)

    sns.scatterplot(
        data=num_sorted,
        x=x_col,
        y="Node Overlap Ratio",
        hue="NOR Level",
        palette=["#0072B2", "#E69F00", "#009E73"],
        s=85
    )

    # Horizontal reference lines
    for y in [0.0, 0.25, 0.5, 0.75, 1.0]:
        plt.axhline(
            y=y,
            linestyle="--",
            linewidth=1,
            color="gray",
            alpha=0.6
        )

    plt.yticks([0, 0.25, 0.5, 0.75, 1.0])
    plt.xlabel("CVEs")
    plt.ylabel("Node Overlap Ratio (NOR)")
    plt.xticks([])
    plt.title(title)
    plt.legend(loc="upper right")

    if output_path:
        plt.savefig(
            output_path,
            format="pdf",
            bbox_inches="tight",
        )

    if show:
        plt.show()
    else:
        plt.close()

    return df, num_sorted


def save_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(json_ready(payload), f, indent=2)


def create_model_summary_table(combined_df: pd.DataFrame) -> pd.DataFrame:
    """
    Build the RQ table:
      - median overlap (NOR) per model over all runs
      - median LCS overlap (LCNR) per model over all runs
      - mean real source found per model over runs with overlap > 0 only
      - mean real sink found per model over runs with overlap > 0 only
    """
    if combined_df.empty:
        return pd.DataFrame(
            columns=[
                "model",
                "median_overlap",
                "median_lcs_overlap",
                "mean_real_src_found",
                "mean_real_sink_found",
            ]
        )

    df = combined_df.copy()
    df = df[df["promptType"] == "llmql"]

    for col in ["nor", "lcnr", "sourceHit", "sinkHit", "numOverlapNodes"]:
        if col not in df.columns:
            df[col] = 0

    df["nor"] = pd.to_numeric(df["nor"], errors="coerce").fillna(0.0)
    df["lcnr"] = pd.to_numeric(df["lcnr"], errors="coerce").fillna(0.0)
    df["sourceHit"] = pd.to_numeric(df["sourceHit"], errors="coerce").fillna(0.0)
    df["sinkHit"] = pd.to_numeric(df["sinkHit"], errors="coerce").fillna(0.0)
    df["numOverlapNodes"] = pd.to_numeric(df["numOverlapNodes"], errors="coerce").fillna(0.0)

    # Main summary over all runs
    summary_all = (
        df.groupby("model", dropna=False)
        .agg(
            median_overlap=("nor", "median"),
            median_lcs_overlap=("lcnr", "median")
        )
        .reset_index()
    )

    # Source/sink means only where overlap > 0
    overlap_df = df[(df["nor"] > 0) | (df["numOverlapNodes"] > 0)].copy()

    if overlap_df.empty:
        summary_all["mean_real_src_found"] = 0.0
        summary_all["mean_real_sink_found"] = 0.0
    else:
        summary_overlap = (
            overlap_df.groupby("model", dropna=False)
            .agg(
                mean_real_src_found=("sourceHit", "mean"),
                mean_real_sink_found=("sinkHit", "mean")
            )
            .reset_index()
        )

        summary_all = summary_all.merge(summary_overlap, on="model", how="left")
        summary_all["mean_real_src_found"] = summary_all["mean_real_src_found"].fillna(0.0)
        summary_all["mean_real_sink_found"] = summary_all["mean_real_sink_found"].fillna(0.0)

    for col in [
        "median_overlap",
        "median_lcs_overlap",
        "mean_real_src_found",
        "mean_real_sink_found",
    ]:
        summary_all[col] = summary_all[col].round(3)

    summary_all = summary_all.sort_values(
        by=["median_overlap", "median_lcs_overlap", "mean_real_src_found", "mean_real_sink_found"],
        ascending=False,
    ).reset_index(drop=True)

    summary_all = summary_all.rename(
        columns={
            "model": "Model",
            "median_overlap": "Median NOR",
            "median_lcs_overlap": "Median LCNR",
            "mean_real_src_found": "Mean Source Hit | NOR > 0",
            "mean_real_sink_found": "Mean Sink Hit | NOR > 0",
        }
    )

    return summary_all


def add_overlap_bins(
        df: pd.DataFrame,
        score_col: str,
        out_col: str = "overlap_bin",
) -> pd.DataFrame:
    """
    Exact bins:
      Low    = [0, 0.25)
      Medium = [0.25, 0.75)
      High   = [0.75, 1]
    """
    out = df.copy()
    eps = 1e-9

    out[out_col] = pd.cut(
        out[score_col].fillna(0).clip(lower=0, upper=1),
        bins=[0.0, 0.25, 0.75, 1.0 + eps],
        labels=["Low", "Medium", "High"],
        include_lowest=True,
        right=False,
    )
    return out

import math
import re
from typing import Any, Iterable

import pandas as pd


def extract_cwe_ints(value: Any) -> set[int]:
    """
    Robustly extract CWE ids as ints from values like:
      ['CWE-77', 'CWE-78']
      "['CWE-77', 'CWE-78']"
      "CWE-77, CWE-78"
      ["cwe_77", "CWE 78"]
    """
    found: set[int] = set()

    if value is None:
        return found

    if isinstance(value, int):
        return {value}

    if isinstance(value, (list, tuple, set)):
        for item in value:
            found.update(extract_cwe_ints(item))
        return found

    text = str(value)

    # Prefer CWE-like patterns
    matches = re.findall(r"cwe[\s\-_]*?(\d+)", text, flags=re.IGNORECASE)
    if matches:
        return {int(m) for m in matches}

    return found


def create_single_model_cwe_table(
    combined_df: pd.DataFrame,
    model_name: str,
    target_cwes: Iterable[int] = (22, 20, 94, 502),
    empty_value: float = float("nan"),
) -> pd.DataFrame:
    """
    Build a table like:

        Metric   CWE-22  CWE-20  CWE-94  CWE-502
        NOR      ...
        LCNR     ...
        Src-HR   ...
        Sink-HR  ...

    Notes:
    - Filters to one model only.
    - A row belongs to a CWE if that CWE id is present in its `cwes` field.
    - Src-HR / Sink-HR are computed only over rows with overlap > 0.
    """
    if combined_df.empty:
        columns = ["Metric"] + [f"CWE-{c}" for c in target_cwes]
        return pd.DataFrame(columns=columns)

    df = combined_df.copy()
    df = df[df["promptType"] == "llmql"]

    required_cols = ["model", "cwes", "nor", "lcnr", "sourceHit", "sinkHit", "numOverlapNodes"]
    for col in required_cols:
        if col not in df.columns:
            if col == "cwes":
                df[col] = [[] for _ in range(len(df))]
            else:
                df[col] = 0

    df = df[df["model"] == model_name].copy()

    if df.empty:
        columns = ["Metric"] + [f"CWE-{c}" for c in target_cwes]
        return pd.DataFrame(columns=columns)

    df["nor"] = pd.to_numeric(df["nor"], errors="coerce").fillna(0.0)
    df["lcnr"] = pd.to_numeric(df["lcnr"], errors="coerce").fillna(0.0)
    df["sourceHit"] = pd.to_numeric(df["sourceHit"], errors="coerce").fillna(0.0)
    df["sinkHit"] = pd.to_numeric(df["sinkHit"], errors="coerce").fillna(0.0)
    df["numOverlapNodes"] = pd.to_numeric(df["numOverlapNodes"], errors="coerce").fillna(0.0)

    df["_cwe_ints"] = df["cwes"].apply(extract_cwe_ints)

    rows = {
        "NOR": [],
        "LCNR": [],
        "Src-HR": [],
        "Sink-HR": [],
    }

    for cwe in target_cwes:
        cwe_df = df[df["_cwe_ints"].apply(lambda s: cwe in s)].copy()

        if cwe_df.empty:
            rows["NOR"].append(empty_value)
            rows["LCNR"].append(empty_value)
            rows["Src-HR"].append(empty_value)
            rows["Sink-HR"].append(empty_value)
            continue

        rows["NOR"].append(float(cwe_df["nor"].median()))
        rows["LCNR"].append(float(cwe_df["lcnr"].median()))

        overlap_df = cwe_df[(cwe_df["nor"] > 0) | (cwe_df["numOverlapNodes"] > 0)].copy()
        if overlap_df.empty:
            rows["Src-HR"].append(empty_value)
            rows["Sink-HR"].append(empty_value)
        else:
            rows["Src-HR"].append(float(overlap_df["sourceHit"].mean()))
            rows["Sink-HR"].append(float(overlap_df["sinkHit"].mean()))

    out = pd.DataFrame(
        {
            "Metric": ["NOR", "LCNR", "Src-HR", "Sink-HR"],
            **{
                f"CWE-{cwe}": [
                    rows["NOR"][i],
                    rows["LCNR"][i],
                    rows["Src-HR"][i],
                    rows["Sink-HR"][i],
                ]
                for i, cwe in enumerate(target_cwes)
            },
        }
    )

    # Round numeric cells for paper tables
    for col in out.columns:
        if col != "Metric":
            out[col] = out[col].apply(
                lambda x: round(x, 2) if pd.notna(x) and not isinstance(x, str) else x
            )

    return out


def save_success_failure_violin_plots(
    df: pd.DataFrame,
    output_path: Path,
    threshold: float = 0.5,
    score_col: str = "nor",
    feature_map: dict[str, str] | None = None,
    palette: dict[str, str] | None = None,
) -> None:
    """
    Plot violin distributions for success vs failure at a given threshold.

    Success = score_col >= threshold
    Failure = score_col < threshold
    """
    if df.empty or score_col not in df.columns:
        return

    if feature_map is None:
        feature_map = {
            "realPathLen": "Vulnerable Path Length",
            "numInputFiles": "Number of Files per Path",
            "numInputTokens": "Number of Input Tokens",
            "numInputLines": "Number of Input Lines",
        }

    if palette is None:
        palette = {
            "Success": "#bdbdbd",
            "Failure": "#bdbdbd",
        }

    plot_df = df.copy()
    plot_df[score_col] = pd.to_numeric(plot_df[score_col], errors="coerce").fillna(0.0)

    df_success = plot_df[plot_df[score_col] >= threshold].copy()
    df_failure = plot_df[plot_df[score_col] < threshold].copy()

    available_features = [col for col in feature_map if col in plot_df.columns]
    if not available_features:
        return

    n_features = len(available_features)
    ncols = 2
    nrows = (n_features + ncols - 1) // ncols

    fig, axes = plt.subplots(nrows=nrows, ncols=ncols, figsize=(10, 7))
    axes = axes.flatten() if hasattr(axes, "flatten") else [axes]

    for i, col in enumerate(available_features):
        cur_success = pd.to_numeric(df_success[col], errors="coerce").dropna()
        cur_failure = pd.to_numeric(df_failure[col], errors="coerce").dropna()

        if cur_success.empty and cur_failure.empty:
            axes[i].axis("off")
            continue

        df_plot = pd.DataFrame({
            col: pd.concat([cur_success, cur_failure], ignore_index=True),
            "source": (["Success"] * len(cur_success)) + (["Failure"] * len(cur_failure)),
        })

        sns.violinplot(
            data=df_plot,
            x="source",
            y=col,
            ax=axes[i],
            hue="source",
            palette=palette,
            cut=0,
            width=0.9,
            inner="box",
            inner_kws=dict(
                box_width=12,
                whis_width=2,
                linewidth=0,
            ),
            legend=False,
        )

        for artist in getattr(axes[i], "artists", []):
            artist.set_facecolor("black")
            artist.set_edgecolor("black")

        for line in axes[i].lines:
            line.set_color("black")

        med_success = float(cur_success.median()) if not cur_success.empty else None
        med_fail = float(cur_failure.median()) if not cur_failure.empty else None

        x_success = 0
        x_failure = 1
        half_width = 0.2

        if med_success is not None:
            axes[i].hlines(
                med_success,
                x_success - half_width,
                x_success + half_width,
                colors="black",
                linestyles="dashed",
                linewidth=2,
                zorder=10,
            )

        if med_fail is not None:
            axes[i].hlines(
                med_fail,
                x_failure - half_width,
                x_failure + half_width,
                colors="black",
                linestyles="dashed",
                linewidth=2,
                zorder=10,
            )

        axes[i].set_title(feature_map[col])
        axes[i].set_xlabel("")
        axes[i].set_ylabel("")

    for ax in axes[len(available_features):]:
        ax.axis("off")

    fig.text(
        0.5,
        0.02,
        f"Violin plots of studied features for successful and unsuccessful path reconstructions at {score_col.upper()} = {threshold}.",
        ha="center",
        fontsize=10,
    )
    fig.tight_layout(rect=[0, 0.06, 1, 1])
    fig.savefig(output_path, dpi=300, bbox_inches="tight", pad_inches=0.1)
    plt.close(fig)