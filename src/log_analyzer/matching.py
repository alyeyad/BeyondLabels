from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np


def calculate_median_path_length(paths: Dict[str, Dict[str, Any]]) -> float:
    lengths = [len(path_info) for path_info in paths.values()]
    return float(np.median(lengths)) if lengths else 0.0


def calculate_median_output_path_length(output_paths: List[Dict[str, Any]]) -> float:
    lengths = [len(path_info.get("taint_path", [])) for path_info in output_paths]
    return float(np.median(lengths)) if lengths else 0.0


def determine_output_label(output_data: Any) -> int:
    if isinstance(output_data, dict) and "findings" in output_data:
        return int(len(output_data["findings"]) > 0)

    if isinstance(output_data, dict):
        for file_info in output_data.values():
            vuln_lines = file_info.get("vulnerable_lines") if isinstance(file_info, dict) else None
            if vuln_lines:
                return 1
    return 0


def dedupe_nodes(nodes: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for node in nodes:
        key = node_key(node)
        if key not in seen:
            seen.add(key)
            out.append(node)
    return out


def node_key(node: Dict[str, Any]) -> Tuple[str, int, int]:
    file_name = node.get("file_name", "")
    start_line = int(node.get("line_number", -1))
    end_line = int(node.get("endLine", start_line))
    return file_name, start_line, end_line


def _interval_overlap(a1: int, a2: int, b1: int, b2: int) -> bool:
    return not (a2 < b1 or b2 < a1)


def compare_paths_standard(real_path: List[Dict[str, Any]], output_path: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    match_list: List[Dict[str, Any]] = []
    for r_idx, r_node in enumerate(real_path):
        real_file = r_node.get("file_name")
        real_start_line = int(r_node.get("line_number", -1))
        real_end_line = int(r_node.get("endLine", real_start_line))
        real_snippet = r_node.get("sourceCode", "")

        for o_idx, o_node in enumerate(output_path):
            if "file" not in o_node or "lines" not in o_node:
                continue
            output_file = o_node["file"]
            try:
                output_start_line = int(str(o_node["lines"]).split("-")[0])
                output_end_line = int(str(o_node["lines"]).split("-")[1])
            except Exception:
                continue
            output_snippet = o_node.get("snippet", "")

            file_match = output_file == real_file
            line_match = (
                file_match
                and real_start_line >= 0
                and _interval_overlap(output_start_line, output_end_line, real_start_line, real_end_line)
            )

            if file_match and line_match:
                match_list.append(
                    {
                        "realNodeIndex": r_idx,
                        "outputNodeIndex": o_idx,
                        "fileMatch": file_match,
                        "lineMatch": line_match,
                        "realStartLine": real_start_line,
                        "realEndLine": real_end_line,
                        "outputStartLine": output_start_line,
                        "outputEndLine": output_end_line,
                        "outputSnippet": output_snippet,
                        "realSnippet": real_snippet,
                    }
                )
    return match_list

def compare_paths_by_line(real_path: List[Dict[str, Any]], output_dict: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    match_list: List[Dict[str, Any]] = []
    for r_idx, r_node in enumerate(real_path):
        real_file = r_node.get("file_name")
        line_info = r_node.get("lineInfo", {})
        real_start_line = int(line_info.get("startLine", -1))
        real_end_line = int(line_info.get("endLine", real_start_line))
        real_snippet = r_node.get("sourceCode", "")

        if real_file not in output_dict:
            continue

        output_info = output_dict.get(real_file, {})
        vulnerable_lines = output_info.get("vulnerable_lines") or []
        if vulnerable_lines == [None]:
            vulnerable_lines = []

        for output_line in vulnerable_lines:
            try:
                output_line_int = int(output_line)
            except Exception:
                continue

            line_match = _interval_overlap(real_start_line, real_end_line, output_line_int, output_line_int)
            if line_match:
                match_list.append(
                    {
                        "realNodeIndex": r_idx,
                        "outputFile": real_file,
                        "fileMatch": True,
                        "lineMatch": True,
                        "realStartLine": real_start_line,
                        "realEndLine": real_end_line,
                        "outputStartLine": output_line_int,
                        "outputEndLine": output_line_int,
                        "realSnippet": real_snippet,
                        "outputExplanation": output_info.get("explanation", ""),
                    }
                )
    return match_list

def nodes_match(node_a: Dict[str, Any], node_b: Dict[str, Any]) -> bool:
    if node_a.get("file_name") != node_b.get("file"):
        return False

    real_start = int(node_a.get("line_number", -1))
    real_end = int(node_a.get("endLine", real_start))

    try:
        pred_start = int(str(node_b["lines"]).split("-")[0])
        pred_end = int(str(node_b["lines"]).split("-")[1])
    except Exception:
        return False

    return _interval_overlap(real_start, real_end, pred_start, pred_end)


def longest_common_subsequence_stretched(
    real_nodes: List[Dict[str, Any]],
    pred_nodes: List[Dict[str, Any]],
    min_len: int = 1,
    maximal_only: bool = True,
    allow_overlaps: bool = True,
) -> List[Dict[str, Any]]:
    m, n = len(real_nodes), len(pred_nodes)
    results: List[Dict[str, Any]] = []

    for j_start in range(n):
        for i_start in range(m):
            if not nodes_match(real_nodes[i_start], pred_nodes[j_start]):
                continue

            i = i_start
            j = j_start
            matched_len = 0

            while j < n:
                matched_this_pred = False
                while i < m and nodes_match(real_nodes[i], pred_nodes[j]):
                    i += 1
                    matched_len += 1
                    matched_this_pred = True
                if not matched_this_pred:
                    break
                j += 1

            a_end = i - 1
            b_end = j - 1

            if matched_len >= min_len:
                can_extend = False
                if maximal_only and i < m and j < n and nodes_match(real_nodes[i], pred_nodes[j]):
                    can_extend = True
                if not can_extend:
                    results.append(
                        {
                            "len": matched_len,
                            "real_range": (i_start, a_end),
                            "output_range": (j_start, b_end),
                            "nodes": real_nodes[i_start : a_end + 1],
                        }
                    )

    seen = set()
    deduped: List[Dict[str, Any]] = []
    for result in results:
        key = (
            result["real_range"][0],
            result["real_range"][1],
            result["output_range"][0],
            result["output_range"][1],
        )
        if key not in seen:
            seen.add(key)
            deduped.append(result)

    if not allow_overlaps:
        deduped.sort(key=lambda item: item["len"], reverse=True)
        kept: List[Dict[str, Any]] = []
        used_real: List[Tuple[int, int]] = []
        used_pred: List[Tuple[int, int]] = []

        def overlaps(candidate: Tuple[int, int], used_ranges: List[Tuple[int, int]]) -> bool:
            return any(not (candidate[1] < cur[0] or candidate[0] > cur[1]) for cur in used_ranges)

        for item in deduped:
            if overlaps(item["real_range"], used_real) or overlaps(item["output_range"], used_pred):
                continue
            kept.append(item)
            used_real.append(item["real_range"])
            used_pred.append(item["output_range"])
        deduped = sorted(kept, key=lambda item: (item["real_range"][0], item["output_range"][0]))
    else:
        deduped.sort(key=lambda item: (item["real_range"][0], item["output_range"][0], -item["len"]))

    return deduped


def get_real_and_predicted_matches_standard(
    real_paths: Dict[str, Dict[str, Any]],
    output_paths: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    final_matches: List[Dict[str, Any]] = []
    for op_idx, op_path in enumerate(output_paths):
        taint_path = op_path.get("taint_path", [])
        output_files = sorted({node["file"] for node in taint_path if "file" in node})
        for path_hash, real_path in real_paths.items():

            match_details = compare_paths_standard(real_path, taint_path)
            if match_details:
                final_matches.append(
                    {
                        "pathHash": path_hash,
                        "realPath": real_path,
                        "outputPath": taint_path,
                        "outputPathInd": op_idx,
                        "matchDetails": match_details,
                        "realPathLen": len(real_path),
                        "outputPathLen": len(taint_path),
                        "outputFilesMatched": output_files,
                    }
                )
    return final_matches


def get_real_and_predicted_matches_by_line(
    real_paths: Dict[str, Dict[str, Any]],
    output_dict: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    final_matches: List[Dict[str, Any]] = []
    for path_hash, real_path_data in real_paths.items():
        deduped_real = dedupe_nodes(real_path_data)
        match_details = compare_paths_by_line(deduped_real, output_dict)
        if match_details:
            output_files = sorted({item["outputFile"] for item in match_details})
            final_matches.append(
                {
                    "pathHash": path_hash,
                    "realPath": deduped_real,
                    "outputPath": output_dict,
                    "matchDetails": match_details,
                    "realPathLen": len(deduped_real),
                    "outputFilesMatched": output_files,
                    "totalOutputFiles": len(output_dict),
                }
            )
    return final_matches


def get_all_lcs_matches(real_paths: Dict[str, Dict[str, Any]], output_paths: List[Dict[str, Any]]) -> Dict[Tuple[str, int], Dict[str, Any]]:
    all_lcs: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for path_hash, real_path in real_paths.items():
        for op_idx, output_path in enumerate(output_paths):
            taint_path = output_path.get("taint_path", [])
            lcs_matches = longest_common_subsequence_stretched(real_path, taint_path, min_len=1)
            best = {} if len(lcs_matches) < 1 else lcs_matches[0]
            if best:
                best["realPathLen"] = len(real_path)
            all_lcs[(path_hash, op_idx)] = best
    return all_lcs
