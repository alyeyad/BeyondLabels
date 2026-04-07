from __future__ import annotations

from typing import Any, Dict, List, Tuple


def get_source_sink_detections(
    all_matches: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
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


def find_best_lcs_match(
    lcs_matches: Dict[Tuple[str, int], Dict[str, Any]],
    prompt_data: Dict[str, Any],
) -> Dict[str, Any]:
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