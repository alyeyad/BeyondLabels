from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

import pandas as pd


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

    for col in ["nor", "lcnr", "numOverlapNodes", "lcs_length", "outputPathLen", "lcs_outputPathLen"]:
        if col in combined.columns:
            combined[col] = combined[col].replace({-1: 0})

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

    df_unique = result.loc[
        result.groupby(["CVE", "promptType", "model"])["nor"].idxmax()
    ].reset_index(drop=True)

    return df_unique


def create_model_summary_table(combined_df: pd.DataFrame) -> pd.DataFrame:
    if combined_df.empty:
        return pd.DataFrame(
            columns=[
                "Model",
                "Median NOR",
                "Median LCNR",
                "Mean Source Hit | NOR > 0",
                "Mean Sink Hit | NOR > 0",
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

    summary_all = (
        df.groupby("model", dropna=False)
        .agg(
            median_overlap=("nor", "median"),
            median_lcs_overlap=("lcnr", "median"),
        )
        .reset_index()
    )

    overlap_df = df[(df["nor"] > 0) | (df["numOverlapNodes"] > 0)].copy()

    if overlap_df.empty:
        summary_all["mean_real_src_found"] = 0.0
        summary_all["mean_real_sink_found"] = 0.0
    else:
        summary_overlap = (
            overlap_df.groupby("model", dropna=False)
            .agg(
                mean_real_src_found=("sourceHit", "mean"),
                mean_real_sink_found=("sinkHit", "mean"),
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

    return summary_all.rename(
        columns={
            "model": "Model",
            "median_overlap": "Median NOR",
            "median_lcs_overlap": "Median LCNR",
            "mean_real_src_found": "Mean Source Hit | NOR > 0",
            "mean_real_sink_found": "Mean Sink Hit | NOR > 0",
        }
    )


def extract_cwe_ints(value: Any) -> set[int]:
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

    for col in ["nor", "lcnr", "sourceHit", "sinkHit", "numOverlapNodes"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

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
            for key in rows:
                rows[key].append(empty_value)
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

    for col in out.columns:
        if col != "Metric":
            out[col] = out[col].apply(
                lambda x: round(x, 2) if pd.notna(x) and not isinstance(x, str) else x
            )

    return out