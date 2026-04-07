from __future__ import annotations

from typing import Sequence

import numpy as np
import pandas as pd


def create_negative_results_df(
    negative_runs: dict[str, dict[str, dict]],
) -> pd.DataFrame:
    rows: list[dict] = []

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


def _safe_div(num: float, den: float) -> float:
    return float(num / den) if den else 0.0


def _compute_mcc(tp: int, tn: int, fp: int, fn: int) -> float:
    denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    if denom <= 0:
        return 0.0
    return float((tp * tn - fp * fn) / np.sqrt(denom))


def _normalize_prompt_type(value: str) -> str:
    raw = str(value).strip().lower()
    if raw == "llmql":
        return "LLMQL"
    if raw == "baseline":
        return "Baseline"
    return str(value).strip()


def _binary_metrics_from_labels(actual: pd.Series, pred: pd.Series) -> dict[str, float]:
    actual = actual.astype(int)
    pred = pred.astype(int)

    tp = int(((actual == 1) & (pred == 1)).sum())
    tn = int(((actual == 0) & (pred == 0)).sum())
    fp = int(((actual == 0) & (pred == 1)).sum())
    fn = int(((actual == 1) & (pred == 0)).sum())

    fpr = _safe_div(fp, fp + tn)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    mcc = _compute_mcc(tp, tn, fp, fn)

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "FPR": fpr,
        "Precision": precision,
        "Recall": recall,
        "MCC": mcc,
    }


def create_prompt_type_label_comparison_table(
    combined_df: pd.DataFrame,
    negative_df: pd.DataFrame,
    selected_models: Sequence[str],
    prompt_order: Sequence[str] = ("LLMQL", "Baseline"),
) -> pd.DataFrame:
    if combined_df.empty and negative_df.empty:
        return pd.DataFrame(
            columns=[
                "Model", "Prompt", "TP", "TN", "FP", "FN", "FPR",
                "ΔFP", "ΔFPR", "Precision", "Recall", "MCC"
            ]
        )

    selected_models = list(selected_models)
    prompt_order = list(prompt_order)
    prompt_rank = {prompt: i for i, prompt in enumerate(prompt_order)}
    reference_prompt = prompt_order[0] if prompt_order else None

    pos_df = combined_df.copy()
    for col in ["model", "promptType", "outputLabel", "actualLabel", "numInputFiles"]:
        if col not in pos_df.columns:
            if col == "actualLabel":
                pos_df[col] = 1
            else:
                raise ValueError(f"combined_df is missing required column: {col}")

    pos_df = pos_df[pos_df["model"].isin(selected_models)].copy()
    pos_df["numInputFiles"] = pd.to_numeric(pos_df["numInputFiles"], errors="coerce")
    pos_df = pos_df[pos_df["numInputFiles"] == 1].copy()
    pos_df = pos_df[["model", "promptType", "actualLabel", "outputLabel"]].copy()
    pos_df["Prompt"] = pos_df["promptType"].apply(_normalize_prompt_type)

    neg_df = negative_df.copy()
    for col in ["model", "promptType", "outputLabel", "actualLabel"]:
        if col not in neg_df.columns:
            raise ValueError(f"negative_df is missing required column: {col}")

    neg_df = neg_df[neg_df["model"].isin(selected_models)].copy()
    neg_df = neg_df[["model", "promptType", "actualLabel", "outputLabel"]].copy()
    neg_df["Prompt"] = neg_df["promptType"].apply(_normalize_prompt_type)

    eval_df = pd.concat([pos_df, neg_df], ignore_index=True)
    if eval_df.empty:
        return pd.DataFrame(
            columns=[
                "Model", "Prompt", "TP", "TN", "FP", "FN", "FPR",
                "ΔFP", "ΔFPR", "Precision", "Recall", "MCC"
            ]
        )

    eval_df["actualLabel"] = pd.to_numeric(eval_df["actualLabel"], errors="coerce").fillna(0).astype(int)
    eval_df["outputLabel"] = pd.to_numeric(eval_df["outputLabel"], errors="coerce").fillna(0).astype(int)

    rows: list[dict[str, object]] = []

    for model in selected_models:
        model_df = eval_df[eval_df["model"] == model].copy()
        if model_df.empty:
            continue

        present_prompts = sorted(
            model_df["Prompt"].dropna().unique().tolist(),
            key=lambda p: prompt_rank.get(p, 999),
        )

        per_prompt_metrics: dict[str, dict[str, float]] = {}
        for prompt in present_prompts:
            prompt_df = model_df[model_df["Prompt"] == prompt]
            metrics = _binary_metrics_from_labels(
                actual=prompt_df["actualLabel"],
                pred=prompt_df["outputLabel"],
            )
            per_prompt_metrics[prompt] = metrics

        reference_metrics = per_prompt_metrics.get(reference_prompt) if reference_prompt else None

        for prompt in present_prompts:
            metrics = per_prompt_metrics[prompt]
            row: dict[str, object] = {
                "Model": model,
                "Prompt": prompt,
                "TP": metrics["TP"],
                "TN": metrics["TN"],
                "FP": metrics["FP"],
                "FN": metrics["FN"],
                "FPR": round(metrics["FPR"], 3),
                "ΔFP": "",
                "ΔFPR": "",
                "Precision": round(metrics["Precision"], 3),
                "Recall": round(metrics["Recall"], 3),
                "MCC": round(metrics["MCC"], 3),
            }

            if reference_metrics is not None and prompt != reference_prompt:
                delta_fp = int(reference_metrics["FP"] - metrics["FP"])
                delta_fpr = reference_metrics["FPR"] - metrics["FPR"]
                row["ΔFP"] = delta_fp
                row["ΔFPR"] = f"{delta_fpr:.0%}"

            rows.append(row)

    out = pd.DataFrame(rows)

    if not out.empty:
        out["__model_order"] = out["Model"].apply(
            lambda m: selected_models.index(m) if m in selected_models else 999
        )
        out["__prompt_order"] = out["Prompt"].apply(
            lambda p: prompt_rank.get(p, 999)
        )
        out = out.sort_values(["__model_order", "__prompt_order"]).drop(
            columns=["__model_order", "__prompt_order"]
        ).reset_index(drop=True)

    return out