from __future__ import annotations

from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy.stats import mannwhitneyu, shapiro, ttest_ind


def cohens_d(x: np.ndarray, y: np.ndarray) -> float:
    nx, ny = len(x), len(y)
    if nx < 2 or ny < 2:
        return 0.0
    dof = nx + ny - 2
    if dof <= 0:
        return 0.0
    pooled_std = np.sqrt(((nx - 1) * np.var(x, ddof=1) + (ny - 1) * np.var(y, ddof=1)) / dof)
    if pooled_std == 0:
        return 0.0
    return float((np.mean(x) - np.mean(y)) / pooled_std)


def cohens_d_and_interpret(success: List[float], failure: List[float]) -> Tuple[float, str]:
    d = cohens_d(np.array(success), np.array(failure))
    abs_d = abs(d)
    if abs_d < 0.2:
        interpretation = "negligible"
    elif abs_d < 0.5:
        interpretation = "small"
    elif abs_d < 0.8:
        interpretation = "medium"
    else:
        interpretation = "large"
    return d, interpretation


def cliffs_delta(x: List[float], y: List[float]) -> Tuple[float, str]:
    x_arr = np.array(x)
    y_arr = np.array(y)
    n_x, n_y = len(x_arr), len(y_arr)
    if n_x == 0 or n_y == 0:
        return 0.0, "negligible"

    greater = 0
    less = 0
    for x_i in x_arr:
        greater += int(np.sum(x_i > y_arr))
        less += int(np.sum(x_i < y_arr))

    delta = (greater - less) / (n_x * n_y)
    abs_delta = abs(delta)
    if abs_delta < 0.147:
        magnitude = "negligible"
    elif abs_delta < 0.33:
        magnitude = "small"
    elif abs_delta < 0.474:
        magnitude = "medium"
    else:
        magnitude = "large"
    return float(delta), magnitude


def run_statistical_tests(success_data: List[float], failure_data: List[float], column_name: str) -> Dict[str, Any]:
    p_success = shapiro(success_data).pvalue if len(success_data) > 2 else 1.0
    p_failure = shapiro(failure_data).pvalue if len(failure_data) > 2 else 1.0

    u_stat, wilcoxon_p = mannwhitneyu(success_data, failure_data, alternative="two-sided")
    delta, magnitude = cliffs_delta(failure_data, success_data)
    t_stat, cohen_p = ttest_ind(success_data, failure_data, equal_var=False)
    cohens_d_val, cohens_interp = cohens_d_and_interpret(success_data, failure_data)

    return {
        "column": column_name,
        "success_normality": float(p_success),
        "failure_normality": float(p_failure),
        "delta": float(delta),
        "mag": magnitude,
        "wilcoxon_p": float(wilcoxon_p),
        "U-Stat": float(u_stat),
        "cohen_p": float(cohen_p),
        "t_stat": float(t_stat),
        "cohens_d": float(cohens_d_val),
        "cohen_interpretation": cohens_interp,
    }


def analyze_at_threshold(
    df: pd.DataFrame,
    threshold: float,
    columns_to_test: List[str],
    score_col: str = "nor",
    excluded_cols: List[str] | None = None,
) -> Dict[str, Any]:
    excluded = set(excluded_cols or [])
    df_success = df[df[score_col] >= threshold]
    df_failure = df[df[score_col] < threshold]

    results: Dict[str, Any] = {
        "threshold": threshold,
        "success_size": int(len(df_success)),
        "failure_size": int(len(df_failure)),
    }

    for col in columns_to_test:
        if col in excluded:
            continue
        success_data = df_success[col].tolist()
        failure_data = df_failure[col].tolist()
        if not success_data or not failure_data:
            continue
        results[col] = run_statistical_tests(success_data, failure_data, col)
    return results
import ast
import json
from pathlib import Path
from typing import Union

import pandas as pd


FEATURE_LABELS = {
    "realPathLen": "Vulnerable Path Length",
    "numInputFiles": "Number of Files per Path",
    "numInputTokens": "Number of Input Tokens",
    "numInputLines": "Number of Input Lines",
}

MAG_LABELS = {
    "negligible": "N",
    "small": "S",
    "medium": "M",
    "large": "L",
}


def _load_stats(data_or_path: Union[str, Path, dict]) -> dict:
    """
    Accepts either:
      - a Python dict
      - a path to a valid JSON file
      - a path to a text file containing a Python-style dict (like your example)
    """
    if isinstance(data_or_path, dict):
        return data_or_path

    path = Path(data_or_path)
    text = path.read_text(encoding="utf-8").strip()

    # Try JSON first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Fallback for Python-style dict text
    return ast.literal_eval(text)


def _format_p(p: float) -> str:
    if p is None:
        return ""
    # Nice compact formatting for table display
    return f"{p:.2g}"


def _format_effect(delta: float, mag: str, abs_delta: bool = True) -> str:
    if delta is None:
        return ""
    value = abs(delta) if abs_delta else delta
    mag_short = MAG_LABELS.get(str(mag).lower(), str(mag))
    return f"{value:.2f} ({mag_short})"


def json_to_nor_table_csv(
    data_or_path: Union[str, Path, dict],
    csv_path: Union[str, Path],
    p_key: str = "wilcoxon_p",
    delta_key: str = "delta",
    mag_key: str = "mag",
    feature_order=None,
    threshold_order=None,
    abs_delta: bool = True,
) -> pd.DataFrame:
    """
    Build a CSV table like:

                    0.25         0.5         0.75        1.0
                  p     Δ      p     Δ      p     Δ     p     Δ
    Feature
    Vulnerable...
    ...

    Parameters
    ----------
    data_or_path : dict or file path
        Your nested stats object.
    csv_path : str or Path
        Output CSV path.
    p_key : str
        Which p-value field to use, e.g. 'wilcoxon_p' or 'cohen_p'.
    delta_key : str
        Which effect-size field to use, e.g. 'delta' or 'cohens_d'.
    mag_key : str
        Which magnitude label field to use, usually 'mag'.
    abs_delta : bool
        If True, writes absolute effect size values like the screenshot style.
    """
    stats = _load_stats(data_or_path)

    if feature_order is None:
        feature_order = [
            "realPathLen",
            "numInputFiles",
            "numInputTokens",
            "numInputLines",
        ]

    if threshold_order is None:
        threshold_order = sorted(stats.keys(), key=float)

    # MultiIndex columns -> two header rows in CSV
    columns = []
    for thr in threshold_order:
        columns.append((str(thr), "p"))
        columns.append((str(thr), "Δ"))

    df = pd.DataFrame(
        index=[FEATURE_LABELS[f] for f in feature_order],
        columns=pd.MultiIndex.from_tuples(columns),
    )
    df.index.name = "Feature"

    for thr in threshold_order:
        thr_stats = stats[thr]
        for feature in feature_order:
            row_name = FEATURE_LABELS[feature]
            feat_stats = thr_stats.get(feature, {})

            p_val = feat_stats.get(p_key)
            delta_val = feat_stats.get(delta_key)
            mag_val = feat_stats.get(mag_key)

            df.loc[row_name, (str(thr), "p")] = _format_p(p_val)
            df.loc[row_name, (str(thr), "Δ")] = _format_effect(
                delta_val, mag_val, abs_delta=abs_delta
            )

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(csv_path, encoding="utf-8-sig")

    return df


from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score
from sklearn.preprocessing import StandardScaler


def create_predictive_power_table(
    df: pd.DataFrame,
    thresholds: Iterable[float] = (0.25, 0.5, 0.75, 1.0),
    score_col: str = "nor",
    model_name: str | None = None,
) -> pd.DataFrame:
    """
    Build the table:

        NOR | AUC | Brier | VPL | Files | Tokens

    where:
      - success = 1 if score_col >= threshold
      - failure = 1 - success
      - VPL coefficient comes from realPathLen
      - Files coefficient comes from numInputFiles
      - Tokens coefficient comes from numInputTokens

    Coefficients are standardized because predictors are z-scored before fitting.
    Positive coefficients mean higher failure probability.
    """
    required_cols = [
        score_col,
        "realPathLen",
        "numInputFiles",
        "numInputTokens",
        "model",
    ]

    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns for predictive power table: {missing}")

    work_df = df.copy()

    if model_name is not None:
        work_df = work_df[work_df["model"] == model_name].copy()

    if work_df.empty:
        return pd.DataFrame(
            columns=["NOR", "AUC", "Brier", "VPL", "Files", "Tokens"]
        )

    for col in [score_col, "realPathLen", "numInputFiles", "numInputTokens"]:
        work_df[col] = pd.to_numeric(work_df[col], errors="coerce")

    feature_cols = ["realPathLen", "numInputFiles", "numInputTokens"]
    feature_name_map = {
        "realPathLen": "VPL",
        "numInputFiles": "Files",
        "numInputTokens": "Tokens",
    }

    rows: list[dict[str, float]] = []

    for threshold in thresholds:
        cur_df = work_df[[score_col] + feature_cols].dropna().copy()

        if cur_df.empty:
            rows.append(
                {
                    "NOR": threshold,
                    "AUC": np.nan,
                    "Brier": np.nan,
                    "VPL": np.nan,
                    "Files": np.nan,
                    "Tokens": np.nan,
                }
            )
            continue

        # success = score >= threshold ; model FAILURE as 1
        success = (cur_df[score_col] >= threshold).astype(int)
        y = 1 - success

        # Need both classes for logistic regression / AUC
        if y.nunique() < 2:
            rows.append(
                {
                    "NOR": threshold,
                    "AUC": np.nan,
                    "Brier": np.nan,
                    "VPL": np.nan,
                    "Files": np.nan,
                    "Tokens": np.nan,
                }
            )
            continue

        X = cur_df[feature_cols].to_numpy()

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        clf = LogisticRegression(max_iter=2000)
        clf.fit(X_scaled, y)

        prob_failure = clf.predict_proba(X_scaled)[:, 1]

        auc = roc_auc_score(y, prob_failure)
        brier = brier_score_loss(y, prob_failure)

        row = {
            "NOR": float(threshold),
            "AUC": float(auc),
            "Brier": float(brier),
        }

        for feat, coef in zip(feature_cols, clf.coef_[0]):
            row[feature_name_map[feat]] = float(coef)

        rows.append(row)

    out = pd.DataFrame(rows)

    for col in ["AUC", "Brier", "VPL", "Files", "Tokens"]:
        if col in out.columns:
            out[col] = out[col].round(2)

    return out



from typing import Iterable, Sequence

import numpy as np
import pandas as pd


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
    """
    Build a binary evaluation table for selected models using:
      - all negative samples from negative_df
      - positive samples from combined_df where numInputFiles == 1

    Metrics use only:
      - actualLabel
      - outputLabel

    Deltas are computed relative to the first prompt in prompt_order:
      delta_fp = reference_fp - current_fp
      delta_fpr = reference_fpr - current_fpr

    This matches the sign convention in your screenshot, where negative values
    on the Baseline row mean Baseline has more false positives than the reference.
    """
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

    # Positive subset from RQ1 combined_df
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

    # Negative subset from negative_df
    neg_df = negative_df.copy()
    for col in ["model", "promptType", "outputLabel", "actualLabel"]:
        if col not in neg_df.columns:
            raise ValueError(f"negative_df is missing required column: {col}")

    neg_df = neg_df[neg_df["model"].isin(selected_models)].copy()
    neg_df = neg_df[["model", "promptType", "actualLabel", "outputLabel"]].copy()
    neg_df["Prompt"] = neg_df["promptType"].apply(_normalize_prompt_type)

    # Merge the positive and negative binary examples
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