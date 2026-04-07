from __future__ import annotations

from typing import Any, Dict, List

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


def cohens_d_and_interpret(success: List[float], failure: List[float]) -> tuple[float, str]:
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


def cliffs_delta(x: List[float], y: List[float]) -> tuple[float, str]:
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