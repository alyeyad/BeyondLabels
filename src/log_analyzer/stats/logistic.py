from __future__ import annotations

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
        return pd.DataFrame(columns=["NOR", "AUC", "Brier", "VPL", "Files", "Tokens"])

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
            rows.append({"NOR": threshold, "AUC": np.nan, "Brier": np.nan, "VPL": np.nan, "Files": np.nan, "Tokens": np.nan})
            continue

        success = (cur_df[score_col] >= threshold).astype(int)
        y = 1 - success

        if y.nunique() < 2:
            rows.append({"NOR": threshold, "AUC": np.nan, "Brier": np.nan, "VPL": np.nan, "Files": np.nan, "Tokens": np.nan})
            continue

        X = cur_df[feature_cols].to_numpy()
        X_scaled = StandardScaler().fit_transform(X)

        clf = LogisticRegression(max_iter=2000)
        clf.fit(X_scaled, y)

        prob_failure = clf.predict_proba(X_scaled)[:, 1]
        row = {
            "NOR": float(threshold),
            "AUC": float(roc_auc_score(y, prob_failure)),
            "Brier": float(brier_score_loss(y, prob_failure)),
        }

        for feat, coef in zip(feature_cols, clf.coef_[0]):
            row[feature_name_map[feat]] = float(coef)

        rows.append(row)

    out = pd.DataFrame(rows)
    for col in ["AUC", "Brier", "VPL", "Files", "Tokens"]:
        if col in out.columns:
            out[col] = out[col].round(2)
    return out