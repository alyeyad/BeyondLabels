from __future__ import annotations

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
    if isinstance(data_or_path, dict):
        return data_or_path

    path = Path(data_or_path)
    text = path.read_text(encoding="utf-8").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return ast.literal_eval(text)


def _format_p(p: float) -> str:
    if p is None:
        return ""
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
            df.loc[row_name, (str(thr), "p")] = _format_p(feat_stats.get(p_key))
            df.loc[row_name, (str(thr), "Δ")] = _format_effect(
                feat_stats.get(delta_key),
                feat_stats.get(mag_key),
                abs_delta=abs_delta,
            )

    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(csv_path, encoding="utf-8-sig")

    return df