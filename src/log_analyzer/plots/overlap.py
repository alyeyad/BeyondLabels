from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def add_overlap_bins(
    df: pd.DataFrame,
    score_col: str,
    out_col: str = "overlap_bin",
) -> pd.DataFrame:
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


def plot_nor_scatter(
    df: pd.DataFrame,
    output_path: Path | None = None,
    x_col: str = "CVE",
    overlap_col: str = "nor",
    title: str = "",
    model: str = "claude-sonnet-4-5",
    figsize: tuple[int, int] = (20, 5),
    show: bool = False,
):
    df = df[(df["promptType"] == "llmql") & (df["model"] == model)].copy()
    df[overlap_col] = df[overlap_col].replace({-1: 0})

    df["overlap_bin"] = pd.cut(
        df[overlap_col],
        bins=[0, 0.25, 0.75, 1.0],
        labels=["Low", "Medium", "High"],
        include_lowest=True,
    )

    num_sorted = df.sort_values(by=overlap_col, ascending=False).copy()
    num_sorted = num_sorted.rename(
        columns={
            overlap_col: "Node Overlap Ratio",
            "overlap_bin": "NOR Level",
        }
    )

    plt.figure(figsize=figsize)
    sns.scatterplot(
        data=num_sorted,
        x=x_col,
        y="Node Overlap Ratio",
        hue="NOR Level",
        palette=["#0072B2", "#E69F00", "#009E73"],
        s=85,
    )

    for y in [0.0, 0.25, 0.5, 0.75, 1.0]:
        plt.axhline(y=y, linestyle="--", linewidth=1, color="gray", alpha=0.6)

    plt.yticks([0, 0.25, 0.5, 0.75, 1.0])
    plt.xlabel("CVEs")
    plt.ylabel("Node Overlap Ratio (NOR)")
    plt.xticks([])
    plt.title(title)
    plt.legend(loc="upper right")

    if output_path:
        plt.savefig(output_path, format="pdf", bbox_inches="tight")

    if show:
        plt.show()
    else:
        plt.close()

    return df, num_sorted