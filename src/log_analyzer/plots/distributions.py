from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def save_success_failure_violin_plots(
    df: pd.DataFrame,
    output_path: Path,
    threshold: float = 0.5,
    score_col: str = "nor",
    feature_map: dict[str, str] | None = None,
    palette: dict[str, str] | None = None,
) -> None:
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