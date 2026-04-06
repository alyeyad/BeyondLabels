from __future__ import annotations

from typing import Any

import pandas as pd

from src.config import AnalysisConfig
from src.log_analyzer.reporting import (
    create_combined_results_df,
    create_negative_results_df,
    create_refined_matches,
    get_source_sink_detections,
    process_output_files,
    save_json,
    plot_nor_scatter,
    create_model_summary_table,
    create_single_model_cwe_table
)
from src.log_analyzer.stats_utils import analyze_at_threshold


def run_threshold_tests(
    df: pd.DataFrame,
    score_col: str,
    thresholds: list[float],
) -> dict[float, dict[str, Any]]:
    if df.empty or score_col not in df.columns:
        return {}

    numeric_cols = list(df.select_dtypes(include="number").columns)
    excluded = {
        score_col,
        "outputLabel",
        "actualLabel",
        "labelCorrect",
    }
    columns_to_test = [col for col in numeric_cols if col not in excluded]

    all_results: dict[float, dict[str, Any]] = {}
    for threshold in thresholds:
        all_results[threshold] = analyze_at_threshold(
            df=df,
            threshold=threshold,
            columns_to_test=columns_to_test,
            score_col=score_col,
            excluded_cols=list(excluded),
        )
    return all_results


def build_negative_summary(negative_df: pd.DataFrame) -> dict[str, Any]:
    if negative_df.empty:
        return {
            "num_runs": 0,
            "num_correct": 0,
            "accuracy": 0.0,
            "tp": 0,
            "tn": 0,
            "fp": 0,
            "fn": 0,
            "false_positive_rate": 0.0,
        }

    actual = negative_df["actualLabel"].astype(int)
    pred = negative_df["outputLabel"].astype(int)

    tp = int(((actual == 1) & (pred == 1)).sum())
    tn = int(((actual == 0) & (pred == 0)).sum())
    fp = int(((actual == 0) & (pred == 1)).sum())
    fn = int(((actual == 1) & (pred == 0)).sum())

    neg_count = int((actual == 0).sum())
    fpr = (fp / neg_count) if neg_count > 0 else 0.0

    return {
        "num_runs": int(len(negative_df)),
        "num_correct": int((actual == pred).sum()),
        "accuracy": float((actual == pred).mean()),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "false_positive_rate": float(fpr),
    }


def run_log_analysis(config: AnalysisConfig) -> None:
    data_dir = config.output_dir / "data"
    img_dir = config.output_dir / "plots"
    data_dir.mkdir(parents=True, exist_ok=True)
    img_dir.mkdir(parents=True, exist_ok=True)

    print("[1/6] Processing logs...")
    rq1_matches, negative_runs, excluded_files, _ = process_output_files(
        logs_dir=config.logs_dir,
        pathvul_dataset_dir=config.pathvul_dataset_dir,
        negative_dataset_dir=config.negative_dataset_dir,
        recursive=config.recursive,
    )
    save_json(data_dir / "excluded_files.json", excluded_files)

    if rq1_matches:
        print("[2/6] Computing RQ1 source/sink detections...")
        source_sink_det = get_source_sink_detections(rq1_matches)

        print("[3/6] Building RQ1 refined node and LCS matches...")
        node_refined_matches, lcs_refined_matches = create_refined_matches(
            rq1_matches,
            source_sink_det,
        )

        print("[4/6] Writing RQ1 results...")
        combined_df = create_combined_results_df(
            node_refined_matches,
            lcs_refined_matches,
        )
        if not combined_df.empty:
            combined_df.to_csv(data_dir / "rq1_combined_refined_match.csv", index=False)
        model_summary_df = create_model_summary_table(combined_df)
        model_summary_df.to_csv(data_dir / "rq1_model_summary.csv", index=False)

        best_model = "claude-sonnet-4-5"

        plot_nor_scatter(
            combined_df,
            model=best_model,
            output_path=img_dir / f"rq1_nor_binned_scatter_{best_model.replace('/','__')}.pdf"
        )
        cwe_table = create_single_model_cwe_table(
            combined_df,
            model_name=best_model,
            target_cwes=(22, 20, 94, 502),
        )

        cwe_table.to_csv(data_dir / f"rq1_cwe_table_{best_model.replace('/','__')}.csv", index=False)
    else:
        print("[2/6] No RQ1 logs found.")

    if negative_runs:
        print("[5/6] Writing negative-results table...")
        negative_df = create_negative_results_df(negative_runs)
        if not negative_df.empty:
            negative_df.to_csv(data_dir / "negative_label_results.csv", index=False)
    else:
        print("[5/6] No negative logs found.")

    print("[6/6] Done.")
    print(f"Processed RQ1 groups: {len(rq1_matches)}")
    print(f"Processed negative groups: {len(negative_runs)}")
    print(f"Excluded log files: {len(excluded_files)}")
    print(f"Outputs written to: {config.output_dir}")