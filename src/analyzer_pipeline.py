from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.config import AnalysisConfig
from src.log_analyzer.reporting import (
    create_combined_results_df,
    create_refined_matches,
    get_source_sink_detections,
    process_output_files,
    save_json,
)
from src.log_analyzer.stats_utils import analyze_at_threshold


def run_threshold_tests(
    df: pd.DataFrame,
    score_col: str,
    thresholds: list[float],
) -> dict[float, dict]:
    if df.empty:
        return {}

    excluded = {
        "CVE",
        "run_id",
        "prompt_type",
        "model",
        "language",
        score_col,
        "numOverlapNodes",
        "op_label",
        "success",
        "lcs_success",
        "lcs_length",
    }
    columns_to_test = [col for col in df.columns if col not in excluded]

    all_results: dict[float, dict] = {}
    for threshold in thresholds:
        all_results[threshold] = analyze_at_threshold(
            df=df,
            threshold=threshold,
            columns_to_test=columns_to_test,
            score_col=score_col,
            excluded_cols=list(excluded),
        )
    return all_results


def run_log_analysis(config: AnalysisConfig) -> None:
    data_dir = config.output_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    print("[1/6] Processing logs...")
    all_matches, excluded_files, _ = process_output_files(
        logs_dir=Path(config.logs_dir),
        dataset_dir=Path(config.dataset_dir),
        recursive=config.recursive,
    )
    save_json(data_dir / "excluded_files.json", excluded_files)

    print("[2/6] Computing source/sink detections...")
    source_sink_det = get_source_sink_detections(all_matches)

    print("[3/6] Building refined node and LCS matches...")
    node_refined_matches, lcs_refined_matches = create_refined_matches(
        all_matches,
        source_sink_det,
    )

    print("[4/6] Converting outputs to tables...")
    combined_df = create_combined_results_df(
        node_refined_matches,
        lcs_refined_matches,
    )
    if not combined_df.empty:
        combined_df.to_csv(data_dir / "combined_refined_match.csv", index=False)


    print("[6/6] Done.")
    print(f"Processed runs: {sum(len(v) for v in all_matches.values())}")
    print(f"Processed CVEs: {len(all_matches)}")
    print(f"Excluded log files: {len(excluded_files)}")
    print(f"Outputs written to: {config.output_dir}")