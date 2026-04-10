import argparse
from pathlib import Path

import csv
import os
from dotenv import load_dotenv

import argparse

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from src.log_analysis_pipeline import run_log_analysis
from src.utils.config import AnalysisConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze mixed RQ1 and negative-sample LLM run logs."
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=None,
        help="Directory containing JSON log files. Uses config default if omitted.",
    )
    parser.add_argument(
        "--cvepath-dataset-dir",
        type=Path,
        default=None,
        help="CVEPath dataset root. Uses config default if omitted.",
    )
    parser.add_argument(
        "--negative-dataset-dir",
        type=Path,
        default=None,
        help="Negative-samples dataset root. Uses config default if omitted.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory where analysis outputs will be written. Uses config default if omitted.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively scan the logs directory.",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Disable recursive scan.",
    )
    parser.add_argument(
        "--thresholds",
        nargs="*",
        type=float,
        default=None,
        help="Thresholds used for RQ1 success/failure statistical tests.",
    )
    parser.add_argument(
        "--analysis-model",
        type=str,
        default=None,
        help="Analysis model used for CWE analysis and success/failure statistical tests."
    )
    return parser


def parse_args() -> AnalysisConfig:
    args = build_parser().parse_args()

    default_config = AnalysisConfig()

    if args.recursive and args.no_recursive:
        raise ValueError("Use only one of --recursive or --no-recursive.")

    recursive = default_config.recursive
    if args.recursive:
        recursive = True
    if args.no_recursive:
        recursive = False

    config = AnalysisConfig(
        logs_dir=args.logs_dir if args.logs_dir is not None else default_config.logs_dir,
        analysis_model=args.analysis_model if args.analysis_model is not None else default_config.analysis_model,
        cvepath_dataset_dir=(
            args.cvepath_dataset_dir
            if args.cvepath_dataset_dir is not None
            else default_config.cvepath_dataset_dir
        ),
        negative_dataset_dir=(
            args.negative_dataset_dir
            if args.negative_dataset_dir is not None
            else default_config.negative_dataset_dir
        ),
        output_dir=args.output_dir if args.output_dir is not None else default_config.output_dir,
        recursive=recursive,
        thresholds=args.thresholds if args.thresholds is not None else default_config.thresholds,
    )
    config.validate_paths()
    return config


def main() -> None:
    config = parse_args()
    run_log_analysis(config)


if __name__ == "__main__":
    load_dotenv()
    main()