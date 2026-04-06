import argparse
from pathlib import Path

from src.config import AnalysisConfig
from src.analyzer_pipeline import run_log_analysis


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze PathVul-style LLM run logs."
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=None,
        help="Directory containing JSON log files.",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=None,
        help="PathVul dataset root containing Java/ and Python/.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory where analysis outputs will be written.",
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
        help="Thresholds used for success/failure statistical tests.",
    )
    return parser


def parse_args() -> AnalysisConfig:
    args = build_parser().parse_args()

    recursive = True
    if args.no_recursive:
        recursive = False
    elif args.recursive:
        recursive = True

    config = AnalysisConfig(
        logs_dir=args.logs_dir if args.logs_dir is not None else AnalysisConfig().logs_dir,
        dataset_dir=args.dataset_dir if args.dataset_dir is not None else AnalysisConfig().dataset_dir,
        output_dir=args.output_dir if args.output_dir is not None else AnalysisConfig().output_dir,
        recursive=recursive,
        thresholds=args.thresholds if args.thresholds is not None else AnalysisConfig().thresholds,
    )
    config.validate_paths()
    return config


def main() -> None:
    config = parse_args()
    run_log_analysis(config)


if __name__ == "__main__":
    main()