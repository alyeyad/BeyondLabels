import argparse
from pathlib import Path
from dotenv import load_dotenv

from src.config import RunConfig
from src.pipeline import run_experiment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run RQ1 prompt experiments for a CVE."
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        required=True,
        help="Path to the dataset root directory.",
    )
    parser.add_argument(
        "--cve",
        type=str,
        required=True,
        help="CVE identifier, e.g. CVE-2021-41110",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-4o",
        help="Model name to use.",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default="openai",
        help="LLM provider name.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("output"),
        help="Directory where logs/results will be written.",
    )
    parser.add_argument(
        "--prompt-mode",
        type=str,
        choices=["llmql", "baseline", "all"],
        default="all",
        help="Which prompt set to run.",
    )
    parser.add_argument(
        "--actual-label",
        type=bool,
        default=True,
        help="Ground-truth label to store in the run log.",
    )
    return parser


def parse_args() -> RunConfig:
    args = build_parser().parse_args()

    config = RunConfig(
        dataset_dir=args.dataset_dir,
        cve=args.cve,
        model=args.model,
        provider=args.provider,
        out_dir=args.out_dir,
        prompt_mode=args.prompt_mode,
        actual_label=args.actual_label,
    )
    config.validate_paths()
    return config


def main() -> None:
    config = parse_args()
    run_experiment(config)


if __name__ == "__main__":
    load_dotenv()
    main()