import argparse

from dotenv import load_dotenv

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from src.utils.config import RunConfig
from src.negative_pipeline import run_negative_samples


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the negative-samples single-file experiment."
    )

    parser.add_argument(
        "--language",
        type=str,
        choices=["Java", "Python", "all"],
        default="all",
        help="Which language split to run.",
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
        "--prompt-mode",
        type=str,
        choices=["llmpath", "baseline", "all"],
        default="all",
        help="Which prompt set to run.",
    )
    parser.add_argument(
        "--actual-label",
        type=int,
        default=0,
        help="Ground-truth label to store in the run log for negative samples.",
    )
    return parser


def parse_args() -> RunConfig:
    args = build_parser().parse_args()

    config = RunConfig(
        task="negative",
        language=args.language,
        cve=None,
        run_all_cves=False,
        model=args.model,
        provider=args.provider,
        prompt_mode=args.prompt_mode,
        actual_label=args.actual_label,
    )
    config.validate_paths()
    return config


def main() -> None:
    config = parse_args()
    run_negative_samples(config)


if __name__ == "__main__":
    load_dotenv()
    main()