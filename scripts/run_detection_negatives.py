"""Run the RQ4 detection negatives with multi-run majority decoding (R3C12).

Copy of ``run_llms_on_negative_samples.py`` that adds ``--runs``/``--seed``/
``--temperature``/``--out-dir`` and calls the detection pipeline
(``run_negative_samples_detect``), which applies the RQ1 / R2C3 decoding
settings and tags each run with a run index. The original script is untouched.
"""

import argparse

from dotenv import load_dotenv

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import RunConfig
from src.negative_pipeline_detect import run_negative_samples_detect


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the RQ4 detection negatives (multi-run majority)."
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
    parser.add_argument(
        "--runs",
        type=int,
        default=4,
        help="Number of repetitions per (sample, prompt) for multi-run majority.",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.2,
        help="Sampling temperature for chat models (auto-omitted for reasoning models).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1000,
        help="Base seed; run i uses seed+i (forwarded for OpenAI chat models).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel worker threads for API calls (default 1 = sequential).",
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default=None,
        help="Where to write run logs (default: output/runs).",
    )
    parser.add_argument(
        "--dataset-dir",
        type=str,
        default=None,
        help="Negative-samples dataset root (default: data/negative_samples).",
    )
    return parser


def parse_args() -> tuple[RunConfig, int]:
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
        runs=args.runs,
        temperature=args.temperature,
        seed=args.seed,
        out_dir=args.out_dir,
        dataset_dir=args.dataset_dir,
    )
    config.validate_paths()
    return config, args.workers


def main() -> None:
    config, workers = parse_args()
    run_negative_samples_detect(config, workers=workers)


if __name__ == "__main__":
    load_dotenv()
    main()
