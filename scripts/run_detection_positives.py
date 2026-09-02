"""Run baseline-prompt predictions on the positive CVEs, parallelized (R3C12).

Copy of ``run_llms_on_cvepath.py`` that calls the parallel pipeline
(``run_experiment_parallel``) and adds ``--workers``. Used to add the coarse
baseline positive predictions for the RQ4 detection table; the LLMPath positives
already exist under output/runs. The original script is untouched.
"""

import argparse

from dotenv import load_dotenv

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import RunConfig
from src.cvepath_pipeline_detect import run_experiment_parallel


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run baseline predictions on positive CVEs (parallel)."
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--cve", type=str, help="Single CVE identifier, e.g. CVE-2021-41110")
    target_group.add_argument("--all-cves", action="store_true", help="Run all CVEs in the dataset.")

    parser.add_argument("--language", type=str, choices=["Java", "Python", "all"], default="all")
    parser.add_argument("--model", type=str, default="gpt-4o")
    parser.add_argument("--provider", type=str, default="openai")
    parser.add_argument(
        "--prompt-mode", type=str, choices=["llmpath", "baseline", "all"], default="baseline",
        help="Default 'baseline' (LLMPath positives already exist).",
    )
    parser.add_argument("--actual-label", type=int, default=1)
    parser.add_argument("--runs", type=int, default=4)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=1000)
    parser.add_argument(
        "--workers", type=int, default=1,
        help="Number of parallel worker threads for API calls (default 1 = sequential).",
    )
    parser.add_argument("--distractors", type=str, default="0")
    parser.add_argument("--distractor-seed", type=int, default=1234)
    parser.add_argument(
        "--distractor-repos-dir",
        type=str,
        default=None,
        help="Root of full vulnerable-commit repo checkouts "
             "(default: output/original_repos from clone_cvepath_repos.py).",
    )
    parser.add_argument("--out-dir", type=str, default=None)
    parser.add_argument("--dataset-dir", type=str, default=None)
    return parser


def parse_args() -> tuple[RunConfig, int]:
    args = build_parser().parse_args()

    config = RunConfig(
        task="rq1",
        language=args.language,
        cve=args.cve,
        run_all_cves=args.all_cves,
        model=args.model,
        provider=args.provider,
        prompt_mode=args.prompt_mode,
        actual_label=args.actual_label,
        runs=args.runs,
        temperature=args.temperature,
        seed=args.seed,
        distractors=args.distractors,
        distractor_seed=args.distractor_seed,
        distractor_repos_dir=args.distractor_repos_dir,
        dataset_dir=args.dataset_dir,
        out_dir=args.out_dir,
    )
    config.validate_paths()
    return config, args.workers


def main() -> None:
    config, workers = parse_args()
    run_experiment_parallel(config, workers=workers)


if __name__ == "__main__":
    load_dotenv()
    main()
