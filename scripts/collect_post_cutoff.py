#!/usr/bin/env python3
"""Collect a post-cutoff CVEPath set, from GHSA discovery through PF-1.

Runs the CVEPath study-design stages end to end on advisories published after a
model knowledge cutoff:

    GHSA discovery -> NVD/OSV/GitHub metadata -> CS-1 (path-problem CWE)
    -> removed-line hunks -> CS-2 (vulnerability-path-fixing file)
    -> clone at parent SHA -> PC-1 (CodeQL database + query augmentation)
    -> PC-2 (database analyze) -> PF-1 (max vulnerable-hunk overlap)

PF-2 (manual validation of each reference path) is not automated and is not
performed here.

Prerequisites:
  * ``python scripts/setup_codeql.py`` (CodeQL CLI 2.15.3), or ``CODEQL_PATH``
  * ``scripts/.env`` with ``GITHUB_TOKEN``, ``NVD_API_KEY`` and, for CS-2, the
    key for the classifier provider (``ANTHROPIC_API_KEY`` by default)

Example:
    python scripts/collect_post_cutoff.py --language Python --n 14

Output lands under ``output/post_cutoff/`` (gitignored). The PF-1 pack in
``output/post_cutoff/cvepath/<language>/`` uses CVEPath layout and can be passed
to ``scripts/run_llms_on_cvepath.py --dataset-dir``.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.post_cutoff import build_db, clone, collect, cs1, cs2, funnel, pack_pf1, run_queries  # noqa: E402
from src.post_cutoff.config import (  # noqa: E402
    DEFAULT_CS2_MODEL,
    DEFAULT_CUTOFF,
    DEFAULT_OUT,
    DEFAULT_SINCE,
    PROMPT_PATH,
    QUERY_PACKS,
    Layout,
    custom_cwe_queries,
    log,
    resolve_codeql,
    warn,
)

STAGES = ["collect", "cs1", "cs2", "clone", "pc1", "pc2", "pack"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--language",
        choices=["Python", "Java"],
        default="Python",
        help="Only Python is wired through PC-1/PC-2 (Java databases need a "
             "per-project build command). Default: Python.",
    )
    parser.add_argument(
        "--n",
        type=int,
        default=None,
        help="Stop once this many CVEs have non-empty PF-1 paths. "
             "Discovery and CS still run over the full pool. Default: no limit.",
    )
    parser.add_argument(
        "--cutoff",
        default=DEFAULT_CUTOFF,
        help=f"Keep CVEs published and fixed strictly after this day (default {DEFAULT_CUTOFF}).",
    )
    parser.add_argument(
        "--since",
        default=DEFAULT_SINCE,
        help=f"GHSA published-on-or-after date (default {DEFAULT_SINCE}).",
    )
    parser.add_argument(
        "--cve",
        action="append",
        default=None,
        metavar="CVE-ID",
        help="Restrict everything after discovery to these CVEs (repeatable).",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Run directory.")
    parser.add_argument(
        "--codeql",
        type=Path,
        default=None,
        help="CodeQL CLI. Default: $CODEQL_PATH, else tools/codeql/codeql.",
    )
    parser.add_argument("--query-packs", type=Path, default=QUERY_PACKS)

    parser.add_argument("--cs2-model", default=DEFAULT_CS2_MODEL)
    parser.add_argument("--cs2-provider", default="anthropic")
    parser.add_argument("--cs2-prompt", type=Path, default=PROMPT_PATH)
    parser.add_argument("--cs2-workers", type=int, default=4)
    parser.add_argument("--cs2-limit", type=int, default=None, help="Max LLM calls.")

    parser.add_argument("--clone-workers", type=int, default=4)
    parser.add_argument("--clone-retries", type=int, default=5)
    parser.add_argument("--threads", type=int, default=6, help="CodeQL threads.")
    parser.add_argument("--ram", type=int, default=24576, help="CodeQL RAM in MB.")

    parser.add_argument(
        "--max-advisories",
        type=int,
        default=None,
        help="Cap GHSA advisories scanned (smoke tests).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Cap kept metadata records during collection (smoke tests).",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Ignore the HTTP cache and re-fetch every advisory, CVE and commit.",
    )
    parser.add_argument(
        "--stages",
        default="all",
        help="Comma-separated subset of " + ",".join(STAGES) + " (default: all).",
    )
    return parser


def _selected_stages(raw: str) -> list[str]:
    if raw.strip().lower() in {"", "all"}:
        return list(STAGES)
    chosen = [s.strip() for s in raw.split(",") if s.strip()]
    unknown = [s for s in chosen if s not in STAGES]
    if unknown:
        raise SystemExit(f"unknown stage(s) {unknown}; choose from {STAGES}")
    return [s for s in STAGES if s in chosen]


def main() -> int:
    args = build_parser().parse_args()
    load_dotenv()
    load_dotenv(SCRIPT_DIR / ".env", override=False)

    stages = _selected_stages(args.stages)
    layout = Layout(root=args.out)
    layout.root.mkdir(parents=True, exist_ok=True)
    codeql = resolve_codeql(args.codeql)
    language = args.language
    resume = not args.no_resume
    query_root = custom_cwe_queries(args.query_packs)
    # A --cve run covers part of the pool, so its stage results must not
    # overwrite the funnel of a full run.
    scoped = bool(args.cve)

    def record_stage(stage: str, cves: set[str]) -> set[str]:
        if not scoped:
            funnel.write(layout, {stage: cves})
        return cves

    log(f"[run] language={language} n={args.n or 'all'} out={layout.root}")
    log(f"[run] stages={stages}" + (" (scoped to --cve)" if scoped else ""))

    # --- Discovery, CS-1 gate on CWE support, and metadata --------------------
    if "collect" in stages:
        records, discovery = collect.collect(
            layout=layout,
            languages=[language],
            since=date.fromisoformat(args.since),
            cutoff=date.fromisoformat(args.cutoff),
            resume=resume,
            limit=args.limit,
            max_advisories=args.max_advisories,
            query_root=query_root,
        )
        collect.write_outputs(layout, records)
        if not scoped:
            funnel.write(layout, discovery)
    records = collect.load_records(layout.candidates)
    records = [r for r in records if r.get("cve_language") == language]
    if scoped:
        wanted = set(args.cve)
        records = [r for r in records if r["cve_id"] in wanted]
        missing = wanted - {r["cve_id"] for r in records}
        if missing:
            warn(f"[run] --cve not in the {language} candidate pool: {sorted(missing)}")
    log(f"[run] {len(records)} {language} candidate records")

    # --- CS-1: path-problem CWE, then drop addition-only fixes ---------------
    if "cs1" in stages:
        record_stage("cs1", cs1.cs1_ids(records, query_root))
        record_stage("removed_lines", cs1.filter_removed_hunks(layout, records, query_root))
    # Pools come from the stage artifacts, not the funnel lists, so that a
    # partial or --cve-scoped run resumes correctly.
    pool = [r for r in records if r["cve_id"] in cs1.hunks_available(layout, records)]

    # --- CS-2: keep CVEs with a vulnerability-path-fixing file ---------------
    if "cs2" in stages:
        record_stage(
            "cs2",
            cs2.classify(
                layout,
                pool,
                model=args.cs2_model,
                provider=args.cs2_provider,
                workers=args.cs2_workers,
                limit=args.cs2_limit,
                prompt=args.cs2_prompt,
            ),
        )
    cs2_keep = cs2.passed_ids(layout, pool, args.cs2_model)
    cs2_pool = [r for r in pool if r["cve_id"] in cs2_keep]
    log(f"[run] CS-2 pool: {len(cs2_pool)}")

    # --- Clone the vulnerable revision ---------------------------------------
    if "clone" in stages:
        clone.clone_all(
            layout,
            cs2_pool,
            workers=args.clone_workers,
            retries=args.clone_retries,
        )

    # --- PC-1: CodeQL databases ----------------------------------------------
    if "pc1" in stages:
        record_stage(
            "pc1", build_db.build_all(layout, cs2_pool, codeql=codeql, language=language)
        )

    # --- PC-1 augmentation, PC-2 analysis, PF-1 overlap ----------------------
    if "pc2" in stages:
        pf1_ids = run_queries.run_all(
            layout,
            cs2_pool,
            codeql=codeql,
            language=language,
            cs2_model=args.cs2_model,
            target=args.n,
            threads=args.threads,
            ram=args.ram,
            query_packs=args.query_packs,
        )
        record_stage("pc2", run_queries.pc2_ids(layout, cs2_pool))
        record_stage("pf1", pf1_ids)

    # --- Pack PF-1 survivors in CVEPath layout -------------------------------
    if "pack" in stages:
        packed = pack_pf1.pack_all(layout, cs2_pool, language=language)
        if args.n is not None and len(packed) < args.n:
            warn(
                f"[run] packed {len(packed)} CVEs but --n was {args.n}; "
                "widen --since or re-run to continue where this left off"
            )

    if not scoped:
        funnel.write_markdown(
            layout, language=language, cutoff=args.cutoff, since=args.since
        )
        funnel.print_summary(layout)
    log(f"[run] CVEPath-layout output: {layout.cvepath / language}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
