"""Per-stage CVE-ID lists and a FUNNEL.md summary of the run.

One file per stage under ``<out>/funnel/``, sorted, one CVE per line. Stage 12
(PF-2, manual path validation) is deliberately absent: this pipeline stops at
PF-1.
"""

from __future__ import annotations

from src.post_cutoff.config import FUNNEL_FILES, Layout, load_ids, log, write_ids

STAGE_NOTES = [
    ("ghsa", "GHSA reviewed + CVE id",
     "Reviewed GHSA advisories in the selected ecosystems published on or after `--since`, carrying a CVE id."),
    ("language", "Target language",
     "GHSA ecosystem maps to the requested language (pip -> Python, maven -> Java)."),
    ("github_fix", "GitHub fix commit",
     "Fix SHA from a GHSA commit reference, else an OSV `FIX` reference, else an NVD reference."),
    ("parent_sha", "Parent (vulnerable) SHA",
     "The GitHub commit API returns a first parent to use as the vulnerable revision."),
    ("after_cutoff", "After cutoff",
     "NVD publish date and fix-commit date both strictly after `--cutoff`. This is `candidates.jsonl`."),
    ("cs1", "CS-1 path-problem CWE",
     "Some NVD CWE has an `@kind path-problem` query under `query_packs/custom-cwe-queries/`."),
    ("removed_lines", "Has removed lines",
     "The fix patch deletes or replaces lines; addition-only fixes are dropped. Local parse, no LLM."),
    ("cs2", "CS-2 vulnerability-path-fixing",
     "At least one changed file is labelled vulnerability-path-fixing (single-file commits auto-keep)."),
    ("pc1", "PC-1 CodeQL database",
     "The vulnerable revision checks out and `codeql database create` succeeds."),
    ("pc2", "PC-2 taint paths",
     "The augmented CodeQL path-problem queries report at least one path."),
    ("pf1", "PF-1 hunk overlap",
     "At least one path touches a vulnerable hunk; the maximum-overlap paths are kept."),
]


def write(layout: Layout, stages: dict[str, set[str]]) -> None:
    layout.funnel.mkdir(parents=True, exist_ok=True)
    for stage, cves in stages.items():
        if stage in FUNNEL_FILES:
            write_ids(layout.funnel_file(stage), cves)


def summary_table(layout: Layout) -> list[tuple[str, str, int | None, str]]:
    rows: list[tuple[str, str, int | None, str]] = []
    for stage, name, note in STAGE_NOTES:
        path = layout.funnel_file(stage)
        count = len(load_ids(path)) if path.is_file() else None
        rows.append((FUNNEL_FILES[stage], name, count, note))
    return rows


def write_markdown(layout: Layout, *, language: str, cutoff: str, since: str) -> None:
    lines = [
        "# Post-cutoff CVE funnel",
        "",
        f"Language: **{language}**. GHSA advisories published on or after **{since}**; "
        f"NVD publish date and fix-commit date both strictly after **{cutoff}**.",
        "",
        "Counts are unique CVE IDs. ID lists are in `funnel/`, one CVE per line.",
        "This pipeline stops at PF-1; PF-2 (manual path validation) is not automated.",
        "",
        "| File | Stage | Remaining | Dropped | Notes |",
        "|---|---|---:|---:|---|",
    ]
    previous: int | None = None
    for filename, name, count, note in summary_table(layout):
        if count is None:
            lines.append(f"| `{filename}` | {name} | *not run* | | {note} |")
            continue
        dropped = "" if previous is None else str(max(previous - count, 0))
        lines.append(f"| `{filename}` | {name} | {count} | {dropped} | {note} |")
        previous = count
    lines.append("")

    path = layout.root / "FUNNEL.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    log(f"[funnel] wrote {path}")


def print_summary(layout: Layout) -> None:
    log("[funnel] stage counts:")
    for filename, name, count, _note in summary_table(layout):
        shown = "not run" if count is None else str(count)
        log(f"  {filename:<28} {name:<32} {shown}")
