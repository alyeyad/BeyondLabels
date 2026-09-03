"""CS-1 and the removed-line hunk filter.

CS-1 keeps a CVE when at least one of its NVD CWEs has an ``@kind path-problem``
query for that language under ``query_packs/custom-cwe-queries/``; that check
runs during collection and is stored as ``cwe_in_cvepath``.

The hunk filter then drops addition-only fixes: a CVE survives when some changed
file deletes or replaces lines, was deleted outright, or is a modified/renamed
file whose patch GitHub omitted (so addition-only cannot be proven). Surviving
CVEs get their removed hunks written to ``<out>/hunks/<slug>.json``.
"""

from __future__ import annotations

import json

from src.post_cutoff.config import Layout, log
from src.post_cutoff.hunks import extract_removed_hunks, hunk_list_to_output
from src.post_cutoff.schema import folder_slug


def file_keep_kind(detail: dict) -> str:
    """``hunk``, ``removed``, ``unproven``, or ``none``."""
    status = (detail.get("status") or "").lower()
    if status == "removed":
        return "removed"
    patch = detail.get("patch") or ""
    if extract_removed_hunks(patch):
        return "hunk"
    if status in {"modified", "renamed"} and not str(patch).strip():
        return "unproven"
    return "none"


def extract_file_hunks(detail: dict) -> dict | None:
    hunks = extract_removed_hunks(detail.get("patch") or "")
    if not hunks:
        return None
    out = hunk_list_to_output(hunks)
    return {
        "file_name": detail.get("file_name") or "unknown_file",
        "status": detail.get("status") or "",
        "hunks": out["hunks"],
        "summary": out["summary"],
    }


def process_record(record: dict) -> tuple[bool, str, list[dict]]:
    details = [d for d in (record.get("details") or []) if isinstance(d, dict)]
    if not details:
        return True, "no_details_unproven", []

    kinds = [file_keep_kind(d) for d in details]
    extracted = [e for e in (extract_file_hunks(d) for d in details) if e]

    if "hunk" in kinds:
        return True, "removed_hunks", extracted
    if "removed" in kinds:
        return True, "status_removed", extracted
    if "unproven" in kinds:
        return True, "empty_patch_unproven", extracted
    return False, "addition_only", extracted


def cs1_ids(records: list[dict]) -> set[str]:
    """CVEs whose CWE set has a path-problem query pack (CS-1)."""
    return {r["cve_id"] for r in records if r.get("cwe_in_cvepath")}


def hunks_available(layout: Layout, records: list[dict]) -> set[str]:
    """CVEs that already have hunk JSON on disk.

    Derived from the files rather than a funnel list so that a partial or
    ``--cve``-scoped run can still tell which CVEs are eligible downstream.
    """
    return {
        r["cve_id"]
        for r in records
        if (layout.hunks / f"{folder_slug(r['cve_id'], r.get('project') or '')}.json").is_file()
    }


def filter_removed_hunks(layout: Layout, records: list[dict]) -> set[str]:
    """Write hunk JSON for the CS-1 pool; return the CVEs that keep lines."""
    pool = [r for r in records if r.get("cwe_in_cvepath")]
    layout.hunks.mkdir(parents=True, exist_ok=True)

    kept: set[str] = set()
    reasons: dict[str, int] = {}
    for rec in pool:
        cve_id = rec.get("cve_id") or ""
        keep, reason, extracted = process_record(rec)
        reasons[reason] = reasons.get(reason, 0) + 1
        if not keep:
            continue
        kept.add(cve_id)
        slug = folder_slug(cve_id, rec.get("project") or "")
        (layout.hunks / f"{slug}.json").write_text(
            json.dumps(
                {
                    "cve_id": cve_id,
                    "project": rec.get("project"),
                    "cve_language": rec.get("cve_language"),
                    "keep_reason": reason,
                    "files": extracted,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

    log(
        f"[cs1] pool={len(pool)} kept={len(kept)} "
        f"dropped_addition_only={len(pool) - len(kept)} reasons={reasons}"
    )
    return kept
