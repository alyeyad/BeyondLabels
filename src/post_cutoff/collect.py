"""Discovery: GHSA advisories to CVEPath-shaped metadata records.

Reviewed GHSA advisories published on or after ``since`` are mapped to a
language by ecosystem (pip -> Python, maven/gradle -> Java). The fix commit comes from
a GHSA commit reference, else an OSV ``FIX`` reference, else an NVD reference;
the vulnerable revision is that commit's first parent. A record is kept only if
the NVD publish date *and* the fix-commit date are both strictly after
``cutoff``. Every HTTP response is cached under ``<out>/cache/`` so a re-run
with ``resume=True`` costs no API quota.

Writes ``candidates.jsonl``, ``summary.csv``, and ``metadata/<slug>/``.
"""

from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path
from urllib.error import URLError

from src.post_cutoff.config import LANG_ECOSYSTEMS, Layout, log, warn
from src.post_cutoff.schema import (
    after_cutoff,
    build_record,
    folder_slug,
    format_publish_date_portable,
    normalize_cwes,
    parse_iso_date,
)
from src.post_cutoff.sources.ghsa import (
    advisory_ecosystems,
    language_for_ecosystems,
    list_advisories,
)
from src.post_cutoff.sources.github_commits import (
    commit_file_details,
    fetch_commit,
    first_commit_from_urls,
    parent_sha,
)
from src.post_cutoff.sources.nvd import fetch_nvd, parse_nvd
from src.post_cutoff.sources.osv import fetch_osv, fix_urls

SKIP_REASONS = (
    "no_language",
    "no_fix",
    "no_commit",
    "no_parent",
    "before_cutoff",
    "duplicate",
    "nvd_missing",
    "http_error",
)


def advisory_urls(advisory: dict) -> list[str]:
    urls: list[str] = []
    for item in advisory.get("references") or []:
        url = (item if isinstance(item, str) else (item.get("url") or "")).strip()
        if url and url not in urls:
            urls.append(url)
    return urls


def advisory_cwes(advisory: dict) -> list[str]:
    values: list[str] = []
    for item in advisory.get("cwes") or []:
        cid = item.get("cwe_id") if isinstance(item, dict) else str(item)
        if cid:
            values.append(str(cid))
    return values


def resolve_fix(
    *,
    cve_id: str,
    ghsa_id: str | None,
    ghsa_urls: list[str],
    nvd_urls: list[str],
    cache_dir: Path,
    resume: bool,
) -> tuple[tuple[str, str, str] | None, list[str]]:
    """Return ((owner, repo, sha), provenance) for the fix commit."""
    parsed = first_commit_from_urls(ghsa_urls)
    if parsed:
        return parsed, ["ghsa"]

    for vuln_id in (cve_id, ghsa_id):
        if not vuln_id:
            continue
        osv_record = fetch_osv(vuln_id, cache_dir=cache_dir, resume=resume)
        parsed = first_commit_from_urls(fix_urls(osv_record))
        if parsed:
            return parsed, ["osv"]

    parsed = first_commit_from_urls(nvd_urls)
    if parsed:
        return parsed, ["nvd"]
    return None, []


def _collect_one(
    *,
    advisory: dict,
    languages: list[str],
    cutoff: date,
    cache_dir: Path,
    resume: bool,
    seen: set[tuple[str, str]],
    skipped: dict[str, int],
    query_root: Path | None = None,
) -> dict | None:
    cve_id = advisory.get("cve_id")
    ghsa_id = advisory.get("ghsa_id")
    language = language_for_ecosystems(advisory_ecosystems(advisory))
    if language is None or language not in languages:
        skipped["no_language"] += 1
        return None

    ghsa_urls = advisory_urls(advisory)
    nvd_payload = None
    nvd = parse_nvd(None)
    fix, sources = resolve_fix(
        cve_id=cve_id,
        ghsa_id=ghsa_id,
        ghsa_urls=ghsa_urls,
        nvd_urls=[],
        cache_dir=cache_dir,
        resume=resume,
    )
    if not fix:
        nvd_payload = fetch_nvd(cve_id, cache_dir=cache_dir, resume=resume)
        nvd = parse_nvd(nvd_payload)
        fix, sources = resolve_fix(
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            ghsa_urls=ghsa_urls,
            nvd_urls=nvd.get("reference_urls") or [],
            cache_dir=cache_dir,
            resume=resume,
        )
    if not fix:
        skipped["no_fix"] += 1
        return None
    if nvd_payload is None:
        nvd_payload = fetch_nvd(cve_id, cache_dir=cache_dir, resume=resume)
        nvd = parse_nvd(nvd_payload)
    if not nvd_payload:
        skipped["nvd_missing"] += 1

    publish_day = parse_iso_date(nvd.get("published") or advisory.get("published_at"))
    published_ok = after_cutoff(publish_day, cutoff)
    owner, repo, sha = fix
    project = f"{owner}/{repo}"
    key = (cve_id, project.lower())
    if key in seen:
        skipped["duplicate"] += 1
        return None

    commit = fetch_commit(owner, repo, sha, cache_dir=cache_dir, resume=resume)
    if not commit:
        skipped["no_commit"] += 1
        return None
    parent = parent_sha(commit)
    if not parent:
        skipped["no_parent"] += 1
        return None

    commit_meta = commit.get("commit") or {}
    commit_date_raw = (commit_meta.get("committer") or {}).get("date") or (
        commit_meta.get("author") or {}
    ).get("date")
    commit_ok = after_cutoff(parse_iso_date(commit_date_raw), cutoff)
    if not published_ok or not commit_ok or publish_day is None:
        skipped["before_cutoff"] += 1
        return None

    return build_record(
        cve_id=cve_id,
        cwe_id=normalize_cwes(nvd.get("cwes") or advisory_cwes(advisory)),
        cve_language=language,
        cve_description=nvd.get("description") or (advisory.get("summary") or ""),
        cvss=nvd.get("cvss") or "",
        publish_date=format_publish_date_portable(publish_day),
        cvss_parts=nvd.get("cvss_parts") or {},
        commit_id=commit.get("sha") or sha,
        commit_message=commit_meta.get("message") or "",
        commit_date=commit_date_raw,
        project=project,
        ghsa_id=ghsa_id,
        sources=sources + ["github_commit"],
        published_ok=published_ok,
        commit_after_cutoff=commit_ok,
        parent_sha=parent,
        details=commit_file_details(
            commit,
            owner=owner,
            repo=repo,
            parent=parent,
            cache_dir=cache_dir,
            resume=resume,
        ),
        query_root=query_root,
    )


def collect(
    *,
    layout: Layout,
    languages: list[str],
    since: date,
    cutoff: date,
    resume: bool = True,
    limit: int | None = None,
    max_advisories: int | None = None,
    query_root: Path | None = None,
) -> tuple[list[dict], dict[str, set[str]]]:
    """Return (kept records, per-stage CVE-ID sets for funnel steps 01-05)."""
    ecosystems: list[str] = []
    for lang in languages:
        ecosystems.extend(LANG_ECOSYSTEMS.get(lang, []))
    if not ecosystems:
        raise SystemExit(f"No GHSA ecosystems for languages {languages}")

    layout.cache.mkdir(parents=True, exist_ok=True)
    log(
        f"[collect] GHSA ecosystems={ecosystems} published>={since} "
        f"cutoff={cutoff} resume={resume}"
    )
    advisories = list_advisories(
        since=since,
        ecosystems=ecosystems,
        cache_dir=layout.cache,
        resume=resume,
        max_advisories=max_advisories,
    )
    log(f"[collect] {len(advisories)} reviewed GHSA advisories with a CVE id")

    kept: list[dict] = []
    seen: set[tuple[str, str]] = set()
    skipped = {reason: 0 for reason in SKIP_REASONS}
    stages: dict[str, set[str]] = {
        "ghsa": set(),
        "language": set(),
        "github_fix": set(),
        "parent_sha": set(),
        "after_cutoff": set(),
    }

    for i, advisory in enumerate(advisories, start=1):
        cve_id = advisory.get("cve_id")
        if cve_id:
            stages["ghsa"].add(cve_id)
        if limit is not None and len(kept) >= limit:
            break
        before = dict(skipped)
        try:
            record = _collect_one(
                advisory=advisory,
                languages=languages,
                cutoff=cutoff,
                cache_dir=layout.cache,
                resume=resume,
                seen=seen,
                skipped=skipped,
                query_root=query_root,
            )
        except (TimeoutError, URLError, OSError) as exc:
            skipped["http_error"] += 1
            warn(f"[collect] skip {cve_id}: {type(exc).__name__}: {exc}")
            continue

        # Funnel bookkeeping: which gate this advisory reached.
        if cve_id and skipped["no_language"] == before["no_language"]:
            stages["language"].add(cve_id)
            if skipped["no_fix"] == before["no_fix"]:
                stages["github_fix"].add(cve_id)
                if (
                    skipped["no_commit"] == before["no_commit"]
                    and skipped["no_parent"] == before["no_parent"]
                ):
                    stages["parent_sha"].add(cve_id)

        if record is None:
            continue
        seen.add((record["cve_id"], record["project"].lower()))
        stages["after_cutoff"].add(record["cve_id"])
        kept.append(record)
        flag = "yes" if record.get("cwe_in_cvepath") else "no"
        log(
            f"[collect] [{len(kept)}] {record['cve_id']} {record['project']} "
            f"{record['cve_language']} cs1={flag} ({i}/{len(advisories)} scanned)"
        )

    n_cs1 = sum(1 for r in kept if r.get("cwe_in_cvepath"))
    log(f"[collect] skipped: {skipped}")
    log(f"[collect] kept {len(kept)} CVE/repo pairs ({n_cs1} with a path-problem CWE)")
    return kept, stages


def write_outputs(layout: Layout, records: list[dict]) -> None:
    layout.root.mkdir(parents=True, exist_ok=True)
    with layout.candidates.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    ranked = sorted(
        records, key=lambda r: (not r.get("cwe_in_cvepath"), r.get("cve_id") or "")
    )
    fieldnames = [
        "cve_id", "ghsa_id", "cwe_id", "cve_language", "project", "repo_url",
        "publish_date", "commit_date", "commit_id", "parent_sha",
        "cwe_in_cvepath", "sources",
    ]
    with layout.summary.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for rec in ranked:
            parents = rec.get("parents") or [{}]
            writer.writerow({
                "cve_id": rec.get("cve_id"),
                "ghsa_id": rec.get("ghsa_id"),
                "cwe_id": ";".join(rec.get("cwe_id") or []),
                "cve_language": rec.get("cve_language"),
                "project": rec.get("project"),
                "repo_url": rec.get("repo_url"),
                "publish_date": rec.get("publish_date"),
                "commit_date": rec.get("commit_date"),
                "commit_id": rec.get("commit_id"),
                "parent_sha": parents[0].get("commit_id_before"),
                "cwe_in_cvepath": rec.get("cwe_in_cvepath"),
                "sources": ";".join(rec.get("sources") or []),
            })

    for rec in ranked:
        dest = layout.metadata / folder_slug(rec["cve_id"], rec["project"])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "cve_metadata.json").write_text(
            json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    log(
        f"[collect] wrote {len(records)} records to {layout.candidates}, "
        f"summary {layout.summary}, metadata under {layout.metadata}"
    )


def load_records(candidates: Path, pool: set[str] | None = None) -> list[dict]:
    """Read ``candidates.jsonl``, optionally restricted to a CVE-ID pool."""
    records: list[dict] = []
    seen: set[str] = set()
    if not candidates.is_file():
        raise SystemExit(f"missing {candidates}; run the collect stage first")
    with candidates.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            cve = rec.get("cve_id")
            if cve in seen or (pool is not None and cve not in pool):
                continue
            seen.add(cve)
            records.append(rec)
    return records
