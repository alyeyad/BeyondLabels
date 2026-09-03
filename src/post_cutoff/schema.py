"""CVEPath-shaped CVE metadata records and CWE helpers."""

from __future__ import annotations

import functools
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_CWE_RE = re.compile(r"^CWE-0*(\d+)$", re.I)
_CWE_DIR_RE = re.compile(r"^cwe-0*(\d+)$", re.I)
_KIND_PATH_PROBLEM = re.compile(r"@kind\s+path-problem\b", re.I)

# Same packs CS-1 uses: CodeQL CWE queries of kind path-problem, per language.
DEFAULT_QUERY_ROOT = (
    Path(__file__).resolve().parents[2] / "query_packs" / "custom-cwe-queries"
)

# GPT-5.2 knowledge cutoff. Both NVD publish date and fix-commit date
# must be strictly after this day.
DEFAULT_CUTOFF = date(2025, 8, 31)


def normalize_cwe(raw: str) -> str | None:
    """Return ``CWE-22`` (no leading zeros). Drop NVD placeholders."""
    text = (raw or "").strip()
    if not text or text.upper().startswith("NVD-CWE"):
        return None
    match = _CWE_RE.match(text)
    if not match:
        return None
    return f"CWE-{int(match.group(1))}"


def normalize_cwes(values: Iterable[str] | None) -> list[str]:
    seen: list[str] = []
    for raw in values or []:
        cwe = normalize_cwe(str(raw))
        if cwe and cwe not in seen:
            seen.append(cwe)
    return seen


@functools.lru_cache(maxsize=1)
def path_problem_cwes(
    query_root: str | None = None,
) -> dict[str, frozenset[str]]:
    """CWE ids that have at least one ``@kind path-problem`` query per language."""
    root = Path(query_root) if query_root else DEFAULT_QUERY_ROOT
    by_lang: dict[str, set[str]] = {}
    if not root.is_dir():
        return {}
    for lang_dir in sorted(root.iterdir()):
        if not lang_dir.is_dir():
            continue
        found: set[str] = set()
        for cwe_dir in lang_dir.iterdir():
            match = _CWE_DIR_RE.match(cwe_dir.name)
            if not match or not cwe_dir.is_dir():
                continue
            for ql in cwe_dir.glob("*.ql"):
                text = ql.read_text(encoding="utf-8", errors="replace")
                if _KIND_PATH_PROBLEM.search(text):
                    found.add(f"CWE-{int(match.group(1))}")
                    break
        by_lang[lang_dir.name] = found
    return {lang: frozenset(cwes) for lang, cwes in by_lang.items()}


def cwe_in_cvepath(cwes: Iterable[str], language: str | None = None) -> bool:
    """True if any CWE has a path-problem query for ``language`` (Java/Python)."""
    allowed = path_problem_cwes().get(language or "", frozenset())
    return any(cwe in allowed for cwe in cwes)


def parse_iso_date(value: str | None) -> date | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
        return dt.date()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.date()


def format_publish_date_portable(d: date) -> str:
    """``September 7, 2025`` — %-d is POSIX-only, so strip a leading zero."""
    return f"{d.strftime('%B')} {d.day}, {d.year}"


def after_cutoff(value: date | None, cutoff: date = DEFAULT_CUTOFF) -> bool:
    return value is not None and value > cutoff


def folder_slug(cve_id: str, project: str) -> str:
    repo = project.split("/")[-1] if project else "repo"
    repo = re.sub(r"[^A-Za-z0-9._-]+", "_", repo)
    return f"{cve_id}_{repo}"


def build_record(
    *,
    cve_id: str,
    cwe_id: list[str],
    cve_language: str,
    cve_description: str,
    cvss: str,
    publish_date: str,
    cvss_parts: dict[str, str],
    commit_id: str,
    commit_message: str,
    commit_date: str,
    project: str,
    ghsa_id: str | None,
    sources: list[str],
    published_ok: bool,
    commit_after_cutoff: bool,
    parent_sha: str,
    details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    owner, _, repo = project.partition("/")
    html_url = f"https://github.com/{project}/commit/{commit_id}"
    api_url = f"https://api.github.com/repos/{project}/commits/{commit_id}"
    parent_html = f"https://github.com/{project}/commit/{parent_sha}"
    parent_api = f"https://api.github.com/repos/{project}/commits/{parent_sha}"
    record: dict[str, Any] = {
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "cve_language": cve_language,
        "cve_description": cve_description,
        "cvss": cvss,
        "publish_date": publish_date,
        "AV": cvss_parts.get("AV", ""),
        "AC": cvss_parts.get("AC", ""),
        "PR": cvss_parts.get("PR", ""),
        "UI": cvss_parts.get("UI", ""),
        "S": cvss_parts.get("S", ""),
        "C": cvss_parts.get("C", ""),
        "I": cvss_parts.get("I", ""),
        "A": cvss_parts.get("A", ""),
        "commit_id": commit_id,
        "commit_message": commit_message,
        "commit_date": commit_date,
        "project": project,
        "repo_url": f"https://github.com/{project}.git",
        "url": api_url,
        "html_url": html_url,
        "parents": [
            {
                "commit_id_before": parent_sha,
                "url_before": parent_api,
                "html_url_before": parent_html,
            }
        ],
        "ghsa_id": ghsa_id,
        "sources": sources,
        "published_ok": published_ok,
        "commit_after_cutoff": commit_after_cutoff,
        "cwe_in_cvepath": cwe_in_cvepath(cwe_id, cve_language),
        "owner": owner,
        "repo": repo,
        "details": details or [],
    }
    return record
