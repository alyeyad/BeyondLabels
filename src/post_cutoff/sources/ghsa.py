"""GitHub Global Advisory Database (GHSA) discovery."""

from __future__ import annotations

import os
import time
from datetime import date
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlencode

from src.post_cutoff.http_util import cache_load, cache_path, cache_store, http_json

GITHUB_API = "https://api.github.com"
ECOSYSTEM_LANGUAGE = {
    "maven": "Java",
    "gradle": "Java",
    "pip": "Python",
    "pypi": "Python",
}


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def language_for_ecosystems(ecosystems: Iterable[str]) -> str | None:
    langs = {ECOSYSTEM_LANGUAGE[e] for e in ecosystems if e in ECOSYSTEM_LANGUAGE}
    if len(langs) == 1:
        return langs.pop()
    if langs == {"Java"} or langs == {"Python"}:
        return langs.pop()
    return None


def advisory_ecosystems(advisory: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    for vuln in advisory.get("vulnerabilities") or []:
        eco = ((vuln.get("package") or {}).get("ecosystem") or "").strip().lower()
        if eco and eco not in seen:
            seen.append(eco)
    return seen


def _parse_link_next(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        if 'rel="next"' in part:
            start = part.find("<")
            end = part.find(">")
            if start != -1 and end != -1:
                return part[start + 1:end]
    return None


def list_advisories(
    *,
    since: date,
    ecosystems: list[str],
    cache_dir: Path,
    resume: bool,
    max_advisories: int | None,
    sleep_s: float = 0.25,
) -> list[dict[str, Any]]:
    """Paginate reviewed GHSA advisories published on/after ``since``."""
    collected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    until = date.today().isoformat()
    published = f"{since.isoformat()}..{until}"

    for ecosystem in ecosystems:
        page = 1
        query = {
            "type": "reviewed",
            "ecosystem": ecosystem,
            "published": published,
            "per_page": "100",
        }
        url = f"{GITHUB_API}/advisories?{urlencode(query)}"
        while url:
            if max_advisories is not None and len(collected) >= max_advisories:
                return collected[:max_advisories]
            cache_file = cache_path(cache_dir, "ghsa", f"{ecosystem}_p{page}_{published}")
            payload = cache_load(cache_file) if resume else None
            headers_out: dict[str, str] = {}
            if payload is None:
                payload, headers_out = http_json(url, headers=github_headers())
                cache_store(cache_file, {"url": url, "body": payload, "headers": headers_out})
                time.sleep(sleep_s)
            else:
                headers_out = payload.get("headers") or {}
                payload = payload.get("body", payload)

            if not isinstance(payload, list):
                break
            for item in payload:
                ghsa_id = item.get("ghsa_id")
                if not ghsa_id or ghsa_id in seen_ids:
                    continue
                if not item.get("cve_id"):
                    continue
                ecos = advisory_ecosystems(item)
                if ecosystem not in ecos and ecos:
                    # keep if GitHub's ecosystem filter already applied
                    pass
                seen_ids.add(ghsa_id)
                collected.append(item)
                if max_advisories is not None and len(collected) >= max_advisories:
                    return collected[:max_advisories]
            url = _parse_link_next(headers_out.get("link"))
            page += 1
    return collected
