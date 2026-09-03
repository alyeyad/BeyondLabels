"""OSV.dev lookup for FIX git commit URLs."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

from src.post_cutoff.http_util import cache_load, cache_path, cache_store, http_json

OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"


def fetch_osv(
    vuln_id: str,
    *,
    cache_dir: Path,
    resume: bool,
    sleep_s: float = 0.2,
) -> dict[str, Any] | None:
    cache_file = cache_path(cache_dir, "osv", vuln_id)
    cached = cache_load(cache_file) if resume else None
    if cached is not None:
        return cached if cached.get("_ok", True) else None
    try:
        payload, _ = http_json(OSV_VULN.format(id=vuln_id))
    except HTTPError as exc:
        if exc.code == 404:
            cache_store(cache_file, {"_ok": False, "id": vuln_id})
            return None
        raise
    cache_store(cache_file, payload)
    time.sleep(sleep_s)
    return payload


def fix_urls(osv_record: dict[str, Any] | None) -> list[str]:
    if not osv_record:
        return []
    urls: list[str] = []
    for ref in osv_record.get("references") or []:
        url = (ref.get("url") or "").strip()
        ref_type = (ref.get("type") or "").upper()
        if url and (ref_type == "FIX" or "/commit/" in url):
            if url not in urls:
                urls.append(url)
    return urls
