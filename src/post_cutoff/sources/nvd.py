"""NVD CVE 2.0 lookup for CWE, CVSS, description, and publish date."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from src.post_cutoff.http_util import cache_load, cache_path, cache_store, http_json

NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


def nvd_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    return headers


def nvd_sleep_s() -> float:
    # Without a key: 5 requests / 30s. With a key: 50 / 30s.
    return 0.7 if os.environ.get("NVD_API_KEY") else 6.0


def fetch_nvd(
    cve_id: str,
    *,
    cache_dir: Path,
    resume: bool,
) -> dict[str, Any] | None:
    cache_file = cache_path(cache_dir, "nvd", cve_id)
    cached = cache_load(cache_file) if resume else None
    if cached is not None:
        return cached if cached.get("_ok", True) else None
    try:
        payload, _ = http_json(
            NVD_CVE.format(cve_id=cve_id),
            headers=nvd_headers(),
            timeout=120,
        )
    except HTTPError as exc:
        if exc.code in {404, 422}:
            cache_store(cache_file, {"_ok": False, "cve_id": cve_id})
            return None
        raise
    except (TimeoutError, URLError) as exc:
        # Do not cache; --resume should retry this CVE.
        sys.stderr.write(f"warning: NVD fetch failed for {cve_id}: {exc}\n")
        return None
    cache_store(cache_file, payload)
    time.sleep(nvd_sleep_s())
    return payload


def _english_description(cve: dict[str, Any]) -> str:
    for item in (cve.get("descriptions") or []):
        if (item.get("lang") or "").lower() == "en":
            return (item.get("value") or "").strip()
    descs = cve.get("descriptions") or []
    if descs:
        return (descs[0].get("value") or "").strip()
    return ""


def _cwes(cve: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = (desc.get("value") or "").strip()
            if value and value not in out:
                out.append(value)
    return out


def _pick_cvss(metrics: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        items = metrics.get(key) or []
        if items:
            primary = next((x for x in items if x.get("type") == "Primary"), items[0])
            return primary.get("cvssData") or {}
    return None


def parse_nvd(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Flatten an NVD 2.0 response into the CVEPath-relevant fields."""
    empty = {
        "description": "",
        "cwes": [],
        "published": None,
        "cvss": "",
        "cvss_parts": {},
        "reference_urls": [],
    }
    if not payload:
        return empty
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return empty
    cve = vulns[0].get("cve") or {}
    cvss_data = _pick_cvss(cve.get("metrics") or {}) or {}
    parts = {
        "AV": cvss_data.get("attackVector") or "",
        "AC": cvss_data.get("attackComplexity") or "",
        "PR": cvss_data.get("privilegesRequired") or "",
        "UI": cvss_data.get("userInteraction") or "",
        "S": cvss_data.get("scope") or "",
        "C": cvss_data.get("confidentialityImpact") or "",
        "I": cvss_data.get("integrityImpact") or "",
        "A": cvss_data.get("availabilityImpact") or "",
    }
    score = cvss_data.get("baseScore")
    refs = [(r.get("url") or "").strip() for r in (cve.get("references") or [])]
    return {
        "description": _english_description(cve),
        "cwes": _cwes(cve),
        "published": cve.get("published"),
        "cvss": "" if score is None else str(score),
        "cvss_parts": parts,
        "reference_urls": [u for u in refs if u],
    }
