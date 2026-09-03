"""JSON file cache and HTTP GET/POST with retries."""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SAFE_KEY = re.compile(r"[^A-Za-z0-9._-]+")


def cache_path(cache_dir: Path, namespace: str, key: str) -> Path:
    safe = SAFE_KEY.sub("_", key)[:180]
    return cache_dir / namespace / f"{safe}.json"


def cache_load(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def cache_store(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _read_json(resp) -> Any:
    raw = resp.read().decode("utf-8")
    return json.loads(raw) if raw else None


def http_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 60,
    retries: int = 4,
) -> tuple[Any, dict[str, str]]:
    """Return (json, response headers). Raises HTTPError on 4xx after retries skip 404."""
    hdrs = {"Accept": "application/json", "User-Agent": "beyondlabels-post-cutoff-cves"}
    if headers:
        hdrs.update(headers)
    last_err: Exception | None = None
    for attempt in range(retries):
        req = Request(url, data=body, headers=hdrs, method=method)
        try:
            with urlopen(req, timeout=timeout) as resp:
                payload = _read_json(resp)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return payload, resp_headers
        except HTTPError as exc:
            if exc.code == 401 and "Authorization" in hdrs:
                sys.stderr.write(
                    "warning: GitHub token rejected (401); retrying unauthenticated\n"
                )
                hdrs = {k: v for k, v in hdrs.items() if k != "Authorization"}
                last_err = exc
                continue
            if exc.code in {404, 422}:
                raise
            if exc.code == 403 or exc.code == 429 or exc.code >= 500:
                last_err = exc
                time.sleep(min(2 ** attempt, 30))
                continue
            raise
        except URLError as exc:
            last_err = exc
            time.sleep(min(2 ** attempt, 30))
        except TimeoutError as exc:
            last_err = exc
            sys.stderr.write(
                f"warning: timeout {url} (attempt {attempt + 1}/{retries})\n"
            )
            time.sleep(min(2 ** attempt, 30))
    if last_err:
        raise last_err
    raise RuntimeError(f"request failed: {url}")


def http_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 60,
    retries: int = 4,
    max_bytes: int = 2_000_000,
) -> str | None:
    """Return decoded text, or None on 404. Raises on other errors after retries."""
    hdrs = {"User-Agent": "beyondlabels-post-cutoff-cves"}
    if headers:
        hdrs.update(headers)
    last_err: Exception | None = None
    for attempt in range(retries):
        req = Request(url, headers=hdrs, method="GET")
        try:
            with urlopen(req, timeout=timeout) as resp:
                raw = resp.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    return None
                if b"\x00" in raw:
                    return None
                return raw.decode("utf-8", errors="replace")
        except HTTPError as exc:
            if exc.code == 401 and "Authorization" in hdrs:
                hdrs = {k: v for k, v in hdrs.items() if k != "Authorization"}
                last_err = exc
                continue
            if exc.code in {404, 422}:
                return None
            if exc.code == 403 or exc.code == 429 or exc.code >= 500:
                last_err = exc
                time.sleep(min(2 ** attempt, 30))
                continue
            raise
        except URLError as exc:
            last_err = exc
            time.sleep(min(2 ** attempt, 30))
        except TimeoutError as exc:
            last_err = exc
            sys.stderr.write(
                f"warning: timeout {url} (attempt {attempt + 1}/{retries})\n"
            )
            time.sleep(min(2 ** attempt, 30))
    if last_err:
        raise last_err
    return None

