"""Parse GitHub commit URLs and resolve parent (vulnerable) SHAs."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError
from urllib.parse import quote

from src.post_cutoff.http_util import cache_load, cache_path, cache_store, http_json, http_text
from src.post_cutoff.sources.ghsa import github_headers

COMMIT_RE = re.compile(
    r"https?://(?:www\.)?github\.com/"
    r"(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
    r"(?:commit|commits)/(?P<sha>[0-9a-fA-F]{7,40})"
    r"(?:[/?#].*)?$",
    re.I,
)


def parse_commit_url(url: str) -> tuple[str, str, str] | None:
    """Return (owner, repo, sha) if ``url`` is a GitHub commit link."""
    match = COMMIT_RE.match((url or "").strip().rstrip("/"))
    if not match:
        return None
    repo = match.group("repo")
    if repo.endswith(".git"):
        repo = repo[:-4]
    return match.group("owner"), repo, match.group("sha")


def first_commit_from_urls(urls: Iterable[str]) -> tuple[str, str, str] | None:
    for url in urls:
        parsed = parse_commit_url(url)
        if parsed:
            return parsed
    return None


def fetch_commit(
    owner: str,
    repo: str,
    sha: str,
    *,
    cache_dir: Path,
    resume: bool,
    sleep_s: float = 0.25,
) -> dict[str, Any] | None:
    key = f"{owner}_{repo}_{sha}"
    cache_file = cache_path(cache_dir, "commits", key)
    cached = cache_load(cache_file) if resume else None
    if cached is not None:
        return cached if cached.get("_ok", True) else None
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        payload, _ = http_json(url, headers=github_headers())
    except HTTPError as exc:
        if exc.code in {404, 422}:
            cache_store(cache_file, {"_ok": False, "url": url})
            return None
        raise
    cache_store(cache_file, payload)
    time.sleep(sleep_s)
    return payload


def parent_sha(commit: dict[str, Any] | None) -> str | None:
    if not commit:
        return None
    parents = commit.get("parents") or []
    if not parents:
        return None
    sha = (parents[0].get("sha") or "").strip()
    return sha or None


_LANG_EXT = {
    ".java": "java",
    ".jsp": "java",
    ".py": "py",
}


def _file_language(filename: str) -> str:
    name = filename.lower()
    for ext, lang in _LANG_EXT.items():
        if name.endswith(ext):
            return lang
    return ""


def fetch_raw_file(
    owner: str,
    repo: str,
    sha: str,
    path: str,
    *,
    cache_dir: Path,
    resume: bool,
    sleep_s: float = 0.15,
) -> str:
    """File text at ``sha``, or empty string if missing/binary/too large."""
    key = f"{owner}_{repo}_{sha}_{path}"
    cache_file = cache_path(cache_dir, "blobs", key)
    cached = cache_load(cache_file) if resume else None
    if cached is not None:
        return cached.get("text") or ""
    encoded = quote(path, safe="/")
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{encoded}"
    # Do not send GitHub API Accept/Authorization headers; they break raw.githubusercontent.com.
    text = http_text(url)
    cache_store(cache_file, {"url": url, "text": text or ""})
    time.sleep(sleep_s)
    return text or ""


def commit_file_details(
    commit: dict[str, Any],
    *,
    owner: str,
    repo: str,
    parent: str,
    cache_dir: Path,
    resume: bool,
) -> list[dict[str, Any]]:
    """ReposVul-like ``details`` entries from the GitHub commit files list.

    GitHub already returns ``filename``, ``patch``, and ``raw_url``. Full
    ``code`` / ``code_before`` are fetched from raw.githubusercontent.com at
    the fix SHA and parent SHA. ReposVul-only fields (llm_check, semgrep,
    internal ``file_path``) are omitted.
    """
    details: list[dict[str, Any]] = []
    for file_info in commit.get("files") or []:
        filename = file_info.get("filename") or ""
        if not filename:
            continue
        status = (file_info.get("status") or "").lower()
        previous = file_info.get("previous_filename") or filename
        code = ""
        code_before = ""
        if status != "removed":
            code = fetch_raw_file(
                owner, repo, commit.get("sha") or "", filename,
                cache_dir=cache_dir, resume=resume,
            )
        if status != "added":
            code_before = fetch_raw_file(
                owner, repo, parent, previous,
                cache_dir=cache_dir, resume=resume,
            )
        entry: dict[str, Any] = {
            "raw_url": file_info.get("raw_url") or (
                f"https://github.com/{owner}/{repo}/raw/"
                f"{commit.get('sha')}/{filename}"
            ),
            "code": code,
            "code_before": code_before,
            "patch": file_info.get("patch") or "",
            "file_name": filename,
            "file_language": _file_language(filename),
            "status": status,
        }
        if file_info.get("previous_filename"):
            entry["previous_filename"] = file_info["previous_filename"]
        details.append(entry)
    return details
