#!/usr/bin/env python3
"""Clone each CVEPath repo at the vulnerable (pre-fix) commit.

Reads ``data/CVEPath/{Java,Python}/<CVE>_<repo>/annotations/cve_metadata.json``.
Writes ``output/original_repos/{Java,Python}/<CVE>_<repo>/``, which is the
default ``--distractor-repos-dir`` for E3 / RQ4 positive runs.

Vulnerable commit, in order:
  1. parents[0].commit_id_before
  2. windows_before[0].commit_id
  3. parent of commit_id (``sha^``)

Resumable: skips a dest already at the target HEAD. Optional ``GITHUB_TOKEN``
raises GitHub rate limits. Does not change git config.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.dataset import list_all_cve_folders  # noqa: E402

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DEFAULT_CVEPATH = PROJECT_ROOT / "data" / "CVEPath"
DEFAULT_OUT = PROJECT_ROOT / "output" / "original_repos"


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    token = (env.get("GITHUB_TOKEN") or env.get("GH_TOKEN") or "").strip()
    if token:
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = "http.extraHeader"
        env["GIT_CONFIG_VALUE_0"] = f"Authorization: Bearer {token}"
    return env


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git", "-C", str(repo), "-c", f"safe.directory={repo}", *args]
    return subprocess.run(
        cmd,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_git_env(),
    )


def _rmtree(path: Path) -> None:
    def _onerror(func, p, _exc_info):
        try:
            os.chmod(p, stat.S_IWUSR | stat.S_IREAD | stat.S_IEXEC)
            func(p)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_onerror)


def _load_metadata(cve_dir: Path) -> dict:
    path = cve_dir / "annotations" / "cve_metadata.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("metadata", data) if isinstance(data, dict) else {}


def _repo_url(md: dict) -> str | None:
    project = (md.get("project") or "").strip()
    if "/" in project:
        return f"https://github.com/{project}.git"
    for key in ("html_url", "url", "html_url_before"):
        val = md.get(key) or ""
        m = re.match(r"https?://(?:api\.)?github\.com/([^/]+/[^/]+)", val)
        if m:
            return f"https://github.com/{m.group(1)}.git"
    parents = md.get("parents") or []
    if parents and isinstance(parents[0], dict):
        val = parents[0].get("html_url_before") or ""
        m = re.match(r"https?://(?:api\.)?github\.com/([^/]+/[^/]+)", val)
        if m:
            return f"https://github.com/{m.group(1)}.git"
    return None


def _first_sha(value) -> str | None:
    if not value:
        return None
    text = str(value).strip().split(";")[0].strip()
    return text if text else None


def _resolve_vulnerable_commit(md: dict) -> tuple[str | None, str]:
    parents = md.get("parents") or []
    if parents and isinstance(parents[0], dict):
        sha = _first_sha(parents[0].get("commit_id_before"))
        if sha:
            return sha, "commit_id_before"
    wb = md.get("windows_before")
    if isinstance(wb, list) and wb:
        sha = _first_sha(wb[0].get("commit_id"))
        if sha:
            return sha, "windows_before"
    fix = _first_sha(md.get("commit_id"))
    if fix:
        return f"{fix}^", "parent_of_fix"
    return None, "missing"


def _head(repo: Path) -> str | None:
    try:
        return _git(repo, "rev-parse", "HEAD").stdout.strip()
    except subprocess.CalledProcessError:
        return None


def _rev_parse(repo: Path, ref: str) -> str | None:
    try:
        return _git(repo, "rev-parse", ref).stdout.strip()
    except subprocess.CalledProcessError:
        return None


def _matches(head: str | None, wanted: str) -> bool:
    if not head or not wanted:
        return False
    return head == wanted or head.startswith(wanted) or wanted.startswith(head)


def _fetch_sha(repo: Path, url: str, sha: str) -> None:
    _git(repo, "fetch", "--depth", "1", url, sha)


def _clone_checkout(url: str, dest: Path, vuln_ref: str) -> None:
    tmp = dest.with_name(dest.name + ".__clone_tmp__")
    _rmtree(tmp)
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={tmp}",
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            url,
            str(tmp),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_git_env(),
    )
    concrete = vuln_ref[:-1] if vuln_ref.endswith("^") else vuln_ref
    try:
        depth = "2" if vuln_ref.endswith("^") else "1"
        _git(tmp, "fetch", "--depth", depth, "origin", concrete)
        checkout = f"{concrete}^" if vuln_ref.endswith("^") else concrete
        _git(tmp, "checkout", "--detach", checkout)
    except subprocess.CalledProcessError:
        if not SHA_RE.match(concrete):
            raise
        _rmtree(tmp)
        tmp.mkdir(parents=True)
        _git(tmp, "init", "-q")
        _git(tmp, "remote", "add", "origin", url)
        _fetch_sha(tmp, url, concrete)
        checkout = "FETCH_HEAD^" if vuln_ref.endswith("^") else "FETCH_HEAD"
        _git(tmp, "checkout", "-q", "--detach", checkout)

    head = _head(tmp)
    resolved = _rev_parse(tmp, "HEAD")
    if not head:
        _rmtree(tmp)
        raise RuntimeError(f"empty HEAD after checkout of {vuln_ref}")
    if dest.exists():
        _rmtree(dest)
    tmp.rename(dest)


def clone_one(lang: str, slug: str, cvepath: Path, out_root: Path, dry_run: bool) -> dict:
    cve_dir = cvepath / lang / slug
    dest = out_root / lang / slug
    md = _load_metadata(cve_dir)
    vuln_ref, source = _resolve_vulnerable_commit(md)
    repo_url = _repo_url(md)
    rec = {
        "cve": slug,
        "language": lang,
        "repo_url": repo_url,
        "vulnerable_ref": vuln_ref,
        "vulnerable_source": source,
        "dest": str(dest),
    }
    if not repo_url or not vuln_ref:
        rec["status"] = "skip"
        rec["reason"] = "missing url or vulnerable commit"
        return rec
    if dry_run:
        rec["status"] = "dry"
        return rec

    if (dest / ".git").is_dir():
        resolved = _rev_parse(dest, vuln_ref)
        if resolved and _matches(_head(dest), resolved):
            rec["status"] = "ok"
            rec["reason"] = "already at vulnerable commit"
            rec["head"] = resolved
            return rec
        try:
            _git(dest, "checkout", "--detach", vuln_ref)
            resolved = _rev_parse(dest, "HEAD")
            if resolved and _matches(_head(dest), resolved):
                rec["status"] = "ok"
                rec["reason"] = "re-checked out in place"
                rec["head"] = resolved
                return rec
        except subprocess.CalledProcessError:
            pass

    try:
        _clone_checkout(repo_url, dest, vuln_ref)
    except (subprocess.CalledProcessError, RuntimeError, OSError) as exc:
        err = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        rec["status"] = "fail"
        rec["error"] = (err or str(exc))[:500]
        return rec

    rec["status"] = "ok"
    rec["head"] = _head(dest)
    return rec


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cvepath", type=Path, default=DEFAULT_CVEPATH)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--language", choices=["Java", "Python", "all"], default="all")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    languages = ["Java", "Python"] if args.language == "all" else [args.language]
    folders = [
        (slug, lang)
        for slug, lang in list_all_cve_folders(args.cvepath)
        if lang in languages
    ]
    if args.limit:
        folders = folders[: args.limit]

    args.out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for i, (slug, lang) in enumerate(folders, 1):
        rec = clone_one(lang, slug, args.cvepath, args.out, args.dry_run)
        manifest.append(rec)
        extra = rec.get("reason") or rec.get("error") or rec.get("repo_url") or ""
        print(f"[{rec['status']}] {i}/{len(folders)} {lang}/{slug}  {extra}", flush=True)

    manifest_path = args.out / "_clone_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    ok = sum(1 for r in manifest if r["status"] in {"ok", "dry"})
    fail = sum(1 for r in manifest if r["status"] == "fail")
    skip = sum(1 for r in manifest if r["status"] == "skip")
    print(f"\nok={ok} fail={fail} skip={skip} dest={args.out} manifest={manifest_path}")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
