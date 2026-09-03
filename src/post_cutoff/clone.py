"""Clone each CS-2 repository and check out the vulnerable (parent) commit.

Blobless clones with ``--no-checkout``, then an explicit fetch of the parent SHA.
Network failures against GitHub are frequently transient (reset streams, early
EOF), so clone and fetch retry with exponential backoff. A destination already
detached at the target SHA is left alone, which makes the stage resumable.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

from src.post_cutoff.config import Layout, github_token, log
from src.post_cutoff.schema import folder_slug

_PROJECT_LOCKS: dict[str, Lock] = defaultdict(Lock)

TRANSIENT_MARKERS = (
    "HTTP/2 stream",
    "early EOF",
    "RPC failed",
    "Connection reset",
    "GnuTLS",
    "index-pack",
    "unexpected disconnect",
    "Recv failure",
    "Failed to connect",
    "transfer closed",
    "The remote end hung up",
    "HTTP 429",
    "SSL_ERROR",
    "timed out",
)

REPORT_FIELDS = [
    "cve", "language", "project", "commit", "status", "message", "repo_path", "head_sha",
]


def slim_record(rec: dict) -> dict:
    parents = rec.get("parents") or []
    parent = ""
    if parents and isinstance(parents[0], dict):
        parent = str(parents[0].get("commit_id_before") or "").strip()
    project = rec.get("project") or ""
    return {
        "cve_id": rec.get("cve_id") or "",
        "project": project,
        "cve_language": rec.get("cve_language") or "",
        "repo_url": rec.get("repo_url")
        or (f"https://github.com/{project}.git" if project else ""),
        "parent_sha": parent,
    }


def dest_for(repos_root: Path, rec: dict) -> Path:
    return repos_root / (rec.get("cve_language") or "unknown") / folder_slug(
        rec["cve_id"], rec.get("project") or ""
    )


def _scrub(text: str, token: str) -> str:
    return text.replace(token, "***") if token else text


def _run_git(
    args: list[str], *, cwd: Path | None = None, token: str = "", network: bool = False
) -> tuple[bool, str]:
    cmd = ["git"]
    if cwd is not None:
        cmd.extend(["-c", f"safe.directory={cwd}"])
    if network:
        cmd.extend(["-c", "credential.helper=", "-c", "http.version=HTTP/1.1"])
        if token:
            cmd.extend(["-c", f"http.extraHeader=Authorization: Bearer {token}"])
    cmd.extend(args)
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            cmd, cwd=cwd, text=True, capture_output=True, check=True, env=env
        )
        return True, _scrub(f"{result.stdout}\n{result.stderr}".strip(), token)
    except subprocess.CalledProcessError as exc:
        return False, _scrub(f"{exc.stdout}\n{exc.stderr}".strip(), token)


def _transient(msg: str) -> bool:
    lower = (msg or "").lower()
    if "repository not found" in lower:
        return False
    return any(marker.lower() in lower for marker in TRANSIENT_MARKERS)


def _run_git_retry(
    args: list[str],
    *,
    cwd: Path | None = None,
    token: str = "",
    network: bool = False,
    attempts: int = 5,
    label: str = "",
) -> tuple[bool, str]:
    last = ""
    for i in range(max(1, attempts)):
        ok, msg = _run_git(args, cwd=cwd, token=token, network=network)
        if ok:
            return True, msg
        last = msg
        if not _transient(msg) or i + 1 >= max(1, attempts):
            return False, last
        delay = min(2**i, 32)
        log(f"[clone] retry {i + 1}/{attempts} {label} in {delay}s")
        time.sleep(delay)
    return False, last


def _head(dest: Path, token: str) -> str:
    ok, out = _run_git(["rev-parse", "HEAD"], cwd=dest, token=token)
    if not ok:
        return ""
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _sha_equal(left: str, right: str) -> bool:
    a, b = left.strip().lower(), right.strip().lower()
    if not a or not b:
        return False
    n = min(len(a), len(b), 40)
    return n >= 7 and a[:n] == b[:n]


def is_ready(dest: Path, parent_sha: str, token: str = "") -> bool:
    return (
        dest.is_dir()
        and (dest / ".git").exists()
        and _sha_equal(_head(dest, token), parent_sha)
    )


def _fetch_commit(dest: Path, commit: str, token: str, attempts: int) -> tuple[bool, str]:
    ok, msg = _run_git_retry(
        ["fetch", "--tags", "--force", "origin", commit],
        cwd=dest, token=token, network=True, attempts=attempts, label=f"fetch {dest.name}",
    )
    if ok:
        return ok, msg
    _run_git_retry(
        ["fetch", "--all", "--tags", "--prune"],
        cwd=dest, token=token, network=True, attempts=max(1, attempts - 2),
        label=f"fetch-all {dest.name}",
    )
    return _run_git_retry(
        ["fetch", "--force", "origin", commit],
        cwd=dest, token=token, network=True, attempts=attempts, label=f"fetch {dest.name}",
    )


def _clone(url: str, dest: Path, token: str, attempts: int, cve: str) -> tuple[bool, str]:
    last = ""
    for i in range(max(1, attempts)):
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        ok, msg = _run_git(
            ["clone", "--filter=blob:none", "--no-checkout", url, str(dest)],
            token=token,
            network=True,
        )
        if ok:
            return True, msg
        last = msg
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        if not _transient(msg) or i + 1 >= max(1, attempts):
            return False, last
        delay = min(2**i, 32)
        log(f"[clone] retry {i + 1}/{attempts} clone {cve} in {delay}s")
        time.sleep(delay)
    return False, last


def _clone_checkout(rec: dict, dest: Path, *, token: str, attempts: int) -> dict:
    url, commit, cve = rec["repo_url"], rec["parent_sha"], rec["cve_id"]
    row = {
        "cve": cve,
        "language": rec["cve_language"],
        "project": rec["project"],
        "commit": commit,
        "status": "failed",
        "message": "",
        "repo_path": str(dest),
        "head_sha": "",
    }

    if dest.exists() and (dest / ".git").exists():
        head = _head(dest, token)
        if _sha_equal(head, commit):
            row.update(status="skipped_exists", message=f"already at {head[:12]}", head_sha=head)
            return row
        ok, msg = _fetch_commit(dest, commit, token, attempts)
        if ok:
            ok, msg = _run_git(["checkout", "--detach", commit], cwd=dest, token=token)
        if ok:
            head = _head(dest, token)
            if _sha_equal(head, commit):
                row.update(status="ok", message=f"reused clone @ {head[:12]}", head_sha=head)
                return row
        log(f"[clone] reclone {cve}; existing checkout unusable")
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    dest.parent.mkdir(parents=True, exist_ok=True)
    ok, msg = _clone(url, dest, token, attempts, cve)
    if not ok:
        row["message"] = f"git clone failed: {msg}"
        shutil.rmtree(dest, ignore_errors=True)
        return row

    ok, msg = _fetch_commit(dest, commit, token, attempts)
    if not ok:
        row["message"] = f"fetch {commit} failed: {msg}"
        return row

    ok, msg = _run_git(["checkout", "--detach", commit], cwd=dest, token=token)
    if not ok:
        row["message"] = f"checkout {commit} failed: {msg}"
        return row

    head = _head(dest, token)
    if not _sha_equal(head, commit):
        row.update(message=f"HEAD {head} != {commit}", head_sha=head)
        return row

    row.update(status="ok", message=f"ready @ {head[:12]}", head_sha=head)
    return row


def clone_all(
    layout: Layout,
    records: list[dict],
    *,
    workers: int = 4,
    retries: int = 5,
    limit: int | None = None,
) -> set[str]:
    """Check out every record at its parent SHA; return the CVEs that are ready."""
    token = github_token()
    slim = [slim_record(rec) for rec in records]
    layout.repos.mkdir(parents=True, exist_ok=True)

    work: list[dict] = []
    already = 0
    for rec in slim:
        if not (rec["cve_id"] and rec["project"] and rec["parent_sha"] and rec["repo_url"]):
            continue
        if is_ready(dest_for(layout.repos, rec), rec["parent_sha"], token):
            already += 1
            continue
        work.append(rec)
    if limit is not None:
        work = work[:limit]

    log(
        f"[clone] pool={len(slim)} ready={already} pending={len(work)} "
        f"auth={'yes' if token else 'no'} workers={max(1, workers)}"
    )

    rows: list[dict] = []

    def _job(rec: dict) -> dict:
        with _PROJECT_LOCKS[rec["project"].lower()]:
            return _clone_checkout(
                rec, dest_for(layout.repos, rec), token=token, attempts=max(1, retries)
            )

    if work:
        n, done = len(work), 0
        if max(1, workers) == 1:
            for rec in work:
                row = _job(rec)
                rows.append(row)
                done += 1
                log(f"[clone] [{done}/{n}] {row['cve']} {row['status']} {row['message']}")
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool_ex:
                futures = [pool_ex.submit(_job, rec) for rec in work]
                for fut in as_completed(futures):
                    row = fut.result()
                    rows.append(row)
                    done += 1
                    log(f"[clone] [{done}/{n}] {row['cve']} {row['status']} {row['message']}")

    ready: set[str] = set()
    seen = {r["cve"] for r in rows}
    for rec in slim:
        dest = dest_for(layout.repos, rec)
        if is_ready(dest, rec["parent_sha"], token):
            ready.add(rec["cve_id"])
            if rec["cve_id"] not in seen:
                rows.append(
                    {
                        "cve": rec["cve_id"],
                        "language": rec["cve_language"],
                        "project": rec["project"],
                        "commit": rec["parent_sha"],
                        "status": "skipped_exists",
                        "message": "already at parent SHA",
                        "repo_path": str(dest),
                        "head_sha": rec["parent_sha"],
                    }
                )

    report = layout.repos / "clone_report.csv"
    with report.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    log(f"[clone] checked out at parent SHA: {len(ready)} / {len(slim)}; report {report}")
    return ready
