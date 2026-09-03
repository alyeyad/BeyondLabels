"""PC-1, first half: build a CodeQL database for each checked-out repository.

Python databases are extracted without a build command, which is what the
post-cutoff run used: ``codeql database create --language=python`` indexes the
source tree directly, so no per-project virtualenv or dependency install is
needed. Repositories are processed smallest first (working tree excluding
``.git``) so a run bounded by ``--n`` reaches usable databases quickly.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

from src.post_cutoff.clone import dest_for, slim_record
from src.post_cutoff.config import Layout, log, warn
from src.post_cutoff.schema import folder_slug

CODEQL_LANGUAGE = {"Python": "python", "Java": "java"}
REPORT_FIELDS = ["cve", "language", "status", "message", "repo_path", "db_path"]


def db_looks_complete(db_path: Path) -> bool:
    if not db_path.is_dir():
        return False
    return (db_path / "codeql-database.yml").is_file() or (db_path / "db-python").is_dir()


def repo_size_bytes(source: Path) -> int:
    """Working-tree size excluding ``.git``; CodeQL indexes source, not history."""
    if not source.is_dir():
        return 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for name in filenames:
            try:
                total += (Path(dirpath) / name).stat().st_size
            except OSError:
                pass
    return total


def human_bytes(n: int) -> str:
    value = float(max(n, 0))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024.0 or unit == "TiB":
            return f"{int(value)}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024.0
    return f"{n}B"


def _run_streaming(argv: list[str], log_path: Path, cwd: Path) -> tuple[bool, str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as fh:
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(cwd),
            )
        except OSError as exc:
            return False, f"{type(exc).__name__}: {exc}"
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            fh.write(line)
        proc.stdout.close()
        rc = proc.wait()
    return (rc == 0), ("ok" if rc == 0 else f"exit code {rc}")


def build_one(
    codeql: Path, source: Path, db_path: Path, language: str
) -> tuple[bool, str]:
    ql_lang = CODEQL_LANGUAGE.get(language)
    if ql_lang is None:
        return False, f"unsupported language {language}"
    argv = [
        str(codeql),
        "database",
        "create",
        str(db_path),
        "--source-root",
        str(source),
        f"--language={ql_lang}",
        "--overwrite",
    ]
    ok, detail = _run_streaming(argv, Path(str(db_path) + ".log"), source)
    if not ok and db_path.exists():
        shutil.rmtree(db_path, ignore_errors=True)
    return ok, detail


def build_all(
    layout: Layout,
    records: list[dict],
    *,
    codeql: Path,
    language: str,
    limit: int | None = None,
) -> set[str]:
    """Build databases smallest-first; return the CVEs with a complete database."""
    if not (codeql.is_file() and os.access(codeql, os.X_OK)):
        raise SystemExit(
            f"codeql not executable: {codeql}\n"
            "Run scripts/setup_codeql.py, or set CODEQL_PATH / --codeql."
        )
    slim = [slim_record(rec) for rec in records if rec.get("cve_language") == language]
    layout.dbs.mkdir(parents=True, exist_ok=True)

    pending: list[tuple[int, dict, Path, Path]] = []
    already = 0
    missing_repo = 0
    for rec in slim:
        source = dest_for(layout.repos, rec)
        db_path = layout.dbs / folder_slug(rec["cve_id"], rec["project"])
        if db_looks_complete(db_path):
            already += 1
            continue
        if not (source.is_dir() and (source / ".git").exists()):
            missing_repo += 1
            continue
        pending.append((repo_size_bytes(source), rec, source, db_path))

    pending.sort(key=lambda t: (t[0], t[1]["cve_id"]))
    if limit is not None:
        pending = pending[:limit]

    log(
        f"[pc1] pool={len(slim)} built={already} missing_checkout={missing_repo} "
        f"pending={len(pending)} order=smallest-first codeql={codeql}"
    )

    rows: list[dict] = []
    for i, (nbytes, rec, source, db_path) in enumerate(pending, start=1):
        log(f"[pc1] [{i}/{len(pending)}] {rec['cve_id']} {human_bytes(nbytes)} -> {db_path}")
        try:
            ok, detail = build_one(codeql, source, db_path, language)
        except Exception as exc:  # noqa: BLE001 - one bad repo must not kill the run
            ok, detail = False, f"{type(exc).__name__}: {exc}"
            shutil.rmtree(db_path, ignore_errors=True)
        if not ok:
            warn(f"[pc1] {rec['cve_id']} database create failed: {detail}")
        rows.append(
            {
                "cve": rec["cve_id"],
                "language": language,
                "status": "ok" if ok else "failed",
                "message": detail,
                "repo_path": str(source),
                "db_path": str(db_path),
            }
        )

    built: set[str] = set()
    seen = {r["cve"] for r in rows}
    for rec in slim:
        db_path = layout.dbs / folder_slug(rec["cve_id"], rec["project"])
        if db_looks_complete(db_path):
            built.add(rec["cve_id"])
            if rec["cve_id"] not in seen:
                rows.append(
                    {
                        "cve": rec["cve_id"],
                        "language": language,
                        "status": "skipped_exists",
                        "message": "database already present",
                        "repo_path": str(dest_for(layout.repos, rec)),
                        "db_path": str(db_path),
                    }
                )

    report = layout.dbs / "db_report.csv"
    with report.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    log(f"[pc1] databases present: {len(built)} / {len(slim)}; report {report}")
    return built
