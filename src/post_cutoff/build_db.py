"""PC-1, first half: build a CodeQL database for each checked-out repository.

Python databases are extracted without a build command, which is what the
post-cutoff run used: ``codeql database create --language=python`` indexes the
source tree directly.

Java databases need a real compile, as in the PathVul builder: detect Maven
(``pom.xml`` / ``mvnw``) or Gradle (``build.gradle`` / ``gradlew``), prefer
wrappers, then try each tool × JDK with ``codeql database create --language java
--command …``. There is no no-command Java fallback.
"""

from __future__ import annotations

import csv
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from shutil import which as _which

from src.post_cutoff.clone import dest_for, slim_record
from src.post_cutoff.config import Layout, log, warn
from src.post_cutoff.schema import folder_slug

CODEQL_LANGUAGE = {"Python": "python", "Java": "java"}
REPORT_FIELDS = ["cve", "language", "status", "message", "repo_path", "db_path"]

MVN_BUILD_ARGS = [
    "clean", "package", "-B", "-V", "-e",
    "-Dfindbugs.skip", "-Dcheckstyle.skip", "-Dpmd.skip=true", "-Dspotbugs.skip",
    "-Denforcer.skip", "-Dmaven.javadoc.skip", "-Dlicense.skip=true", "-Drat.skip=true",
    "-Dspotless.check.skip=true", "-Dmaven.compiler.proc=none", "-Dmaven.test.skip=true",
    "-am",
]
GRADLE_BUILD_ARGS = [
    "clean", "build", "-x", "test", "--stacktrace", "--no-daemon", "--warning-mode", "all",
]


def db_looks_complete(db_path: Path) -> bool:
    if not db_path.is_dir():
        return False
    return (
        (db_path / "codeql-database.yml").is_file()
        or (db_path / "db-python").is_dir()
        or (db_path / "db-java").is_dir()
    )


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


def _run_streaming(
    argv: list[str],
    log_path: Path,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> tuple[bool, str]:
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
                env=env,
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


def _resolve_build_bin(cmd: str, repo: Path) -> str | None:
    if cmd.startswith("./"):
        path = repo / cmd[2:]
        if path.exists():
            try:
                path.chmod(path.stat().st_mode | 0o111)
            except OSError:
                pass
            return str(path)
        return None
    abs_cmd = Path(cmd)
    if abs_cmd.is_absolute():
        return str(abs_cmd) if abs_cmd.is_file() and os.access(abs_cmd, os.X_OK) else None
    found = _which(cmd)
    return found


def detect_build_system(repo: Path) -> tuple[bool, bool]:
    """Return ``(has_maven, has_gradle)`` from wrappers and manifests."""
    try:
        has_pom = (repo / "pom.xml").is_file() or any(repo.glob("**/pom.xml"))
        has_gradle = any(
            (repo / name).is_file() for name in ("build.gradle", "build.gradle.kts")
        ) or any(repo.glob("**/build.gradle")) or any(repo.glob("**/build.gradle.kts"))
        has_mvnw = (repo / "mvnw").exists()
        has_gradlew = (repo / "gradlew").exists()
    except OSError:
        has_pom = (repo / "pom.xml").is_file()
        has_gradle = (repo / "build.gradle").is_file() or (repo / "build.gradle.kts").is_file()
        has_mvnw = (repo / "mvnw").exists()
        has_gradlew = (repo / "gradlew").exists()
    return has_pom or has_mvnw, has_gradle or has_gradlew


def java_build_plan(
    repo: Path, extra_mvn: list[str], extra_gradle: list[str]
) -> list[tuple[str, str]]:
    """Ordered (tool, binary) pairs: wrappers first, then PATH / ``--mvn`` / ``--gradle``."""
    has_maven, has_gradle = detect_build_system(repo)
    plan: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(tool: str, binary: str) -> None:
        key = (tool, binary)
        if key not in seen:
            seen.add(key)
            plan.append(key)

    if has_maven:
        _add("maven", "./mvnw")
        _add("maven", "mvn")
        for extra in extra_mvn:
            _add("maven", extra)
    if has_gradle:
        _add("gradle", "./gradlew")
        _add("gradle", "gradle")
        for extra in extra_gradle:
            _add("gradle", extra)
    if not plan:
        for extra in extra_mvn:
            _add("maven", extra)
        for extra in extra_gradle:
            _add("gradle", extra)
        _add("maven", "mvn")
        _add("gradle", "gradle")
    return plan


def _jdk_homes(explicit: list[Path]) -> list[Path | None]:
    homes: list[Path | None] = []
    seen: set[str] = set()
    for path in explicit:
        key = str(path.resolve()) if path.exists() else str(path)
        if key not in seen:
            seen.add(key)
            homes.append(path)
    env_home = (os.environ.get("JAVA_HOME") or "").strip()
    if env_home:
        path = Path(env_home)
        key = str(path)
        if key not in seen:
            seen.add(key)
            homes.append(path)
    if not homes:
        homes.append(None)
    return homes


def _java_env(jdk: Path | None) -> dict[str, str]:
    env = os.environ.copy()
    if jdk is None:
        return env
    env["JAVA_HOME"] = str(jdk)
    env["PATH"] = f"{jdk / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    return env


def _wipe_db(db_path: Path) -> None:
    if db_path.exists():
        shutil.rmtree(db_path, ignore_errors=True)


def build_java(
    codeql: Path,
    source: Path,
    db_path: Path,
    *,
    jdks: list[Path],
    extra_mvn: list[str],
    extra_gradle: list[str],
) -> tuple[bool, str]:
    plan = java_build_plan(source, extra_mvn, extra_gradle)
    jdk_list = _jdk_homes(jdks)
    attempts: list[dict] = []
    log(f"[pc1] Java build plan={[(t, b) for t, b in plan]} jdks={[str(j) if j else '<system>' for j in jdk_list]}")

    attempt = 0
    for tool, raw_bin in plan:
        resolved = _resolve_build_bin(raw_bin, source)
        if not resolved:
            attempts.append({"tool": tool, "bin": raw_bin, "skipped": "not found"})
            log(f"[pc1] skip {raw_bin}: not found")
            continue
        args = MVN_BUILD_ARGS if tool == "maven" else GRADLE_BUILD_ARGS
        shell_cmd = " ".join(shlex.quote(x) for x in [resolved, *args])
        for jdk in jdk_list:
            attempt += 1
            jdk_label = str(jdk) if jdk else "<system>"
            _wipe_db(db_path)
            argv = [
                str(codeql),
                "database",
                "create",
                str(db_path),
                "--language=java",
                "--source-root",
                str(source),
                "--command",
                shell_cmd,
                "--overwrite",
            ]
            log_path = Path(str(db_path) + f".{attempt:02d}-{tool}.log")
            log(f"[pc1] attempt {attempt}: {tool} {resolved} JAVA_HOME={jdk_label}")
            ok, detail = _run_streaming(argv, log_path, source, env=_java_env(jdk))
            record = {
                "attempt": attempt,
                "tool": tool,
                "bin": resolved,
                "jdk": jdk_label,
                "ok": ok,
                "detail": detail,
                "log": str(log_path),
            }
            attempts.append(record)
            if ok:
                Path(str(db_path) + ".java-build.json").write_text(
                    json.dumps(record, indent=2) + "\n", encoding="utf-8"
                )
                return True, f"{tool} {Path(resolved).name} jdk={jdk_label}"
            _wipe_db(db_path)

    summary = db_path.parent / f"{db_path.name}.java_attempts.json"
    summary.write_text(json.dumps(attempts, indent=2) + "\n", encoding="utf-8")
    return False, f"exhausted {len(attempts)} Maven/Gradle × JDK attempts; see {summary}"


def build_one(
    codeql: Path,
    source: Path,
    db_path: Path,
    language: str,
    *,
    jdks: list[Path] | None = None,
    extra_mvn: list[str] | None = None,
    extra_gradle: list[str] | None = None,
) -> tuple[bool, str]:
    ql_lang = CODEQL_LANGUAGE.get(language)
    if ql_lang is None:
        return False, f"unsupported language {language}"
    if language == "Java":
        return build_java(
            codeql,
            source,
            db_path,
            jdks=jdks or [],
            extra_mvn=extra_mvn or [],
            extra_gradle=extra_gradle or [],
        )
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
    jdks: list[Path] | None = None,
    extra_mvn: list[str] | None = None,
    extra_gradle: list[str] | None = None,
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
        f"pending={len(pending)} order=smallest-first codeql={codeql} language={language}"
    )

    rows: list[dict] = []
    for i, (nbytes, rec, source, db_path) in enumerate(pending, start=1):
        log(f"[pc1] [{i}/{len(pending)}] {rec['cve_id']} {human_bytes(nbytes)} -> {db_path}")
        try:
            ok, detail = build_one(
                codeql,
                source,
                db_path,
                language,
                jdks=jdks,
                extra_mvn=extra_mvn,
                extra_gradle=extra_gradle,
            )
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
