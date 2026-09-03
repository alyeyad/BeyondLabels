#!/usr/bin/env python3
"""Download the CodeQL CLI and the Java/Python libraries the queries need.

The paper used CodeQL CLI 2.15.3. The official ``codeql-cli-binaries`` zip is
extractors only; the post-cutoff run used a 2.15.3 tree that already had
``codeql/python-all`` 0.11.3 and ``codeql/java-all`` 0.8.3 on the CLI search
path. This script unpacks the CLI, then downloads those packs (and their
dependencies) into ``<dest>/qlpacks/`` so both languages resolve the same way.

Writes ``tools/codeql/`` (gitignored). Point ``CODEQL_PATH`` at an existing
2.15.3 install to skip the CLI download; packs are still installed unless
``--skip-packs`` is set.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

DEFAULT_VERSION = "2.15.3"
DEFAULT_DEST = PROJECT_ROOT / "tools" / "codeql"
RELEASE_URL = (
    "https://github.com/github/codeql-cli-binaries/releases/download/"
    "v{version}/codeql-{platform}.zip"
)

# Versions the post-cutoff Python run and the shipped Java qlpack actually used.
LIBRARY_PACKS = (
    "codeql/python-all@0.11.3",
    "codeql/java-all@0.8.3",
    "codeql/suite-helpers@0.7.3",
    "codeql/util@0.2.3",
)
QUERY_PACK_DIRS = (
    PROJECT_ROOT / "query_packs" / "base_queries" / "Python",
    PROJECT_ROOT / "query_packs" / "base_queries" / "Java",
)

PLATFORM_ASSETS = {
    ("linux", "x86_64"): "linux64",
    ("linux", "amd64"): "linux64",
    ("darwin", "x86_64"): "osx64",
    ("darwin", "arm64"): "osx64",
    ("windows", "amd64"): "win64",
}


def detect_platform() -> str:
    key = (platform.system().lower(), platform.machine().lower())
    asset = PLATFORM_ASSETS.get(key)
    if asset is None:
        raise SystemExit(
            f"Unsupported platform {key}; pass --platform linux64|osx64|win64"
        )
    return asset


def codeql_binary(dest: Path) -> Path:
    name = "codeql.exe" if platform.system().lower().startswith("win") else "codeql"
    return dest / name


def installed_version(binary: Path) -> str | None:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return None
    try:
        out = subprocess.check_output(
            [str(binary), "version", "--format=json"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        return str(json.loads(out).get("version") or "") or None
    except json.JSONDecodeError:
        return None


def download(url: str, dest_file: Path) -> None:
    print(f"Downloading {url}", flush=True)
    with urllib.request.urlopen(url) as resp:  # noqa: S310 - fixed GitHub release URL
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        step = 25 * 1024 * 1024
        next_mark = step
        with dest_file.open("wb") as fh:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if done >= next_mark:
                    pct = f" ({100 * done // total}%)" if total else ""
                    print(f"  {done // (1024 * 1024)} MiB{pct}", flush=True)
                    next_mark += step
    print(f"Downloaded {done // (1024 * 1024)} MiB", flush=True)


def restore_execute_bits(dest: Path) -> None:
    """zipfile drops the executable bit on binaries and extractor scripts."""
    for path in dest.rglob("*"):
        if not path.is_file():
            continue
        if not path.suffix or path.suffix == ".sh":
            path.chmod(path.stat().st_mode | 0o111)
    codeql_binary(dest).chmod(codeql_binary(dest).stat().st_mode | 0o111)


def unpack(archive: Path, dest: Path) -> None:
    """Extract the archive's top-level ``codeql/`` directory into ``dest``."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(dest.parent)) as tmp:
        tmp_path = Path(tmp)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp_path)
        inner = tmp_path / "codeql"
        if not inner.is_dir():
            entries = [p for p in tmp_path.iterdir() if p.is_dir()]
            if len(entries) != 1:
                raise SystemExit(f"unexpected archive layout: {[p.name for p in entries]}")
            inner = entries[0]
        shutil.move(str(inner), str(dest))
    restore_execute_bits(dest)


def _run_codeql(binary: Path, args: list[str]) -> None:
    cmd = [str(binary), *args]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


# Only these versions go on the CLI search path. A fuller ~/.codeql cache may
# also hold newer packs (java-all 7.x, python-all 0.8.3) that must not win.
STAGE_PACKS = {
    "python-all": "0.11.3",
    "java-all": "0.8.3",
    "suite-helpers": "0.7.3",
    "util": "0.2.3",
    "dataflow": "0.1.3",
    "mad": "0.2.3",
    "regex": "0.2.3",
    "ssa": "0.2.3",
    "tutorial": "0.2.3",
    "yaml": "0.2.3",
    "rangeanalysis": "0.0.2",
    "threat-models": "0.0.2",
    "typetracking": "0.2.3",
}


def pack_cache_root() -> Path:
    return Path.home() / ".codeql" / "packages"


def stage_packs_into_cli(dest: Path) -> None:
    """Copy the 2.15.3-era libraries into ``<dest>/qlpacks`` so the CLI finds them."""
    cache = pack_cache_root() / "codeql"
    qlpacks = dest / "qlpacks" / "codeql"
    for name, version in STAGE_PACKS.items():
        src = cache / name / version
        if not src.is_dir():
            continue
        target = qlpacks / name / version
        if target.is_dir():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, target)
        print(f"Staged {name}@{version} into {target}", flush=True)


def install_library_packs(binary: Path, dest: Path) -> None:
    """Download Java/Python libraries and make them visible to this CLI."""
    _run_codeql(binary, ["pack", "download", *LIBRARY_PACKS])
    for pack_dir in QUERY_PACK_DIRS:
        if pack_dir.is_dir():
            _run_codeql(binary, ["pack", "install", str(pack_dir)])
    stage_packs_into_cli(dest)


def ensure_cli(dest: Path, version: str, platform_name: str, force: bool) -> Path:
    binary = codeql_binary(dest)
    current = installed_version(binary)
    if current and not force:
        if current != version:
            raise SystemExit(
                f"{binary} is CodeQL {current}, expected {version}\n"
                "Pass --force to replace it."
            )
        print(f"CodeQL {current} already installed at {binary}")
        restore_execute_bits(dest)
        return binary

    url = RELEASE_URL.format(version=version, platform=platform_name)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / f"codeql-{platform_name}.zip"
        download(url, archive)
        print(f"Unpacking into {dest}", flush=True)
        unpack(archive, dest)

    found = installed_version(binary)
    if found != version:
        raise SystemExit(f"installed CodeQL reports {found!r}, expected {version!r}")
    print(f"CodeQL {found} ready at {binary}")
    return binary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument(
        "--platform",
        default=None,
        choices=["linux64", "osx64", "win64"],
        help="Release asset (default: detected from the host).",
    )
    parser.add_argument("--force", action="store_true", help="Re-download even if present.")
    parser.add_argument(
        "--skip-packs",
        action="store_true",
        help="Install the CLI only; do not download Java/Python qlpacks.",
    )
    args = parser.parse_args()

    binary = ensure_cli(
        args.dest, args.version, args.platform or detect_platform(), args.force
    )
    if not args.skip_packs:
        print("Installing Java and Python query libraries …", flush=True)
        install_library_packs(binary, args.dest)
    print(f"Use it with: export CODEQL_PATH={binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
