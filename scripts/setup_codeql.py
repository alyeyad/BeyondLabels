#!/usr/bin/env python3
"""Download and unpack the CodeQL CLI used to build the post-cutoff databases.

The paper used CodeQL CLI 2.15.3 (``codeql/python-all`` 0.11.3,
``codeql/python-queries`` 0.9.3), which matches the ``cliVersion`` pinned in
``query_packs/base_queries/Python/qlpack.yml``. Cloning ``github/codeql`` gives
only the QL sources, not the binary, so this fetches the release archive from
``github/codeql-cli-binaries``.

Writes ``tools/codeql/`` (gitignored). Point ``CODEQL_PATH`` at an existing
install to skip the download.
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
    # zipfile drops the executable bit.
    for path in dest.rglob("*"):
        if path.is_file() and not path.suffix:
            path.chmod(path.stat().st_mode | 0o111)
    codeql_binary(dest).chmod(codeql_binary(dest).stat().st_mode | 0o111)


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
    args = parser.parse_args()

    binary = codeql_binary(args.dest)
    current = installed_version(binary)
    if current and not args.force:
        if current == args.version:
            print(f"CodeQL {current} already installed at {binary}")
            return 0
        print(f"warning: {binary} is CodeQL {current}, expected {args.version}", file=sys.stderr)
        print("Pass --force to replace it.", file=sys.stderr)
        return 1

    asset = args.platform or detect_platform()
    url = RELEASE_URL.format(version=args.version, platform=asset)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / f"codeql-{asset}.zip"
        download(url, archive)
        print(f"Unpacking into {args.dest}", flush=True)
        unpack(archive, args.dest)

    found = installed_version(binary)
    if found != args.version:
        print(
            f"error: installed CodeQL reports {found!r}, expected {args.version!r}",
            file=sys.stderr,
        )
        return 1
    print(f"CodeQL {found} ready at {binary}")
    print(f"Use it with: export CODEQL_PATH={binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
