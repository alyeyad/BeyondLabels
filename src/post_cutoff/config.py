"""Shared defaults and the on-disk layout of a post-cutoff collection run."""

from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
QUERY_PACKS = PROJECT_ROOT / "query_packs"
PROMPT_PATH = PROJECT_ROOT / "prompt_templates" / "llm_multifile_labelling.txt"
DEFAULT_OUT = PROJECT_ROOT / "output" / "post_cutoff"

# CodeQL CLI the paper used; scripts/setup_codeql.py unpacks it here.
CODEQL_VERSION = "2.15.3"
BUNDLED_CODEQL = PROJECT_ROOT / "tools" / "codeql" / "codeql"

# GPT-5.2 knowledge cutoff. NVD publish date and fix-commit date must both be
# strictly after this day; GHSA is scanned from the day after.
DEFAULT_CUTOFF = "2025-08-31"
DEFAULT_SINCE = "2025-09-01"
DEFAULT_CS2_MODEL = "claude-opus-5"

LANG_ECOSYSTEMS = {
    "Python": ["pip"],
    "Java": ["maven"],
}

# CVE-ID lists written after each funnel stage; see funnel.py.
FUNNEL_FILES = {
    "ghsa": "01_ghsa_with_cve.txt",
    "language": "02_language.txt",
    "github_fix": "03_github_fix.txt",
    "parent_sha": "04_parent_sha.txt",
    "after_cutoff": "05_after_cutoff.txt",
    "cs1": "06_path_problem_cwe.txt",
    "removed_lines": "07_has_removed_lines.txt",
    "cs2": "08_cs2_cve_related.txt",
    "pc1": "09_pc1_db_built.txt",
    "pc2": "10_pc2_codeql_paths.txt",
    "pf1": "11_pf1_hunk_overlap.txt",
}

_PRINT_LOCK = threading.Lock()


def log(msg: str) -> None:
    with _PRINT_LOCK:
        print(msg, flush=True)


def warn(msg: str) -> None:
    with _PRINT_LOCK:
        print(msg, file=sys.stderr, flush=True)


@dataclass(frozen=True)
class Layout:
    """Every directory a run reads or writes, rooted at ``--out``."""

    root: Path

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    @property
    def candidates(self) -> Path:
        return self.root / "candidates.jsonl"

    @property
    def summary(self) -> Path:
        return self.root / "summary.csv"

    @property
    def metadata(self) -> Path:
        return self.root / "metadata"

    @property
    def hunks(self) -> Path:
        return self.root / "hunks"

    @property
    def cs2(self) -> Path:
        return self.root / "cs2"

    @property
    def cvepath_hunks(self) -> Path:
        """Augmentation input for PC-1: hunks restricted to CS-2 kept files."""
        return self.root / "cvepath_hunks"

    @property
    def funnel(self) -> Path:
        return self.root / "funnel"

    @property
    def repos(self) -> Path:
        return self.root / "repos"

    @property
    def dbs(self) -> Path:
        return self.root / "dbs"

    @property
    def paths(self) -> Path:
        return self.root / "paths"

    @property
    def cvepath(self) -> Path:
        return self.root / "cvepath"

    def funnel_file(self, stage: str) -> Path:
        return self.funnel / FUNNEL_FILES[stage]


def write_ids(path: Path, cves: set[str] | list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{cve}\n" for cve in sorted(set(cves))), encoding="utf-8")


def load_ids(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def resolve_codeql(explicit: Path | str | None = None) -> Path:
    """``--codeql`` if given, else ``CODEQL_PATH``, else ``tools/codeql/codeql``."""
    if explicit:
        return Path(explicit)
    env = (os.environ.get("CODEQL_PATH") or "").strip()
    if env:
        return Path(env)
    return BUNDLED_CODEQL


def github_token() -> str:
    return (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
