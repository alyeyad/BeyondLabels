"""
Deterministic distractor-file sampling for the non-oracle / noise-robustness
experiment (E3).

Given a CVE's reference (needed) files and a full upstream repository checked out
at the vulnerable commit, this selects ``k`` irrelevant same-language source
files to append to the model input as distractors.

Design goals:
  * Deterministic: identical (cve, k, seed) always yields the same selection.
  * Realistic: prefer files in the *same directory* as the reference files
    (tier 1), then widen to the rest of the repository (tier 2).
  * Safe for NOR/LCNR: distractors are appended *after* the needed files, so the
    reference files keep their original positions and line numbers.
  * Non-leaking of ground truth: reference and test files are excluded.
  * Budget aware: an optional character budget stops adding distractors before
    the prompt overflows the model context window.

The returned distractors are *raw* source (not line-numbered); the caller merges
them into the file mapping and ``construct_prompt`` line-numbers every file
uniformly, exactly like the needed files.
"""

from __future__ import annotations

import os
import random
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from src.utils.prompts import add_line_numbers_to_content

LANG_EXTENSIONS = {
    "Java": (".java",),
    "Python": (".py",),
}

# Approximate context windows (tokens) used only for the distractor budget.
MODEL_TOKEN_LIMITS = {
    "gpt-4o": 128_000,
    "gpt-4.1": 1_000_000,
    "gpt-5.2": 400_000,
    "o3": 200_000,
    "deepseek-reasoner": 65_536,
    "deepseek/deepseek-v3.2": 128_000,
    "claude-sonnet-4-5": 200_000,
    "meta-llama/llama-3.3-70b-instruct": 128_000,
}
OUTPUT_TOKEN_RESERVE = 16_000
CHARS_PER_TOKEN = 3.5


def resolve_k(k) -> Tuple[Optional[int], str]:
    """Normalize the distractors value into (limit, scope)."""
    if isinstance(k, int):
        return k, "count"
    s = str(k).strip().lower()
    if s in ("all-in-dir", "all_in_dir", "dir"):
        return None, "all-in-dir"
    if s == "all":
        return None, "all"
    return int(s), "count"


def char_budget_for(model: str) -> int:
    limit = MODEL_TOKEN_LIMITS.get(model)
    if limit is None:
        # Prefix match (e.g. gpt-5.2-2025-12-11 -> gpt-5.2).
        for key, val in MODEL_TOKEN_LIMITS.items():
            if model.startswith(key):
                limit = val
                break
    if limit is None:
        limit = 128_000
    usable = max(0, limit - OUTPUT_TOKEN_RESERVE)
    return int(usable * CHARS_PER_TOKEN)


def _nonblank_line_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip())


def _is_test_path(rel_path: str) -> bool:
    lower = rel_path.replace("\\", "/").lower()
    parts = lower.split("/")
    if "test" in parts or "tests" in parts:
        return True
    stem = os.path.splitext(os.path.basename(lower))[0]
    return "test" in stem


def _collect_candidates(repo_dir: Path, exts: Tuple[str, ...], needed: set) -> List[str]:
    candidates: List[str] = []
    for root, _dirs, files in os.walk(repo_dir):
        for name in files:
            if not name.endswith(exts):
                continue
            rel = os.path.relpath(os.path.join(root, name), repo_dir).replace("\\", "/")
            if rel in needed or _is_test_path(rel):
                continue
            candidates.append(rel)
    return candidates


def _rank_candidates(candidates: List[str], needed: set, seed: int) -> Tuple[List[str], List[str]]:
    needed_dirs = {os.path.dirname(p) for p in needed}
    tier1 = sorted(p for p in candidates if os.path.dirname(p) in needed_dirs)
    tier2 = sorted(p for p in candidates if os.path.dirname(p) not in needed_dirs)
    random.Random(seed).shuffle(tier1)
    random.Random(seed + 1).shuffle(tier2)
    return tier1, tier2


def sample_distractors(
    repo_dir,
    language: str,
    needed_files: List[str],
    k,
    seed: int = 1234,
    base_chars: int = 0,
    budget_chars: Optional[int] = None,
    min_nonblank_lines: int = 1,
    exclude_paths: Optional[Iterable[str]] = None,
) -> Tuple[List[Tuple[str, str]], Dict]:
    """Select up to ``k`` distractor files from ``repo_dir``.

    Files with fewer than ``min_nonblank_lines`` non-blank lines are skipped, so
    an empty ``__init__.py`` cannot consume one of the ``k`` slots and leave the
    input effectively unchanged.

    ``exclude_paths`` blocks additional files from becoming distractors without
    treating them as part of the input. Callers pass every file belonging to any
    reference path of the CVE: a file from a sibling reference path is not noise,
    because scoring matches a prediction against all of the CVE's reference paths
    and would credit a path reconstructed through it.

    Tiering still keys on ``needed_files`` alone, so "prefer a file from the same
    directory" remains relative to the code the model was actually shown.

    Returns (selected, meta) where ``selected`` is a list of (relpath, raw_code)
    tuples and ``meta`` describes the selection.
    """
    repo_dir = Path(repo_dir)
    exts = LANG_EXTENSIONS.get(language, ())
    needed = {p.replace("\\", "/") for p in needed_files}
    blocked = needed | {p.replace("\\", "/") for p in (exclude_paths or ())}
    limit, scope = resolve_k(k)

    meta: Dict = {
        "distractor_seed": seed,
        "sampling_scope": scope,
        "distractors_requested": (limit if scope == "count" else scope),
        "distractors_used": 0,
        "distractor_files": [],
        "candidate_count": 0,
        "budget_truncated": False,
        "min_nonblank_lines": min_nonblank_lines,
        "skipped_empty": 0,
        "excluded_reference_files": sorted(blocked - needed),
    }

    if not exts or (scope == "count" and limit == 0):
        return [], meta

    if not repo_dir.is_dir():
        meta["error"] = f"missing repo_dir: {repo_dir}"
        return [], meta

    all_candidates = _collect_candidates(repo_dir, exts, blocked)
    meta["candidate_count"] = len(all_candidates)
    if not all_candidates:
        return [], meta

    tier1, tier2 = _rank_candidates(all_candidates, needed, seed)
    ordered = tier1 if scope == "all-in-dir" else tier1 + tier2

    selected: List[Tuple[str, str]] = []
    used_chars = base_chars
    for rel in ordered:
        if scope == "count" and limit is not None and len(selected) >= limit:
            break
        try:
            raw = (repo_dir / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if _nonblank_line_count(raw) < min_nonblank_lines:
            meta["skipped_empty"] += 1
            continue

        # Estimate the assembled cost of one "===== file =====\n<numbered>" block.
        block_chars = len(rel) + len(add_line_numbers_to_content(raw)) + 16
        if budget_chars is not None and used_chars + block_chars > budget_chars:
            meta["budget_truncated"] = True
            break

        selected.append((rel, raw))
        used_chars += block_chars

    meta["distractors_used"] = len(selected)
    meta["distractor_files"] = [rel for rel, _ in selected]
    return selected, meta
