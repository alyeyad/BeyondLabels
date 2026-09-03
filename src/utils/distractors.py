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

import hashlib
import json
import os
import random
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

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


# ---------------------------------------------------------------------------
# RQ4 negatives: prefer test/docs files from cloned CVEPath checkouts.
# E3 ``sample_distractors`` above is unchanged (it *excludes* tests).
# ---------------------------------------------------------------------------

_TEST_DOC_DIR_NAMES = {"test", "tests", "__tests__", "spec", "docs", "doc"}
_TEST_DOC_STEMS = {"readme", "changelog", "license"}
_WALK_SKIP_DIRS = {".git", ".svn", ".hg"}


def is_test_or_docs_path(rel_path: str) -> bool:
    """Letter heuristic: test/docs-like paths (dirs, test_* files, README)."""
    lower = rel_path.replace("\\", "/").lower()
    parts = lower.split("/")
    if any(p in _TEST_DOC_DIR_NAMES for p in parts):
        return True
    if "src/test" in lower or "/readme" in lower:
        return True
    stem = Path(lower).stem
    if stem.startswith("test_") or stem.endswith("_test"):
        return True
    if stem in _TEST_DOC_STEMS:
        return True
    return False


def negative_distractor_seed(
    model: str,
    language: str,
    sample_id: str,
    base: int = 1234,
) -> int:
    """Deterministic seed mixed from model, language, and instance."""
    h = hashlib.md5(f"{model}|{language}|{sample_id}".encode()).hexdigest()
    return base + (int(h[:8], 16) % 1_000_000)


def empty_negative_distractor_meta(seed: int = 1234, k=0) -> Dict:
    return {
        "distractor_seed": seed,
        "distractors_requested": k,
        "distractors_used": 0,
        "distractor_files": [],
        "home_repo": None,
        "fill_repos": [],
        "skipped_empty": 0,
    }


def _load_cve_project(cve_dir: Path) -> str:
    path = cve_dir / "annotations" / "cve_metadata.json"
    if not path.exists():
        return ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    md = data.get("metadata", data) if isinstance(data, dict) else {}
    if not isinstance(md, dict):
        return ""
    return str(md.get("project") or "").strip()


def build_negative_checkout_index(
    cvepath_dir: Path,
    repos_dir: Path,
    language: str,
) -> Tuple[Dict[str, List[Path]], List[Path]]:
    """Map ``project.lower()`` → checkout dirs (lexicographic slug) and all checkouts.

    Only folders that actually exist under ``repos_dir/{language}/`` are included.
    """
    from src.utils.dataset import list_all_cve_folders

    by_project: Dict[str, List[Path]] = {}
    all_repos: List[Path] = []
    lang_root = Path(repos_dir) / language
    for slug, folder_lang in list_all_cve_folders(Path(cvepath_dir)):
        if folder_lang != language:
            continue
        dest = lang_root / slug
        if not dest.is_dir():
            continue
        all_repos.append(dest)
        project = _load_cve_project(Path(cvepath_dir) / language / slug).lower()
        if project:
            by_project.setdefault(project, []).append(dest)
    all_repos.sort(key=lambda p: p.name)
    for project in by_project:
        by_project[project].sort(key=lambda p: p.name)
    return by_project, all_repos


def _blocked_relpaths(exclude: Iterable[str]) -> Set[str]:
    blocked: Set[str] = set()
    for item in exclude:
        if not item:
            continue
        norm = str(item).replace("\\", "/").lstrip("./")
        blocked.add(norm)
        blocked.add(Path(norm).name)
    return blocked


def _iter_source_relpaths(
    repo_dir: Path,
    exts: Tuple[str, ...],
    cache: Optional[Dict[Path, List[str]]] = None,
) -> List[str]:
    if cache is not None and repo_dir in cache:
        return cache[repo_dir]
    rels: List[str] = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in _WALK_SKIP_DIRS]
        for name in files:
            if not name.endswith(exts):
                continue
            rel = os.path.relpath(os.path.join(root, name), repo_dir).replace("\\", "/")
            rels.append(rel)
    rels.sort()
    if cache is not None:
        cache[repo_dir] = rels
    return rels


def _read_if_usable(
    repo_dir: Path,
    rel: str,
    min_nonblank_lines: int,
) -> Optional[str]:
    try:
        raw = (repo_dir / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if _nonblank_line_count(raw) < min_nonblank_lines:
        return None
    return raw


def _partition_relpaths(
    rels: Sequence[str],
    blocked: Set[str],
) -> Tuple[List[str], List[str]]:
    preferred: List[str] = []
    other: List[str] = []
    for rel in rels:
        if rel in blocked or Path(rel).name in blocked:
            continue
        if is_test_or_docs_path(rel):
            preferred.append(rel)
        else:
            other.append(rel)
    return preferred, other


def sample_negative_test_docs_distractors(
    *,
    language: str,
    project: Optional[str],
    sample_id: str,
    model: str,
    k,
    seed: int,
    by_project: Dict[str, List[Path]],
    all_repos: Sequence[Path],
    exclude: Iterable[str],
    min_nonblank_lines: int = 1,
    listing_cache: Optional[Dict[Path, List[str]]] = None,
) -> Tuple[List[Tuple[str, str]], Dict]:
    """Select up to ``k`` test/docs-like files from cloned checkouts.

    Home repo (CVEPath project match, first slug) preferred-files first; if
    fewer than ``k``, fill with test/docs from other same-language checkouts,
    then any remaining same-language source files from those fill repos.
    Selection is nested in ``k``: the k=5 prefix contains k=1 and k=3.
    Returned keys are ``{slug}/{relpath}`` so prompt headers stay unique.
    """
    mixed_seed = negative_distractor_seed(model, language, sample_id, base=seed)
    limit, scope = resolve_k(k)
    meta = empty_negative_distractor_meta(mixed_seed, k=limit if scope == "count" else k)

    if scope != "count" or limit is None:
        raise ValueError(
            "RQ4 negative --distractors must be an integer k (0, 1, 3, or 5); "
            f"got {k!r}"
        )
    if limit == 0 or not LANG_EXTENSIONS.get(language):
        return [], meta

    exts = LANG_EXTENSIONS[language]
    blocked = _blocked_relpaths(exclude)
    home_list = by_project.get((project or "").strip().lower(), [])
    home = home_list[0] if home_list else None
    meta["home_repo"] = home.name if home is not None else None
    others = [p for p in all_repos if home is None or p != home]

    rng_home = random.Random(mixed_seed)
    fill_order = list(others)
    random.Random(mixed_seed + 1).shuffle(fill_order)

    def _take(repo: Path, rels: List[str]) -> None:
        nonlocal skipped_empty
        for rel in rels:
            if len(selected) >= limit:
                return
            key = f"{repo.name}/{rel}"
            if key in seen:
                continue
            raw = _read_if_usable(repo, rel, min_nonblank_lines)
            if raw is None:
                skipped_empty += 1
                continue
            seen.add(key)
            selected.append((key, raw))
            if home is None or repo != home:
                if repo.name not in fill_repos:
                    fill_repos.append(repo.name)

    selected: List[Tuple[str, str]] = []
    fill_repos: List[str] = []
    seen: Set[str] = set()
    skipped_empty = 0
    fill_other: List[Tuple[Path, List[str]]] = []

    if home is not None:
        preferred, _other = _partition_relpaths(
            _iter_source_relpaths(home, exts, listing_cache), blocked
        )
        rng_home.shuffle(preferred)
        _take(home, preferred)

    if len(selected) < limit:
        for i, repo in enumerate(fill_order):
            preferred, other = _partition_relpaths(
                _iter_source_relpaths(repo, exts, listing_cache), blocked
            )
            random.Random(mixed_seed + 2 + i).shuffle(preferred)
            random.Random(mixed_seed + 1000 + i).shuffle(other)
            fill_other.append((repo, other))
            _take(repo, preferred)
            if len(selected) >= limit:
                break

    if len(selected) < limit:
        for repo, other in fill_other:
            _take(repo, other)
            if len(selected) >= limit:
                break

    meta["distractors_used"] = len(selected)
    meta["distractor_files"] = [key for key, _ in selected]
    meta["fill_repos"] = fill_repos
    meta["skipped_empty"] = skipped_empty
    return selected, meta
