"""Write the PF-1 survivors in CVEPath layout.

Turns ``processed_paths_<cwe>.json`` (path hash -> nodes plus hunk matches) into
``annotations/vulnerable_paths.json`` (path hash -> list of
``{line_number, file_name, code_snippet}``), a slim ``cve_metadata.json``, an
``input_filenames.json`` holding the union of files on any kept path, and a
``source/`` copy of those files from the vulnerable checkout.

The result loads with the same readers as ``data/CVEPath`` and
``data/post-cutoff-cves``, so it can be passed straight to
``scripts/run_llms_on_cvepath.py --dataset-dir``. These paths have *not* been
through PF-2 (manual validation), which is what the shipped post-cutoff set had.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from src.post_cutoff.clone import dest_for, slim_record
from src.post_cutoff.config import Layout, log, warn
from src.post_cutoff.schema import folder_slug

METADATA_FIELDS = (
    "cve_id",
    "cwe_id",
    "cve_description",
    "cve_language",
    "project",
    "commit_id",
    "publish_date",
    "commit_date",
    "parents",
)


def _node(raw: dict) -> dict | None:
    line_info = raw.get("lineInfo") or {}
    file_name = raw.get("fileInfo") or ""
    line = line_info.get("startLine")
    if not file_name or not isinstance(line, int):
        return None
    return {
        "line_number": line,
        "file_name": file_name,
        "code_snippet": (raw.get("sourceCode") or "").strip(),
    }


def load_pf1_paths(layout: Layout, slug: str) -> dict[str, list[dict]]:
    """Merge every ``processed_paths_<cwe>.json`` for one CVE."""
    folder = layout.paths / slug
    merged: dict[str, list[dict]] = {}
    if not folder.is_dir():
        return merged
    for path_file in sorted(folder.glob("processed_paths_*.json")):
        try:
            data = json.loads(path_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for path_hash, entry in data.items():
            nodes = entry.get("path") if isinstance(entry, dict) else entry
            if not isinstance(nodes, list):
                continue
            converted = [n for n in (_node(x) for x in nodes if isinstance(x, dict)) if n]
            if converted:
                merged[path_hash] = converted
    return merged


def _oracle_files(paths: dict[str, list[dict]]) -> list[str]:
    seen: list[str] = []
    for path_hash in sorted(paths):
        for node in paths[path_hash]:
            name = node.get("file_name")
            if name and name not in seen:
                seen.append(name)
    return seen


def _slim_metadata(raw: dict, language: str) -> dict:
    meta = {key: raw.get(key) for key in METADATA_FIELDS}
    meta["cve_language"] = raw.get("cve_language") or language
    return meta


def pack_one(layout: Layout, rec: dict, language: str) -> tuple[str, list[str]] | None:
    slug = folder_slug(rec["cve_id"], rec.get("project") or "")
    paths = load_pf1_paths(layout, slug)
    if not paths:
        return None
    files = _oracle_files(paths)
    if not files:
        return None

    repo = dest_for(layout.repos, slim_record(rec))
    if not repo.is_dir():
        warn(f"[pack] {slug}: missing checkout {repo}")
        return None

    dest = layout.cvepath / language / slug
    if dest.exists():
        shutil.rmtree(dest)
    annotations = dest / "annotations"
    source_root = dest / "source"
    annotations.mkdir(parents=True)
    source_root.mkdir(parents=True)

    copied: list[str] = []
    for rel in files:
        src = repo / rel
        if not src.is_file():
            warn(f"[pack] {slug}: missing source file {rel}")
            continue
        dst = source_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel)
    if not copied:
        shutil.rmtree(dest, ignore_errors=True)
        return None

    (annotations / "vulnerable_paths.json").write_text(
        json.dumps(paths, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (annotations / "cve_metadata.json").write_text(
        json.dumps(_slim_metadata(rec, language), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (annotations / "input_filenames.json").write_text(
        json.dumps({"files": [copied]}, indent=4) + "\n", encoding="utf-8"
    )
    return slug, copied


def pack_all(layout: Layout, records: list[dict], *, language: str) -> list[str]:
    """Pack every record that has PF-1 paths; return the packed slugs."""
    layout.cvepath.mkdir(parents=True, exist_ok=True)
    packed: list[str] = []
    for rec in records:
        if rec.get("cve_language") != language:
            continue
        result = pack_one(layout, rec, language)
        if result is None:
            continue
        slug, files = result
        packed.append(slug)
        log(f"[pack] {language}/{slug} paths_ok files={len(files)}")
    log(f"[pack] wrote {len(packed)} CVEs to {layout.cvepath / language}")
    return packed
