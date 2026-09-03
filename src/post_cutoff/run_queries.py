"""PC-1 augmentation, PC-2 analysis, and PF-1 filtering, one CVE at a time.

For each CVE this restricts the removed hunks to the files CS-2 labelled
``vulnerability-path-fixing``, resolves the enclosing function of each hunk in
the vulnerable checkout, and writes the CVEPath-shaped ``hunks.json`` that
``query_pipeline.py`` turns into ``MySources.qll`` / ``MySinks.qll`` /
``MySummaries.qll`` (PC-1). ``query_pipeline.py`` then runs ``codeql database
analyze`` (PC-2) and keeps the paths with maximum hunk overlap (PF-1).

Each (CVE, CWE) pair runs in a subprocess so that a CodeQL crash or an
out-of-memory kill costs one query, not the whole run.
"""

from __future__ import annotations

import ast
import json
import shlex
import subprocess
import sys
from pathlib import Path

from src.post_cutoff.build_db import db_looks_complete, repo_size_bytes
from src.post_cutoff.clone import dest_for, slim_record
from src.post_cutoff.config import QUERY_PACKS, Layout, log, warn
from src.post_cutoff.cs2 import kept_file_names
from src.post_cutoff.schema import folder_slug

PIPELINE_SCRIPT = Path(__file__).resolve().parent / "query_pipeline.py"


def pad_cwe(cwe: str) -> str:
    parts = (cwe or "").strip().split("-")
    if len(parts) != 2 or not parts[1].isdigit():
        return (cwe or "").strip()
    num = parts[1].zfill(3)
    return f"{parts[0].upper()}-{num}"


def expand_cwes(raw: list[str] | None) -> list[str]:
    """CWE ids to query, padded to three digits.

    CWE-502 (deserialization) is reported by the CWE-020 pack, so it is added
    whenever 502 is present and 020 is not.
    """
    seen: list[str] = []
    for item in raw or []:
        cwe = pad_cwe(str(item))
        if cwe and cwe not in seen:
            seen.append(cwe)
    if "CWE-502" in seen and "CWE-020" not in seen:
        seen.append("CWE-020")
    return seen


def cwe_has_queries(cwe: str, language: str, query_packs: Path = QUERY_PACKS) -> bool:
    folder = query_packs / "custom-cwe-queries" / language / cwe.lower()
    return folder.is_dir() and any(
        p.suffix == ".ql" for p in folder.iterdir() if p.is_file()
    )


def _norm_path(value: str) -> str:
    return (value or "").replace("\\", "/").lstrip("./")


def _path_match(left: str, right: str) -> bool:
    a, b = _norm_path(left), _norm_path(right)
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def java_method_at_line(java_file: Path, line_number: int) -> str:
    """Last MethodDeclaration whose start line is still at or before ``line_number``."""
    try:
        import javalang
    except ImportError:
        return ""
    try:
        tree = javalang.parse.parse(java_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, Exception):  # noqa: BLE001 - parse errors
        return ""
    name, start = "", -1
    for _, node in tree:
        if not isinstance(node, javalang.tree.MethodDeclaration):
            continue
        if not (hasattr(node, "position") and node.position):
            continue
        if start < node.position.line <= line_number:
            name, start = node.name, node.position.line
    return name


def function_at_line(source_file: Path, line_number: int, language: str = "") -> str:
    """Innermost function/method name containing ``line_number``, or empty."""
    if source_file.suffix.lower() == ".java" or language == "Java":
        return java_method_at_line(source_file, line_number)
    try:
        tree = ast.parse(source_file.read_text(encoding="utf-8"), filename=str(source_file))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        return ""

    items: list[tuple[str, int, int]] = []
    stack: list[str] = []

    class Collector(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        def _handle(self, node) -> None:
            start = getattr(node, "lineno", None)
            if start is None:
                return
            end = getattr(node, "end_lineno", None) or start
            items.append((".".join(stack + [node.name]), start, end))
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._handle(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._handle(node)

    Collector().visit(tree)
    containing = [it for it in items if it[1] <= line_number <= it[2]]
    if not containing:
        return ""
    qualname = max(containing, key=lambda t: t[1])[0]
    return qualname.rsplit(".", 1)[-1]


def resolve_in_repo(repo: Path, file_name: str) -> Path | None:
    rel = _norm_path(file_name)
    if not rel:
        return None
    candidate = repo / rel
    if candidate.is_file():
        return candidate
    matches = [p for p in repo.rglob(Path(rel).name) if ".git" not in p.parts]
    return matches[0] if len(matches) == 1 else None


def build_augmentation_hunks(
    rec: dict, repo: Path, layout: Layout, cs2_model: str
) -> list[dict]:
    """Removed hunks on CS-2 kept files, annotated with their function names."""
    slug = folder_slug(rec["cve_id"], rec.get("project") or "")
    src = layout.hunks / f"{slug}.json"
    if not src.is_file():
        raise FileNotFoundError(f"missing hunk JSON: {src}")
    payload = json.loads(src.read_text(encoding="utf-8"))
    keep = kept_file_names(rec, layout.cs2, cs2_model)
    if not keep:
        raise ValueError("no CS-2 vulnerability-path-fixing files")

    out: list[dict] = []
    for entry in payload.get("files") or []:
        if not isinstance(entry, dict):
            continue
        file_name = entry.get("file_name") or ""
        if not any(_path_match(file_name, k) for k in keep):
            continue
        abs_file = resolve_in_repo(repo, file_name)
        hunks_out = []
        for hunk in entry.get("hunks") or []:
            if not isinstance(hunk, dict):
                continue
            start = int(hunk.get("start_line") or 0)
            method = ""
            if abs_file is not None and start > 0:
                method = function_at_line(
                    abs_file, start, language=str(rec.get("cve_language") or "")
                )
            hunks_out.append(
                {
                    "method_name": method,
                    "parameters": hunk.get("parameters") or [],
                    "start_line": hunk.get("start_line"),
                    "end_line": hunk.get("end_line"),
                    "lines": hunk.get("lines") or [],
                }
            )
        if hunks_out:
            out.append({file_name: {"hunks": hunks_out}})
    if not out:
        raise ValueError("no removed hunks on CS-2 path-fixing files")
    return out


def write_augmentation_hunks(layout: Layout, slug: str, hunks: list[dict]) -> Path:
    layout.cvepath_hunks.mkdir(parents=True, exist_ok=True)
    path = layout.cvepath_hunks / f"{slug}.json"
    path.write_text(
        json.dumps(hunks, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return path


def has_pf1_paths(layout: Layout, slug: str) -> bool:
    folder = layout.paths / slug
    if not folder.is_dir():
        return False
    for path in folder.glob("processed_paths_*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data:
            return True
    return False


def _run_pipeline(
    *,
    codeql: Path,
    layout: Layout,
    language: str,
    slug: str,
    cwe: str,
    hunks_path: Path,
    threads: int,
    ram: int,
    query_packs: Path,
) -> int:
    cmd = [
        sys.executable,
        str(PIPELINE_SCRIPT),
        "--language", language,
        "--proj-folder-name", slug,
        "--codeql-path", str(codeql),
        "--dbs-dir", str(layout.dbs),
        "--repos-dir", str(layout.repos),
        "--base-op-dir", str(layout.paths),
        "--cwe", cwe,
        "--threads", str(threads),
        "--ram", str(ram),
        "--flat-dbs",
        "--hunks-path", str(hunks_path),
        "--query-packs", str(query_packs),
    ]
    log(f"[pc2] {shlex.join(cmd)}")
    return subprocess.run(cmd, check=False).returncode


def run_all(
    layout: Layout,
    records: list[dict],
    *,
    codeql: Path,
    language: str,
    cs2_model: str,
    target: int | None = None,
    threads: int = 6,
    ram: int = 24576,
    query_packs: Path = QUERY_PACKS,
) -> set[str]:
    """Run PC-1/PC-2/PF-1 smallest-first; stop once ``target`` CVEs have paths."""
    pool = [rec for rec in records if rec.get("cve_language") == language]

    ready: list[tuple[int, dict, Path, Path]] = []
    no_db = 0
    for rec in pool:
        slim = slim_record(rec)
        slug = folder_slug(rec["cve_id"], rec.get("project") or "")
        source = dest_for(layout.repos, slim)
        db_path = layout.dbs / slug
        if not db_looks_complete(db_path):
            no_db += 1
            continue
        ready.append((repo_size_bytes(source), rec, source, db_path))
    ready.sort(key=lambda t: (t[0] == 0, t[0], t[1]["cve_id"]))

    with_paths = {
        rec["cve_id"]
        for _, rec, _, _ in ready
        if has_pf1_paths(layout, folder_slug(rec["cve_id"], rec.get("project") or ""))
    }
    log(
        f"[pc2] pool={len(pool)} with_database={len(ready)} no_database={no_db} "
        f"already_have_paths={len(with_paths)} target={target or 'all'}"
    )

    layout.paths.mkdir(parents=True, exist_ok=True)
    for _, rec, source, _db in ready:
        if target is not None and len(with_paths) >= target:
            log(f"[pc2] reached target of {target} CVEs with PF-1 paths; stopping")
            break
        cve = rec["cve_id"]
        slug = folder_slug(cve, rec.get("project") or "")
        if cve in with_paths:
            continue

        runnable = [c for c in expand_cwes(rec.get("cwe_id")) if cwe_has_queries(c, language, query_packs)]
        if not runnable:
            warn(f"[pc2] {slug}: no {language} query pack for {rec.get('cwe_id')}")
            continue
        try:
            hunks_path = write_augmentation_hunks(
                layout, slug, build_augmentation_hunks(rec, source, layout, cs2_model)
            )
        except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
            warn(f"[pc2] {slug}: hunk augmentation failed: {exc}")
            continue

        for cwe in runnable:
            if (layout.paths / slug / f"processed_paths_{cwe.lower()}.json").is_file():
                continue
            rc = _run_pipeline(
                codeql=codeql,
                layout=layout,
                language=language,
                slug=slug,
                cwe=cwe,
                hunks_path=hunks_path,
                threads=threads,
                ram=ram,
                query_packs=query_packs,
            )
            if rc != 0:
                warn(f"[pc2] {slug} {cwe} exited with {rc}")

        if has_pf1_paths(layout, slug):
            with_paths.add(cve)
            log(f"[pf1] {cve} has overlapping paths ({len(with_paths)} so far)")

    log(f"[pf1] CVEs with hunk-overlapping paths: {len(with_paths)}")
    return with_paths


def pc2_ids(layout: Layout, records: list[dict]) -> set[str]:
    """CVEs where PC-2 reported at least one taint path (before PF-1 overlap)."""
    found: set[str] = set()
    for rec in records:
        slug = folder_slug(rec["cve_id"], rec.get("project") or "")
        folder = layout.paths / slug
        if not folder.is_dir():
            continue
        for path in folder.glob("raw_paths_*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, list) and data:
                found.add(rec["cve_id"])
                break
    return found
