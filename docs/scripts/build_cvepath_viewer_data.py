#!/usr/bin/env python3
"""Build frontend data for the CVEPath dataset viewer.

Usage (from the replication-package root or any cwd):

    python docs/scripts/build_cvepath_viewer_data.py

Defaults scan ``data/CVEPath`` and ``data/post-cutoff-cves`` and write
``docs/backend/data/cvepath_viewer_data.{json,js}``.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re

DOCS_DIR = pathlib.Path(__file__).resolve().parent.parent
PACKAGE_ROOT = DOCS_DIR.parent

COLLECTION_LABELS = {
    "CVEPath": "CVEPath",
    "post-cutoff-cves": "post-cutoff",
}


def derive_project_url(meta: dict) -> str | None:
    project = meta.get("project")
    if isinstance(project, str) and "/" in project:
        return f"https://github.com/{project}"

    html_url = meta.get("html_url") or ""
    match = re.match(r"^(https://github\.com/[^/]+/[^/]+)/commit/", html_url)
    if match:
        return match.group(1)

    return None


def derive_commit_url(meta: dict) -> str | None:
    url = meta.get("html_url")
    if isinstance(url, str) and url:
        return url

    project = meta.get("project")
    commit_id = meta.get("commit_id")
    if isinstance(project, str) and "/" in project and commit_id:
        return f"https://github.com/{project}/commit/{commit_id}"

    return meta.get("url") or None


def collection_label(root: pathlib.Path) -> str:
    return COLLECTION_LABELS.get(root.name, root.name)


def ingest_root(dataset_root: pathlib.Path, collection: str) -> tuple[list[dict], int, int]:
    cves: list[dict] = []
    total_paths = 0
    total_nodes = 0

    if not dataset_root.is_dir():
        return cves, total_paths, total_nodes

    for language_dir in sorted(p for p in dataset_root.iterdir() if p.is_dir()):
        language = language_dir.name

        for cve_dir in sorted(p for p in language_dir.iterdir() if p.is_dir()):
            annotations_dir = cve_dir / "annotations"
            meta_fp = annotations_dir / "cve_metadata.json"
            input_fp = annotations_dir / "input_filenames.json"
            paths_fp = annotations_dir / "vulnerable_paths.json"

            if not (meta_fp.exists() and input_fp.exists() and paths_fp.exists()):
                continue

            meta = json.loads(meta_fp.read_text(encoding="utf-8"))
            input_files = json.loads(input_fp.read_text(encoding="utf-8"))
            vulnerable_paths = json.loads(paths_fp.read_text(encoding="utf-8"))

            file_combinations = input_files.get("files", []) if isinstance(input_files, dict) else []

            paths: list[dict] = []
            for path_hash, nodes in vulnerable_paths.items():
                unique_files: list[str] = []
                seen_files: set[str] = set()

                for node in nodes:
                    file_name = node.get("file_name") or ""
                    if file_name and file_name not in seen_files:
                        unique_files.append(file_name)
                        seen_files.add(file_name)

                paths.append(
                    {
                        "hash": path_hash,
                        "node_count": len(nodes),
                        "files": unique_files,
                        "nodes": [
                            {
                                "line_number": node.get("line_number"),
                                "file_name": node.get("file_name"),
                                "code_snippet": node.get("code_snippet", ""),
                            }
                            for node in nodes
                        ],
                    }
                )
                total_paths += 1
                total_nodes += len(nodes)

            paths.sort(key=lambda entry: entry["hash"])

            cves.append(
                {
                    "id": meta.get("cve_id") or cve_dir.name.split("_")[0],
                    "dir_name": cve_dir.name,
                    "collection": collection,
                    "language": language,
                    "project": meta.get("project"),
                    "project_url": derive_project_url(meta),
                    "commit_url": derive_commit_url(meta),
                    "commit_id": meta.get("commit_id"),
                    "cwes": meta.get("cwe_id") or [],
                    "publish_date": meta.get("publish_date"),
                    "cvss": meta.get("cvss"),
                    "description": meta.get("cve_description") or meta.get("details") or "",
                    "file_combo_count": len(file_combinations),
                    "path_count": len(paths),
                    "input_file_combinations": file_combinations,
                    "paths": paths,
                }
            )

    return cves, total_paths, total_nodes


def build_dataset(dataset_roots: list[pathlib.Path]) -> dict:
    cves: list[dict] = []
    total_paths = 0
    total_nodes = 0
    seen_ids: set[str] = set()

    for root in dataset_roots:
        root = root.resolve()
        added, n_paths, n_nodes = ingest_root(root, collection_label(root))
        for cve in added:
            if cve["id"] in seen_ids:
                print(f"Skipping duplicate {cve['id']} from {root}")
                continue
            seen_ids.add(cve["id"])
            cves.append(cve)
        total_paths += n_paths
        total_nodes += n_nodes

    cves.sort(key=lambda entry: entry["id"])

    collections: dict[str, int] = {}
    for cve in cves:
        collections[cve["collection"]] = collections.get(cve["collection"], 0) + 1

    return {
        "generated_from": [str(root.resolve()) for root in dataset_roots],
        "summary": {
            "total_cves": len(cves),
            "total_paths": total_paths,
            "total_nodes": total_nodes,
            "languages": sorted({cve["language"] for cve in cves}),
            "collections": collections,
        },
        "cves": cves,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset-root",
        action="append",
        dest="dataset_roots",
        help="CVEPath-layout dataset root. May be repeated. "
        "Default: data/CVEPath and data/post-cutoff-cves.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DOCS_DIR / "backend" / "data"),
        help="Where to write the viewer data files",
    )
    args = parser.parse_args()

    if args.dataset_roots:
        dataset_roots = [pathlib.Path(p) for p in args.dataset_roots]
    else:
        dataset_roots = [
            PACKAGE_ROOT / "data" / "CVEPath",
            PACKAGE_ROOT / "data" / "post-cutoff-cves",
        ]

    output_dir = pathlib.Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset = build_dataset(dataset_roots)
    json_text = json.dumps(dataset, ensure_ascii=False)

    (output_dir / "cvepath_viewer_data.json").write_text(json_text, encoding="utf-8")
    (output_dir / "cvepath_viewer_data.js").write_text(
        "window.PATHVUL_DATA = " + json_text + ";",
        encoding="utf-8",
    )

    summary = dataset["summary"]
    print(f"Wrote {output_dir / 'cvepath_viewer_data.json'}")
    print(f"Wrote {output_dir / 'cvepath_viewer_data.js'}")
    print(
        f"{summary['total_cves']} CVEs, {summary['total_paths']} paths "
        f"({summary.get('collections')})"
    )


if __name__ == "__main__":
    main()
