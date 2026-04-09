#!/usr/bin/env python3
"""Build frontend data for the PathVUL dataset viewer.

Usage:
    python scripts/build_pathvul_viewer_data.py \
        --dataset-root data/PathVul \
        --output-dir backend/data
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re


def derive_project_url(meta: dict) -> str | None:
    project = meta.get("project")
    if isinstance(project, str) and "/" in project:
        return f"https://github.com/{project}"

    html_url = meta.get("html_url") or ""
    match = re.match(r"^(https://github\\.com/[^/]+/[^/]+)/commit/", html_url)
    if match:
        return match.group(1)

    return None


def build_dataset(pathvul_root: pathlib.Path) -> dict:
    cves: list[dict] = []
    total_paths = 0
    total_nodes = 0

    for language_dir in sorted(p for p in pathvul_root.iterdir() if p.is_dir()):
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
                    "language": language,
                    "project": meta.get("project"),
                    "project_url": derive_project_url(meta),
                    "commit_url": meta.get("html_url") or meta.get("url"),
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

    cves.sort(key=lambda entry: entry["id"])

    return {
        "generated_from": str(pathvul_root),
        "summary": {
            "total_cves": len(cves),
            "total_paths": total_paths,
            "total_nodes": total_nodes,
            "languages": sorted({cve["language"] for cve in cves}),
        },
        "cves": cves,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", default="data/PathVul", help="Root PathVUL dataset directory")
    parser.add_argument("--output-dir", default="backend/data", help="Where to write the viewer data files")
    args = parser.parse_args()

    dataset_root = pathlib.Path(args.dataset_root)
    output_dir = pathlib.Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset = build_dataset(dataset_root)
    json_text = json.dumps(dataset, ensure_ascii=False)

    (output_dir / "pathvul_viewer_data.json").write_text(json_text, encoding="utf-8")
    (output_dir / "pathvul_viewer_data.js").write_text(
        "window.PATHVUL_DATA = " + json_text + ";",
        encoding="utf-8",
    )

    print(f"Wrote {output_dir / 'pathvul_viewer_data.json'}")
    print(f"Wrote {output_dir / 'pathvul_viewer_data.js'}")


if __name__ == "__main__":
    main()
