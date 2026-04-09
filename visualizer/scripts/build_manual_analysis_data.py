#!/usr/bin/env python3
"""Build frontend manual-analysis data for the PathVUL viewer.

Accepted input styles:
1. A prebuilt JSON file shaped like the old viewer's full_dataset.json:
   {
     "CVE-2021-41110": {
       "real_path": [...],
       "output_path": [...],
       "nor_metrics": {...},
       "lcnr_metrics": {...}
     },
     ...
   }

2. A directory containing one or more JSON files where each file is either:
   - the full mapping above, or
   - a single entry containing keys like real_path/output_path and a cve/cve_id field.

Outputs:
- backend/data/manual_analysis_dataset.js
- backend/data/manual_analysis_index.js
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def looks_like_entry(obj: Any) -> bool:
    return isinstance(obj, dict) and ("real_path" in obj or "output_path" in obj)


def normalize_entry(cve: str, obj: dict[str, Any]) -> dict[str, Any]:
    out = dict(obj)
    out.setdefault("cve", cve)
    return out


def load_from_json_file(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, dict):
        if all(isinstance(k, str) and looks_like_entry(v) for k, v in data.items()):
            return {k: normalize_entry(k, v) for k, v in data.items()}

        if looks_like_entry(data):
            cve = str(data.get("cve") or data.get("cve_id") or path.stem)
            return {cve: normalize_entry(cve, data)}

    raise ValueError(f"Unsupported manual-analysis JSON shape: {path}")


def load_from_dir(path: Path) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for fp in sorted(path.rglob("*.json")):
        try:
            merged.update(load_from_json_file(fp))
        except Exception:
            continue
    return merged


def write_outputs(data: dict[str, dict[str, Any]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_text = json.dumps(data, ensure_ascii=False)
    index_text = json.dumps({cve: True for cve in sorted(data)}, ensure_ascii=False)
    (output_dir / "manual_analysis_dataset.js").write_text(
        "window.MANUAL_ANALYSIS_DATA = " + json_text + ";\n", encoding="utf-8"
    )
    (output_dir / "manual_analysis_index.js").write_text(
        "window.MANUAL_ANALYSIS_INDEX = " + index_text + ";\n", encoding="utf-8"
    )
    print(f"Wrote {output_dir / 'manual_analysis_dataset.js'}")
    print(f"Wrote {output_dir / 'manual_analysis_index.js'}")


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input-json", help="Prebuilt full_dataset.json or one single-entry JSON")
    group.add_argument("--input-dir", help="Directory containing one or more manual-analysis JSON files")
    parser.add_argument("--output-dir", default="backend/data", help="Output directory for JS data files")
    args = parser.parse_args()

    if args.input_json:
        data = load_from_json_file(Path(args.input_json))
    else:
        data = load_from_dir(Path(args.input_dir))

    write_outputs(data, Path(args.output_dir))


if __name__ == "__main__":
    main()
