from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def load_json_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:  # pragma: no cover - defensive logging
        print(f"[load_json_file] Failed to load {path}: {exc}")
        return None


def parse_output_json(output_str: str) -> Optional[Dict[str, Any]]:
    """Parse LLM output that may contain fenced JSON."""
    try:
        cleaned = output_str.strip()
        if "```" in cleaned:
            fence_match = re.search(r"```(?:json|python|java)?\s*(.*?)\s*```", cleaned, re.DOTALL)
            if fence_match:
                cleaned = fence_match.group(1).strip()
            else:
                cleaned = cleaned.replace("```json", "").replace("```python", "")
                cleaned = cleaned.replace("```java", "").replace("```", "").strip()
        return json.loads(cleaned)
    except Exception as exc:  # pragma: no cover - defensive logging
        print(f"[parse_output_json] Failed to parse output JSON: {exc}")
        return None


def extract_cve_id(log_record: Dict[str, Any]) -> str:
    raw = str(log_record.get("item_id", log_record.get("group_key", "")))
    return raw.split("_")[0].split(":")[0].strip()


def extract_needed_files(input_str: str, metadata_or_log: Dict[str, Any]) -> List[str]:
    if "needed_files" in metadata_or_log and metadata_or_log["needed_files"]:
        return list(metadata_or_log["needed_files"])

    pattern = r"===== (.*?) ====="
    return [item.strip() for item in re.findall(pattern, input_str)]


def load_cve_data(dataset_dir: Path, language: str, cve_folder: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    cve_path = dataset_dir / language / cve_folder
    with (cve_path / "annotations" /  "vulnerable_paths.json").open("r", encoding="utf-8") as f:
        real_paths = json.load(f)
    with (cve_path / "annotations" / "cve_metadata.json").open("r", encoding="utf-8") as f:
        metadata = json.load(f)
    return real_paths, metadata


def build_repo_index(dataset_dir: Path, languages: Iterable[str] = ("Java", "Python")) -> Dict[str, List[str]]:
    repo_index: Dict[str, List[str]] = {}
    for language in languages:
        lang_dir = dataset_dir / language
        repo_index[language] = sorted([p.name for p in lang_dir.iterdir() if p.is_dir()]) if lang_dir.exists() else []
    return repo_index


def find_cve_folder(repos: Dict[str, List[str]], language: str, cve_id: str) -> Optional[str]:
    candidates = [folder for folder in repos.get(language, []) if folder.startswith(cve_id)]
    if len(candidates) == 1:
        return candidates[0]
    return None


def iter_log_files(logs_dir: Path, recursive: bool = False) -> Iterable[Path]:
    pattern = "**/*.json" if recursive else "*.json"
    for path in sorted(logs_dir.glob(pattern)):
        if path.is_file():
            yield path


def json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_ready(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_ready(v) for v in value]
    if isinstance(value, tuple):
        return [json_ready(v) for v in value]
    return value
