import json
from pathlib import Path
from typing import Any


SUPPORTED_SOURCE_SUFFIXES = {".py", ".java"}


def list_sample_folders(dataset_dir: Path, language: str) -> list[Path]:
    """
    Return all sample folders for a given language under the negative-samples dataset.
    Example:
        dataset_dir / "Python" / "file_4"
    """
    root = dataset_dir / language
    if not root.exists():
        return []

    return sorted(
        [entry for entry in root.iterdir() if entry.is_dir()],
        key=lambda p: p.name,
    )


def find_source_and_metadata(sample_dir: Path) -> tuple[Path | None, Path | None]:
    """
    Find the single source file and optional JSON metadata file inside a sample folder.
    """
    source_file: Path | None = None
    metadata_file: Path | None = None

    for entry in sorted(sample_dir.iterdir(), key=lambda p: p.name):
        if entry.is_file():
            if entry.suffix.lower() in SUPPORTED_SOURCE_SUFFIXES and source_file is None:
                source_file = entry
            elif entry.suffix.lower() == ".json" and metadata_file is None:
                metadata_file = entry

    return source_file, metadata_file


def read_single_source_file(source_path: Path) -> dict[str, str]:
    """
    Read one source file and return it in the same shape expected by construct_prompt().
    """
    return {
        source_path.name: source_path.read_text(encoding="utf-8")
    }


def read_metadata_file(metadata_path: Path | None) -> dict[str, Any] | None:
    """
    Read optional metadata JSON for a sample.
    """
    if metadata_path is None or not metadata_path.exists():
        return None

    with metadata_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_sample_record(sample_dir: Path) -> dict[str, Any] | None:
    """
    Build a record describing one sample folder.

    Returns:
        {
            "sample_id": "file_4",
            "source_path": Path(...),
            "metadata_path": Path(...) | None,
            "metadata": {...} | None,
        }
    """
    source_path, metadata_path = find_source_and_metadata(sample_dir)
    if source_path is None:
        return None

    return {
        "sample_id": sample_dir.name,
        "source_path": source_path,
        "metadata_path": metadata_path,
        "metadata": read_metadata_file(metadata_path),
    }