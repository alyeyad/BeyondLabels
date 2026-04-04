import json
from pathlib import Path
from typing import Iterable


def find_cve(cve: str, dataset_dir: Path) -> tuple[str | None, str | None]:
    search_roots = [("Java", dataset_dir / "Java"), ("Python", dataset_dir / "Python")]

    for language, root in search_roots:
        if not root.exists():
            continue

        candidates = [
            entry.name
            for entry in root.iterdir()
            if entry.is_dir() and entry.name.startswith(cve)
        ]
        if candidates:
            return candidates[0], language

    return None, None


def list_all_cve_folders(dataset_dir: Path) -> list[tuple[str, str]]:
    """
    Return all dataset CVE folders as (folder_name, language).
    Example: ("CVE-2021-41110_log4j", "Java")
    """
    results: list[tuple[str, str]] = []

    for language in ("Java", "Python"):
        root = dataset_dir / language
        if not root.exists():
            continue

        for entry in sorted(root.iterdir(), key=lambda p: p.name):
            if entry.is_dir() and entry.name.startswith("CVE-"):
                results.append((entry.name, language))

    return results


def get_file_combinations(
    cve_folder: str,
    language: str,
    dataset_dir: Path,
) -> list[list[str]] | None:
    path = dataset_dir / language / cve_folder / "annotations" / "input_filenames.json"
    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    files = payload.get("files")
    if not isinstance(files, list):
        return None

    return files


def flatten_file_combinations(file_combinations: Iterable[Iterable[str]]) -> set[str]:
    return {
        relative_path
        for combination in file_combinations
        for relative_path in combination
    }


def read_file_contents(
    dataset_dir: Path,
    language: str,
    slug: str,
    file_combinations: Iterable[Iterable[str]],
) -> dict[str, str]:
    file_contents: dict[str, str] = {}
    file_set = flatten_file_combinations(file_combinations)

    for relative_path in file_set:
        full_path = dataset_dir / language / slug / "source" / Path(relative_path)

        try:
            file_contents[relative_path] = full_path.read_text(encoding="utf-8")
        except Exception as exc:
            print(f"[WARN] Could not read {full_path}: {exc}")

    return file_contents