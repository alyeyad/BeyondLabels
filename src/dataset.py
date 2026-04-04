import json
from pathlib import Path
from typing import Iterable


def find_cve(cve: str, dataset_dir: Path) -> tuple[str | None, str | None]:
    """
    Find the CVE folder under Java or Python.

    Returns:
        (folder_name, language) if found, otherwise (None, None)
    """
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


def get_file_combinations(
    cve_folder: str,
    language: str,
    dataset_dir: Path,
) -> list[list[str]] | None:
    """
    Load the annotated input file combinations for a CVE.
    """
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
    """
    Flatten nested file combinations into a unique set of relative file paths.
    """
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
    """
    Read all unique source files referenced by the file combinations.

    Returns:
        A mapping from relative dataset path to file contents.
    """
    file_contents: dict[str, str] = {}
    file_set = flatten_file_combinations(file_combinations)

    for relative_path in file_set:
        full_path = dataset_dir / language / slug / "source" / Path(relative_path)

        try:
            file_contents[relative_path] = full_path.read_text(encoding="utf-8")
        except Exception as exc:
            print(f"[WARN] Could not read {full_path}: {exc}")

    return file_contents