from pathlib import Path
from typing import Mapping

from src.utils.config import RunConfig


def load_prompt_file(path: Path) -> str:
    """
    Read and return a prompt template file.
    """
    return path.read_text(encoding="utf-8")


def get_prompts(config: RunConfig) -> dict[str, str]:
    """
    Load the prompt templates requested by the config.
    """
    prompts: dict[str, str] = {}

    if config.prompt_mode in {"llmql", "all"}:
        prompts["llmql"] = load_prompt_file(config.llmql_prompt_path)

    if config.prompt_mode in {"baseline", "all"}:
        prompts["baseline"] = load_prompt_file(config.baseline_prompt_path)

    return prompts


def add_line_numbers_to_content(content: str) -> str:
    """
    Prefix each line with L<line_number>: for easier model referencing.
    """
    return "\n".join(
        f"L{idx}: {line}"
        for idx, line in enumerate(content.splitlines(), start=1)
    )


def build_input_text(files: Mapping[str, str]) -> str:
    """
    Build the multi-file input text block with file separators and line numbers.
    """
    numbered_files = [
        f"===== {filename} =====\n{add_line_numbers_to_content(code)}"
        for filename, code in files.items()
    ]
    return "\n\n".join(numbered_files)


def construct_prompt(
    template: str,
    language: str,
    files: Mapping[str, str],
) -> tuple[str, str]:
    """
    Build the language-specific prompt and the concatenated code input text.
    """
    input_prompt = template.replace("$_LANGUAGE", language.strip().title())
    input_text = build_input_text(files)
    return input_prompt, input_text