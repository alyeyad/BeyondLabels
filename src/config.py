from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class RunConfig:
    dataset_dir: Path
    cve: str
    llmql_prompt_path: Path
    baseline_prompt_path: Path
    model: str = "gpt-4o"
    provider: str = "openai"
    out_dir: Path = Path(".")
    prompt_mode: str = "all"   # one of: "llmql", "baseline", "all"
    actual_label: int = 1

    def __post_init__(self) -> None:
        # Normalize path-like inputs in case strings are passed in.
        self.dataset_dir = Path(self.dataset_dir)
        self.llmql_prompt_path = Path(self.llmql_prompt_path)
        self.baseline_prompt_path = Path(self.baseline_prompt_path)
        self.out_dir = Path(self.out_dir)

        allowed_prompt_modes = {"llmql", "baseline", "all"}
        if self.prompt_mode not in allowed_prompt_modes:
            raise ValueError(
                f"Invalid prompt_mode: {self.prompt_mode!r}. "
                f"Expected one of {sorted(allowed_prompt_modes)}."
            )

        if not self.cve or not self.cve.strip():
            raise ValueError("cve must be a non-empty string.")

    def validate_paths(self) -> None:
        if not self.dataset_dir.exists():
            raise FileNotFoundError(f"Dataset directory does not exist: {self.dataset_dir}")

        if self.prompt_mode in {"llmql", "all"} and not self.llmql_prompt_path.exists():
            raise FileNotFoundError(
                f"LLMQL prompt file does not exist: {self.llmql_prompt_path}"
            )

        if self.prompt_mode in {"baseline", "all"} and not self.baseline_prompt_path.exists():
            raise FileNotFoundError(
                f"Baseline prompt file does not exist: {self.baseline_prompt_path}"
            )

        self.out_dir.mkdir(parents=True, exist_ok=True)