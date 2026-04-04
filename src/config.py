from dataclasses import dataclass, field
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROMPT_TEMPLATES_DIR = PROJECT_ROOT / "prompt_templates"

DEFAULT_LLMQL_PROMPT_PATH = PROMPT_TEMPLATES_DIR / "llmql_prompt.txt"
DEFAULT_BASELINE_PROMPT_PATH = PROMPT_TEMPLATES_DIR / "baseline_prompt.txt"


@dataclass(slots=True)
class RunConfig:
    dataset_dir: Path
    cve: str | None = None
    run_all_cves: bool = False

    model: str = "gpt-4o"
    provider: str = "openai"
    out_dir: Path = Path("output")
    prompt_mode: str = "all"
    actual_label: bool = True

    llmql_prompt_path: Path = field(default_factory=lambda: DEFAULT_LLMQL_PROMPT_PATH)
    baseline_prompt_path: Path = field(default_factory=lambda: DEFAULT_BASELINE_PROMPT_PATH)

    def __post_init__(self) -> None:
        self.dataset_dir = Path(self.dataset_dir)
        self.out_dir = Path(self.out_dir)
        self.llmql_prompt_path = Path(self.llmql_prompt_path)
        self.baseline_prompt_path = Path(self.baseline_prompt_path)

        allowed_prompt_modes = {"llmql", "baseline", "all"}
        if self.prompt_mode not in allowed_prompt_modes:
            raise ValueError(
                f"Invalid prompt_mode: {self.prompt_mode!r}. "
                f"Expected one of {sorted(allowed_prompt_modes)}."
            )

        if self.run_all_cves and self.cve:
            raise ValueError("Use either `cve` or `run_all_cves=True`, not both.")

        if not self.run_all_cves and (self.cve is None or not self.cve.strip()):
            raise ValueError("You must provide a CVE unless run_all_cves=True.")

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