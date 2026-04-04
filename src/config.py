from dataclasses import dataclass
from pathlib import Path
from typing import Literal


LanguageOption = Literal["Java", "Python", "all"]
PromptMode = Literal["llmql", "baseline", "all"]
TaskName = Literal["rq1", "negative"]


PROJECT_ROOT = Path(__file__).resolve().parent.parent

PROMPT_TEMPLATES_DIR = PROJECT_ROOT / "prompt_templates"
DEFAULT_LLMQL_PROMPT_PATH = PROMPT_TEMPLATES_DIR / "llmql_prompt.txt"
DEFAULT_BASELINE_PROMPT_PATH = PROMPT_TEMPLATES_DIR / "baseline_prompt.txt"

DEFAULT_PATHVUL_DATASET_DIR = PROJECT_ROOT / "data" / "PathVul"
DEFAULT_NEGATIVE_DATASET_DIR = PROJECT_ROOT / "data" / "negative_samples"

DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"
DEFAULT_RQ1_OUT_DIR = DEFAULT_OUTPUT_DIR / "pathvul_run_logs"
DEFAULT_NEGATIVE_OUT_DIR = DEFAULT_OUTPUT_DIR / "negative_samples_run_logs"


@dataclass(slots=True)
class RunConfig:
    task: TaskName = "rq1"
    language: LanguageOption = "all"

    cve: str | None = None
    run_all_cves: bool = False

    model: str = "gpt-4o"
    provider: str = "openai"
    prompt_mode: PromptMode = "all"
    actual_label: int = 1

    dataset_dir: Path | None = None
    out_dir: Path | None = None
    llmql_prompt_path: Path = DEFAULT_LLMQL_PROMPT_PATH
    baseline_prompt_path: Path = DEFAULT_BASELINE_PROMPT_PATH

    def __post_init__(self) -> None:
        self.llmql_prompt_path = Path(self.llmql_prompt_path)
        self.baseline_prompt_path = Path(self.baseline_prompt_path)

        if self.dataset_dir is None:
            self.dataset_dir = (
                DEFAULT_PATHVUL_DATASET_DIR
                if self.task == "rq1"
                else DEFAULT_NEGATIVE_DATASET_DIR
            )
        else:
            self.dataset_dir = Path(self.dataset_dir)

        if self.out_dir is None:
            self.out_dir = (
                DEFAULT_RQ1_OUT_DIR
                if self.task == "rq1"
                else DEFAULT_NEGATIVE_OUT_DIR
            )
        else:
            self.out_dir = Path(self.out_dir)

        allowed_tasks = {"rq1", "negative"}
        if self.task not in allowed_tasks:
            raise ValueError(
                f"Invalid task: {self.task!r}. Expected one of {sorted(allowed_tasks)}."
            )

        allowed_languages = {"Java", "Python", "all"}
        if self.language not in allowed_languages:
            raise ValueError(
                f"Invalid language: {self.language!r}. "
                f"Expected one of {sorted(allowed_languages)}."
            )

        allowed_prompt_modes = {"llmql", "baseline", "all"}
        if self.prompt_mode not in allowed_prompt_modes:
            raise ValueError(
                f"Invalid prompt_mode: {self.prompt_mode!r}. "
                f"Expected one of {sorted(allowed_prompt_modes)}."
            )

        if self.task == "rq1":
            if self.run_all_cves and self.cve:
                raise ValueError("Use either `cve` or `run_all_cves=True`, not both.")
            if not self.run_all_cves and (self.cve is None or not self.cve.strip()):
                raise ValueError("For task='rq1', provide a CVE unless run_all_cves=True.")

        if self.task == "negative":
            if self.cve is not None:
                raise ValueError("For task='negative', `cve` should be None.")
            if self.run_all_cves:
                raise ValueError("For task='negative', `run_all_cves` should be False.")

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

    def active_languages(self) -> list[str]:
        if self.language == "all":
            return ["Java", "Python"]
        return [self.language]