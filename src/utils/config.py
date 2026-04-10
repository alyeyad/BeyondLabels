from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


LanguageOption = Literal["Java", "Python", "all"]
PromptMode = Literal["llmpath", "baseline", "all"]
TaskName = Literal["rq1", "negative"]


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

PROMPT_TEMPLATES_DIR = PROJECT_ROOT / "prompt_templates"
DEFAULT_LLMPATH_PROMPT_PATH = PROMPT_TEMPLATES_DIR / "llmpath_prompt.txt"
DEFAULT_BASELINE_PROMPT_PATH = PROMPT_TEMPLATES_DIR / "baseline_prompt.txt"

DEFAULT_CVEPATH_DATASET_DIR = PROJECT_ROOT / "data" / "CVEPath"
DEFAULT_NEGATIVE_DATASET_DIR = PROJECT_ROOT / "data" / "negative_samples"

DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"
DEFAULT_LLMPATH_RUNS_OUTPUT_DIR = DEFAULT_OUTPUT_DIR / "runs"

DEFAULT_ANALYSIS_LOGS_DIR = DEFAULT_LLMPATH_RUNS_OUTPUT_DIR
DEFAULT_ANALYSIS_OUT_DIR = DEFAULT_OUTPUT_DIR / "analysis"

DEFAULT_THRESHOLDS = [0.25, 0.5, 0.75, 1.0]
DEFAULT_FEATURES = ["realPathLen", "numInputFiles", "numInputTokens", "numInputLines"]

DEFAULT_ANALYSIS_MODEL = "claude-sonnet-4-5"

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
    llmpath_prompt_path: Path = DEFAULT_LLMPATH_PROMPT_PATH
    baseline_prompt_path: Path = DEFAULT_BASELINE_PROMPT_PATH

    def __post_init__(self) -> None:
        self.llmpath_prompt_path = Path(self.llmpath_prompt_path)
        self.baseline_prompt_path = Path(self.baseline_prompt_path)

        if self.dataset_dir is None:
            self.dataset_dir = (
                DEFAULT_CVEPATH_DATASET_DIR
                if self.task == "rq1"
                else DEFAULT_NEGATIVE_DATASET_DIR
            )
        else:
            self.dataset_dir = Path(self.dataset_dir)

        if self.out_dir is None:
            self.out_dir = DEFAULT_LLMPATH_RUNS_OUTPUT_DIR
        else:
            self.out_dir = Path(self.out_dir)

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

        if self.prompt_mode in {"llmpath", "all"} and not self.llmpath_prompt_path.exists():
            raise FileNotFoundError(
                f"LLMPath prompt file does not exist: {self.llmpath_prompt_path}"
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

@dataclass(slots=True)
class AnalysisConfig:
    logs_dir: Path = DEFAULT_ANALYSIS_LOGS_DIR
    cvepath_dataset_dir: Path = DEFAULT_CVEPATH_DATASET_DIR
    negative_dataset_dir: Path = DEFAULT_NEGATIVE_DATASET_DIR
    output_dir: Path = DEFAULT_ANALYSIS_OUT_DIR

    target_cwes: tuple[int] = (22, 20, 94, 502)
    recursive: bool = True
    analysis_model: str = DEFAULT_ANALYSIS_MODEL
    thresholds: list[float] = field(default_factory=lambda: list(DEFAULT_THRESHOLDS))
    features_to_test: list[str] = field(default_factory=lambda: DEFAULT_FEATURES)

    def __post_init__(self) -> None:
        self.logs_dir = Path(self.logs_dir)
        self.cvepath_dataset_dir = Path(self.cvepath_dataset_dir)
        self.negative_dataset_dir = Path(self.negative_dataset_dir)
        self.output_dir = Path(self.output_dir)

    def validate_paths(self) -> None:
        if not self.logs_dir.exists():
            raise FileNotFoundError(f"Logs directory does not exist: {self.logs_dir}")
        if not self.cvepath_dataset_dir.exists():
            raise FileNotFoundError(f"CVEPath dataset directory does not exist: {self.cvepath_dataset_dir}")
        if not self.negative_dataset_dir.exists():
            raise FileNotFoundError(f"Negative dataset directory does not exist: {self.negative_dataset_dir}")

        (self.output_dir / "data").mkdir(parents=True, exist_ok=True)