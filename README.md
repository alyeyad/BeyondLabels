# BeyondLabels

This repository contains the datasets and replication package for the paper: ***Beyond Labels: Can LLMs Reconstruct Vulnerability Paths?***

It supports three main workflows:

- **PathVul runs**: evaluate models on vulnerable multi-file CVE examples.
- **Negative-sample runs**: evaluate models on non-vulnerable single-file samples.
- **Log analysis**: aggregate saved logs into CSV summaries and plots.

This README is based on the project files you shared, including the bundled `data/` and `prompt_templates/` directories.

---

## Repository structure

```text
.
├── data/
│   ├── PathVul/
│   │   ├── Java/
│   │   └── Python/
│   └── negative_samples/
│       ├── Java/
│       └── Python/
├── prompt_templates/
│   ├── baseline_prompt.txt
│   └── llmql_prompt.txt
├── requirements.txt
├── scripts/
│   ├── .env.example
│   ├── analyze_runs.py
│   ├── run_llms_on_negative_samples.py
│   └── run_llms_on_pathvul.py
└── src/
    ├── llm_runner/
    ├── log_analyzer/
    ├── log_analysis_pipeline.py
    ├── negative_pipeline.py
    ├── pathvul_pipeline.py
    └── utils/
```

The project writes outputs under:

```text
output/
```

This folder is created automatically when needed.

---

## What the project does

### 1. PathVul experiments
`python scripts/run_llms_on_pathvul.py` runs an LLM on either:
- one selected CVE, or
- all CVEs in the PathVul dataset

It loads prompt templates from `prompt_templates/`, reads source files from `data/PathVul/`, queries the selected provider, and saves one JSON log per run under `output/runs/`.

### 2. Negative-sample experiments
`python scripts/run_llms_on_negative_samples.py` runs the same prompting flow on non-vulnerable single-file examples stored in `data/negative_samples/`.

### 3. Log analysis
`python scripts/analyze_runs.py` reads the saved JSON logs, matches them back to the datasets, and writes CSV tables and plots under `output/analysis/`.

---

## Requirements

- **Python 3.12 recommended**
- A virtual environment
- An API key for the provider you want to use

The project already includes `requirements.txt`.

Install from it rather than trying to recreate dependencies manually.

---

## Setup

### 1. Go to the project root

```bash
cd /path/to/BeyondLabels
```

### 2. Create a virtual environment

#### Linux/macOS

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Create the `.env` file

Copy the example file from `scripts/` into the project root.

#### Linux/macOS

```bash
cp scripts/.env.example .env
```

#### Windows PowerShell

```powershell
Copy-Item scripts/.env.example .env
```

Then open `.env` and fill in the key(s) you need:

```env
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
DEEPSEEK_API_KEY=
OPENROUTER_API_KEY=
```

You only need the key for the provider you will actually use.

---

## Supported providers

The code supports these provider names:

- `openai`
- `anthropic`
- `deepseek`
- `openrouter`

Examples:
- `--provider openai`
- `--provider anthropic`
- `--provider deepseek`
- `--provider openrouter`

If you pass another provider name, the code raises an unsupported-provider error.

---

## Bundled project assets

Unlike a minimal code-only release, the project you shared already includes:

- `prompt_templates/llmql_prompt.txt`
- `prompt_templates/baseline_prompt.txt`
- `data/PathVul/...`
- `data/negative_samples/...`

So after creating the virtual environment and `.env`, you can run the project directly without separately adding datasets or prompt templates.

---

## Default paths used by the code

These defaults come from `src/utils/config.py`:

```text
prompt_templates/llmql_prompt.txt
prompt_templates/baseline_prompt.txt
data/PathVul
data/negative_samples
output/runs
output/analysis
```

The run scripts do **not** currently expose dataset or prompt paths as CLI arguments, so the easiest setup is to keep the repository structure unchanged.

---

## Expected dataset layout

### PathVul

The code expects CVE folders under:

```text
data/PathVul/Java/
data/PathVul/Python/
```

Example:

```text
data/PathVul/
└── Java/
    └── CVE-2021-41110_cwlviewer/
        ├── annotations/
        │   └── input_filenames.json
        └── source/
            └── ...
```

The runner reads file combinations from:

```text
annotations/input_filenames.json
```

and then loads the corresponding files from:

```text
source/
```

### Negative samples

The code expects one folder per sample under:

```text
data/negative_samples/Java/
data/negative_samples/Python/
```

Example:

```text
data/negative_samples/
└── Python/
    ├── file_1/
    │   ├── sample.py
    │   └── metadata.json
    └── file_2/
        └── other_sample.py
```

Each negative-sample folder should contain:
- one source file (`.py` or `.java`)
- optionally one `.json` metadata file

---

## How prompts are built

For each run, the code:

1. loads the selected prompt template
2. replaces `$_LANGUAGE` with the chosen language name
3. concatenates the selected source files into a single input block
4. prefixes lines with line numbers like `L1:`, `L2:`, `L3:`

That means the prompt templates should contain the `$_LANGUAGE` placeholder where the language name is needed.

---

## How to run the project

## Important

Run commands from the **project root**, not from inside `scripts/`.

The scripts append the repository root to `sys.path`, so running from the root avoids import issues.

### 1. Run one PathVul CVE

```bash
python scripts/run_llms_on_pathvul.py \
  --cve CVE-2021-41110 \
  --language Java \
  --model gpt-4o \
  --provider openai \
  --prompt-mode all
```

### 2. Run all PathVul CVEs

```bash
python scripts/run_llms_on_pathvul.py \
  --all-cves \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode all
```

### 3. Run negative samples

```bash
python scripts/run_llms_on_negative_samples.py \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode all
```

### 4. Analyze saved logs

Minimal example:

```bash
python scripts/analyze_runs.py --analysis-model claude-sonnet-4-5
```

Explicit paths example:

```bash
python scripts/analyze_runs.py \
  --logs-dir output/runs \
  --pathvul-dataset-dir data/PathVul \
  --negative-dataset-dir data/negative_samples \
  --output-dir output/analysis \
  --analysis-model claude-sonnet-4-5 \
  --recursive
```

---

## CLI reference

### `run_llms_on_pathvul.py`

```bash
python scripts/run_llms_on_pathvul.py [OPTIONS]
```

Target selection:
- `--cve CVE-...`
- `--all-cves`

Other options:
- `--language {Java,Python,all}`
- `--model MODEL_NAME`
- `--provider PROVIDER_NAME`
- `--prompt-mode {llmql,baseline,all}`
- `--actual-label INT` default: `1`

Notes:
- `--cve` and `--all-cves` are mutually exclusive.
- PathVul runs default to a positive ground-truth label.

### `run_llms_on_negative_samples.py`

```bash
python scripts/run_llms_on_negative_samples.py [OPTIONS]
```

Options:
- `--language {Java,Python,all}`
- `--model MODEL_NAME`
- `--provider PROVIDER_NAME`
- `--prompt-mode {llmql,baseline,all}`
- `--actual-label INT` default: `0`

Notes:
- Negative-sample runs default to a negative ground-truth label.

### `analyze_runs.py`

```bash
python scripts/analyze_runs.py [OPTIONS]
```

Options:
- `--logs-dir PATH`
- `--pathvul-dataset-dir PATH`
- `--negative-dataset-dir PATH`
- `--output-dir PATH`
- `--recursive`
- `--no-recursive`
- `--thresholds FLOAT [FLOAT ...]`
- `--analysis-model MODEL_NAME`

Notes:
- You should use either `--recursive` or `--no-recursive`, not both.
- The default analysis model in the code is `claude-sonnet-4-5`.

---

## Outputs

### Run outputs

The run scripts write JSON logs under:

```text
output/runs/
```

The logs include fields such as:
- task
- language
- model
- provider
- prompt name
- prompt text
- input text
- output text
- reasoning content
- usage
- timestamp

The exact schema differs slightly between PathVul and negative-sample runs.

### Analysis outputs

The analysis script writes under:

```text
output/analysis/
├── data/
└── plots/
```

Examples of generated outputs include CSV summaries and PDF plots.

---

## Suggested first-run workflow

### Smoke test 1: negative samples

This is usually the simplest first test:

```bash
python scripts/run_llms_on_negative_samples.py \
  --language Python \
  --model gpt-4o \
  --provider openai \
  --prompt-mode llmql
```

Then check whether new JSON logs appear in:

```text
output/runs/
```

### Smoke test 2: analysis

After at least one run completes, test the analysis pipeline:

```bash
python scripts/analyze_runs.py --analysis-model claude-sonnet-4-5
```

Then inspect:

```text
output/analysis/data/
output/analysis/plots/
```

---

## Common issues and fixes

### `ModuleNotFoundError: No module named 'src'`

Run the script from the project root:

```bash
python scripts/run_llms_on_pathvul.py ...
```

The scripts already append the repository root to `sys.path`.

### `FileNotFoundError` for prompts or datasets

Make sure you did not move these folders:

```text
prompt_templates/
data/
```

The project uses fixed default paths from `src/utils/config.py`.

### Unsupported provider error

Use one of:

```text
openai
anthropic
deepseek
openrouter
```

### `No CVE found`

Check that:
- the CVE exists under `data/PathVul/Java/` or `data/PathVul/Python/`
- the folder name starts with the CVE identifier

### `No sample folders found`

Check that negative samples are under:

```text
data/negative_samples/Java/
data/negative_samples/Python/
```

---

## Minimal quick start

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp scripts/.env.example .env
# edit .env and add your API key
python scripts/run_llms_on_negative_samples.py \
  --language Python \
  --model gpt-4o \
  --provider openai \
  --prompt-mode llmql
```

---

## Notes

- Keep the repository structure unchanged unless you also update `src/utils/config.py`.
- Run commands from the repository root.
- `output/` is generated automatically.
- The bundled project already includes the datasets and prompt templates.