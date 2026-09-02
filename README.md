# BeyondLabels

This repository contains the datasets and replication package for the paper: ***Beyond Labels: Evaluating LLMs on Vulnerable-Path Reconstruction***

It supports three main workflows:

- **CVEPath runs**: evaluate models on vulnerable multi-file CVE examples (the 105-CVE study set, the identifier-masked copy of that set, or the held-out 14-CVE post-cutoff set). Optionally append same-repo distractor files (`k` = 1, 3, or 5).
- **Negative-sample runs**: evaluate models on non-vulnerable single-file samples.
- **Log analysis**: analyze model run logs into CSV summaries and plots.

CVEPath runs default to **4 repetitions** per query (`--runs 4`, `--temperature 0.2`, `--seed 1000`). Use `--runs 1 --temperature 0.0` to reproduce the original single-run baseline.

---
## Table of contents

- [Repository structure](#repository-structure)
- [What the project does](#what-the-project-does)
  - [1. CVEPath experiments](#1-cvepath-experiments)
  - [2. Negative-sample experiments](#2-negative-sample-experiments)
  - [3. Log analysis](#3-log-analysis)
- [Requirements](#requirements)
- [Setup](#setup)
  - [1. Go to the project root](#1-go-to-the-project-root)
  - [2. Create a virtual environment](#2-create-a-virtual-environment)
    - [Linux/macOS](#linuxmacos)
    - [Windows PowerShell](#windows-powershell)
  - [3. Create the `.env` file](#3-create-the-env-file)
- [Supported providers](#supported-providers)
- [Datasets Layout](#datasets-layout)
  - [CVEPath](#cvepath)
    - [`input_filenames.json`](#input_filenamesjson)
    - [`cve_metadata.json`](#cve_metadatajson)
    - [`vulnerable_paths.json`](#vulnerable_pathsjson)
    - [`source/`](#source)
  - [Post-cutoff CVEs](#post-cutoff-cves)
  - [Identifier-masked CVEPath](#identifier-masked-cvepath)
  - [Negative samples](#negative-samples)
- [How to run the project](#how-to-run-the-project)
  - [1. Run one CVEPath CVE](#1-run-one-cvepath-cve)
  - [2. Run all CVEPath CVEs](#2-run-all-cvepath-cves)
  - [3. Run the post-cutoff set](#3-run-the-post-cutoff-set)
  - [4. Run the identifier-masked set](#4-run-the-identifier-masked-set)
  - [5. Clone full repos for distractors](#5-clone-full-repos-for-distractors)
  - [6. Run with distractor files](#6-run-with-distractor-files)
  - [7. Run RQ4 detection](#7-run-rq4-detection)
  - [8. Run negative samples](#8-run-negative-samples)
  - [9. Analyze saved logs](#9-analyze-saved-logs)
- [CLI reference](#cli-reference)
  - [`run_llms_on_cvepath.py`](#run_llms_on_cvepathpy)
  - [`clone_cvepath_repos.py`](#clone_cvepath_repospy)
  - [`run_detection_positives.py`](#run_detection_positivespy)
  - [`run_detection_negatives.py`](#run_detection_negativespy)
  - [`run_llms_on_negative_samples.py`](#run_llms_on_negative_samplespy)
  - [`analyze_runs.py`](#analyze_runspy)
- [Outputs](#outputs)
  - [Run outputs](#run-outputs)
  - [Analysis outputs](#analysis-outputs)

---

## Repository structure

```text
.
├── data/
│   ├── CVEPath/
│   │   ├── Java/
│   │   └── Python/
│   ├── post-cutoff-cves/
│   │   └── Python/
│   ├── CVEPath_obf/
│   │   ├── Java/
│   │   └── Python/
│   └── negative_samples/
│       ├── Java/
│       └── Python/
├── prompt_templates/
│   ├── baseline_prompt.txt
│   └── cvepath_prompt.txt
├── requirements.txt
├── scripts/
│   ├── .env.example
│   ├── analyze_runs.py
│   ├── clone_cvepath_repos.py
│   ├── run_detection_negatives.py
│   ├── run_detection_positives.py
│   ├── run_llms_on_negative_samples.py
│   └── run_llms_on_cvepath.py
└── src/
    ├── llm_runner/
    ├── log_analyzer/
    ├── log_analysis_pipeline.py
    ├── negative_pipeline.py
    ├── negative_pipeline_detect.py
    ├── cvepath_pipeline.py
    ├── cvepath_pipeline_detect.py
    ├── detection_parallel.py
    └── utils/
```

The project writes outputs under:

```text
output/
```

This folder is created automatically when needed.

---

## What the project does

### 1. CVEPath experiments
`python scripts/run_llms_on_cvepath.py` runs an LLM on either:
- one selected CVE, or
- all CVEs in the CVEPath dataset

It loads prompt templates from `prompt_templates/`, reads source files from `data/CVEPath/` (or `data/CVEPath_obf/` / `data/post-cutoff-cves/` if you pass `--dataset-dir`), queries the selected provider, and saves one JSON log per run under `output/runs/`. With `--distractors k` (`k` = 1, 3, or 5) it appends same-language files sampled from full vulnerable-commit checkouts under `output/original_repos/` (built by `scripts/clone_cvepath_repos.py`). `k = 0` (the default) does not need those checkouts.

### 2. Negative-sample experiments
`python scripts/run_llms_on_negative_samples.py` runs the same prompting flow on non-vulnerable single-file examples stored in `data/negative_samples/`.

### 3. Log analysis
`python scripts/analyze_runs.py` reads the saved JSON logs, matches them back to the datasets, and writes CSV tables and plots under `output/analysis/`.

---

## Requirements

- **Python 3.12 recommended**
- A virtual environment
- An API key for the LLM provider(s) you want to use

The project already includes `requirements.txt`.

Install from it rather than trying to recreate dependencies manually.

---

## Setup

### 1. Go to the project root

```bash
cd /path/to/repo
```

### 2. Create a virtual environment

#### Linux/macOS

```bash
python -m venv .venv
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

Copy the example file from `scripts/` into the same folder under the name `.env`

#### Linux/macOS

```bash
cp scripts/.env.example scripts/.env
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

---

## Datasets Layout

### CVEPath

The CVEPath dataset is organized by programming language, then by CVE instance. Each CVE folder contains:

- an `annotations/` directory with the structured metadata used by the project
- a `source/` directory with the vulnerable project version files that are passed to the LLM

The dataset can be visualized using our [visualization and manual analysis webpage](https://alyeyad.github.io/BeyondLabels/)

Example:

```text
data/CVEPath/
└── Java/
    └── <CVE_ID>_<PROJECT_NAME>/
        ├── annotations/
        │   ├── input_filenames.json
        │   ├── vulnerable_paths.json
        │   └── cve_metadata.json
        └── source/
            └── ...
```

#### `input_filenames.json`

This file defines the **file combinations** that the vulnerable paths traverse. These combinations are what the runner uses to decide which source files to concatenate and pass to the LLM as input.

Structure:

```json
{
  "files": [
    [
      <PATH1_FROM_REPOSITORY_ROOT>,
      <PATH2_FROM_REPOSITORY_ROOT>,
      ...
    ],
    ...
  ]
}
```

Meaning:
- the top-level key is `files`
- each item inside `files` is one candidate file combination
- each file combination is a list of relative file paths under the CVE's `source/` directory

In practice, the runner reads one of these combinations, loads the corresponding files from `source/`, adds line numbers, and inserts the result into the chosen prompt template.

#### `cve_metadata.json`

This file stores the **CVE metadata**, taken from the [ReposVul](https://github.com/Eshe0922/ReposVul) or [CWE-Bench-Java](https://github.com/iris-sast/iris) datasets. It provides contextual information about the vulnerability, such as the CVE ID, CWE(s), language, description, severity, relevant commit hashes and changed file contents.

This file is mainly useful for metadata, bookkeeping, and downstream analysis.

#### `vulnerable_paths.json`

This file stores the **reference vulnerable paths** for the CVE, generated by our CVEPath pipeline.

Structure example:

```json
{
  "<UNIQUE-SHA256-HASH>": [
    {
      "line_number": <LINE_NUMBER>,
      "file_name": <PATH_FROM_REPOSITORY_ROOT>,
      "code_snippet": <SOURCE_CODE_LINE>
    },
    ...
  ]
}
```

Meaning:
- each key is a unique identifier for one vulnerable path
- each value is the ordered sequence of nodes in that path
- every node records:
  - `line_number`: the number of the vulnerable line in the file (1-based)
  - `file_name`: the relative path of the file containing that node
  - `code_snippet`: the code line at that node

These paths act as the ground-truth reference during analysis, where model outputs are compared against the expected vulnerable flow.

#### `source/`

This directory contains the actual vulnerable project files for that CVE instance. The relative file paths listed in `input_filenames.json` and `vulnerable_paths.json` are resolved against this folder.

For example, if `input_filenames.json` contains:

```text
src/main/java/com/jamesmurty/utils/XMLBuilder.java
```

then the file is expected at:

```text
data/CVEPath/Java/CVE-2021-41110_cwlviewer/source/src/main/java/com/jamesmurty/utils/XMLBuilder.java
```

### Post-cutoff CVEs

`data/post-cutoff-cves/` is a held-out reconstruction set in the **same folder layout** as CVEPath. It is not mixed into `data/CVEPath/`.

It contains **14 Python CVEs**. Each has an NVD publish date and a fix-commit date strictly after the GPT-5.2 knowledge cutoff (31 August 2025), so the same 14 cases also post-date the other evaluated models. There is no Java split.

The annotation files (`input_filenames.json`, `cve_metadata.json`, `vulnerable_paths.json`) and `source/` tree follow the CVEPath schema above. Metadata is a slim subset (CVE id, CWE, description, language, project, commit, dates, parents). Each `input_filenames.json` has one file combination: every source file that appears on any reference path.

```text
data/post-cutoff-cves/
└── Python/
    └── CVE-2025-10155_picklescan/
        ├── annotations/
        │   ├── input_filenames.json
        │   ├── vulnerable_paths.json
        │   └── cve_metadata.json
        └── source/
            └── ...
```

The 14 instances are:

- `CVE-2025-10155_picklescan`
- `CVE-2025-12060_keras`
- `CVE-2025-61622_fory`
- `CVE-2025-61677_datachain`
- `CVE-2025-61765_python-socketio`
- `CVE-2025-67502_taguette`
- `CVE-2025-67729_lmdeploy`
- `CVE-2026-11529_mysql_mcp_server`
- `CVE-2026-11816_keras`
- `CVE-2026-25632_EPyT-Flow`
- `CVE-2026-27645_changedetection.io`
- `CVE-2026-27953_ormar`
- `CVE-2026-54499_stanza`
- `CVE-2026-8838_amazon-redshift-python-driver`

Point the CVEPath runner at this tree with `--dataset-dir data/post-cutoff-cves` and `--language Python`. Use a separate `--out-dir` so post-cutoff logs are not mixed with the 105-CVE runs.

### Identifier-masked CVEPath

`data/CVEPath_obf/` is a semantics-preserving identifier-masked copy of the **same 105 CVEs** as `data/CVEPath/` (43 Java + 62 Python). It is not mixed into the unmasked tree. Use it for the RQ1 contamination check: rename user-defined identifiers to opaque tokens (`Cls_####` / `Fn_####` / `v_####`), rename files to `file_####.ext`, and redact comments, Python docstrings, CVE IDs, and project-name tokens. Language keywords and a blocklist of standard-library / framework source/sink APIs stay intact.

The annotation files and `source/` tree follow the CVEPath schema. Paths and snippets in `input_filenames.json` and `vulnerable_paths.json` already point at the masked files, so **score these runs against `data/CVEPath_obf`, not `data/CVEPath`**. Each CVE folder also has `obf_map.json` (`file_map` and `ident_map`) for audit; the runner does not read it. Metadata is stripped of CVE descriptions, project names, commits, and diffs.

```text
data/CVEPath_obf/
├── Java/
│   └── CVE-2021-41110_cwlviewer/
│       ├── annotations/
│       │   ├── input_filenames.json
│       │   ├── vulnerable_paths.json
│       │   └── cve_metadata.json
│       ├── obf_map.json
│       └── source/
│           └── file_0001.java
└── Python/
    └── ...
```

Point the CVEPath runner at this tree with `--dataset-dir data/CVEPath_obf`. Use a separate `--out-dir` so masked logs are not mixed with unmasked 105-CVE runs.

### Negative samples

The negative-sample dataset is organized by language, with one folder per sample.

Example:

```text
data/negative_samples/
└── Python/
    ├── file_1/
    │   ├── file_1.py
    │   └── file_1.json
    └── file_2/
        └── ...
└── Java/
    ...
```

Each negative-sample folder should contain:
- one source file (`.py` or `.java`)
- optionally one `.json` metadata file

The negative pipeline reads the source file content and treats the sample as a non-vulnerable example by default.

---

## How to run the project

### 1. Run one CVEPath CVE

```bash
python scripts/run_llms_on_cvepath.py \
  --cve CVE-2021-41110 \
  --language Java \
  --model gpt-4o \
  --provider openai \
  --prompt-mode all
```

### 2. Run all CVEPath CVEs

```bash
python scripts/run_llms_on_cvepath.py \
  --all-cves \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode all
```

### 3. Run the post-cutoff set

Same runner as CVEPath. Pass `--dataset-dir data/post-cutoff-cves` and `--language Python` (all 14 cases are Python).

One CVE:

```bash
python scripts/run_llms_on_cvepath.py \
  --cve CVE-2025-10155 \
  --language Python \
  --model gpt-4o \
  --provider openai \
  --prompt-mode llmpath \
  --dataset-dir data/post-cutoff-cves \
  --out-dir output/runs_post_cutoff
```

All 14 CVEs:

```bash
python scripts/run_llms_on_cvepath.py \
  --all-cves \
  --language Python \
  --model gpt-4o \
  --provider openai \
  --prompt-mode llmpath \
  --dataset-dir data/post-cutoff-cves \
  --out-dir output/runs_post_cutoff
```

Score those logs against the post-cutoff annotations (not `data/CVEPath`):

```bash
python scripts/analyze_runs.py \
  --logs-dir output/runs_post_cutoff \
  --cvepath-dataset-dir data/post-cutoff-cves \
  --negative-dataset-dir data/negative_samples \
  --output-dir output/analysis_post_cutoff \
  --analysis-model claude-sonnet-4-5 \
  --recursive
```

### 4. Run the identifier-masked set

Same runner as CVEPath. Pass `--dataset-dir data/CVEPath_obf`. Score against the masked annotations (not `data/CVEPath`).

One CVE:

```bash
python scripts/run_llms_on_cvepath.py \
  --cve CVE-2021-41110 \
  --language Java \
  --model gpt-4o \
  --provider openai \
  --prompt-mode llmpath \
  --dataset-dir data/CVEPath_obf \
  --out-dir output/runs_obf
```

All 105 CVEs:

```bash
python scripts/run_llms_on_cvepath.py \
  --all-cves \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode llmpath \
  --dataset-dir data/CVEPath_obf \
  --out-dir output/runs_obf
```

```bash
python scripts/analyze_runs.py \
  --logs-dir output/runs_obf \
  --cvepath-dataset-dir data/CVEPath_obf \
  --negative-dataset-dir data/negative_samples \
  --output-dir output/analysis_obf \
  --analysis-model claude-sonnet-4-5 \
  --recursive
```

### 5. Clone full repos for distractors

CVEPath ships only the oracle source files. Distractor sampling needs each project's **full tree at the pre-fix commit**. `scripts/clone_cvepath_repos.py` reads `data/CVEPath/` metadata and writes:

```text
output/original_repos/{Java,Python}/<CVE>_<repo>/
```

That path is the default `--distractor-repos-dir`. The clones are gitignored under `output/` (they are large). Resume-safe: a dest already at the target commit is skipped.

```bash
python scripts/clone_cvepath_repos.py
```

Optional: `--dry-run`, `--limit N`, `--language Python`, `--out PATH`, `--cvepath data/CVEPath`. Set `GITHUB_TOKEN` if GitHub rate-limits anonymous clones.

### 6. Run with distractor files

Same runner as CVEPath. Sample `k` extra same-language files from `output/original_repos/{Java,Python}/<CVE>_<repo>/` (after step 5). The sampler prefers files in the same directory as the shown code, skips tests and empty files, and never uses a file that appears on any reference path of that CVE. Distractors are appended **after** the oracle combination so reference line numbers stay comparable. With the default seed (`1234`), `k = 1` is a prefix of `k = 3` / `k = 5`.

`--distractor-repos-dir` defaults to `output/original_repos`. Required only when `--distractors` is not `0`.

```bash
python scripts/run_llms_on_cvepath.py \
  --all-cves \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode llmpath \
  --distractors 3 \
  --distractor-seed 1234 \
  --out-dir output/runs_e3/k3
```

Score as usual. Matching uses the CVE's reference paths (and the `needed_files` field in each log), not distractor file headers.

```bash
python scripts/analyze_runs.py \
  --logs-dir output/runs_e3/k3 \
  --cvepath-dataset-dir data/CVEPath \
  --negative-dataset-dir data/negative_samples \
  --output-dir output/analysis_e3/k3 \
  --analysis-model claude-sonnet-4-5 \
  --recursive
```

### 7. Run RQ4 detection

RQ4 positives reuse the CVEPath runner's file combinations and distractor sampler, and add `--workers` for parallel API calls. Default prompt mode is `baseline` (LLMPath positives can come from `run_llms_on_cvepath.py`).

```bash
python scripts/run_detection_positives.py \
  --all-cves \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode baseline \
  --out-dir output/runs_detect
```

With distractors (`k > 0`), clone first, then pass `--distractors` (repos default to `output/original_repos`):

```bash
python scripts/run_detection_positives.py \
  --all-cves \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode baseline \
  --distractors 3 \
  --out-dir output/runs_detect_e3/k3
```

Oracle RQ4 negatives (multi-run majority, no distractors):

```bash
python scripts/run_detection_negatives.py \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode all \
  --out-dir output/runs_detect_neg
```

`scripts/run_llms_on_negative_samples.py` remains the original single-run negatives path.

### 8. Run negative samples

```bash
python scripts/run_llms_on_negative_samples.py \
  --language all \
  --model gpt-4o \
  --provider openai \
  --prompt-mode all
```

### 9. Analyze saved logs

Minimal example:

```bash
python scripts/analyze_runs.py --analysis-model claude-sonnet-4-5
```

Explicit paths example:

```bash
python scripts/analyze_runs.py \
  --logs-dir output/runs \
  --cvepath-dataset-dir data/CVEPath \
  --negative-dataset-dir data/negative_samples \
  --output-dir output/analysis \
  --analysis-model claude-sonnet-4-5 \
  --recursive
```

Per-run scores stay in `output/analysis/data/cvepath_results.csv`. `rq1_model_summary.csv` is the **median of runs per CVE**, then the median across CVEs (Table I / E3 / masking). Malformed `taint_path` nodes are skipped rather than crashing the scorer.

---

## CLI reference

### `run_llms_on_cvepath.py`

```bash
python scripts/run_llms_on_cvepath.py [OPTIONS]
```

Target selection:
- `--cve CVE-...`
- `--all-cves`

Other options:
- `--language {Java,Python,all}`
- `--model MODEL_NAME`
- `--provider PROVIDER_NAME`
- `--prompt-mode {llmpath,baseline,all}`
- `--actual-label INT` default: `1`
- `--runs INT` default: `4` (multi-run variance)
- `--temperature FLOAT` default: `0.2` (auto-omitted for reasoning models)
- `--seed INT` default: `1000` (run *i* uses `seed+i` for OpenAI chat models)
- `--distractors STR` default: `0` (E3 distractor count, or `all-in-dir` / `all`)
- `--distractor-seed INT` default: `1234`
- `--distractor-repos-dir PATH` default: `output/original_repos`
- `--dataset-dir PATH` default: `data/CVEPath`
- `--out-dir PATH` default: `output/runs`

Notes:
- `--cve` and `--all-cves` are mutually exclusive.
- CVEPath runs default to a positive ground-truth label.
- Default `--runs 4` and `--temperature 0.2` target variance estimation; use `--runs 1 --temperature 0.0` to reproduce the original single-run baseline.
- For the held-out set use `--dataset-dir data/post-cutoff-cves` and `--language Python`.
- For the identifier-masked set use `--dataset-dir data/CVEPath_obf` and score with `--cvepath-dataset-dir data/CVEPath_obf`.
- For `--distractors` != `0`, run `python scripts/clone_cvepath_repos.py` first. `k = 0` does not need those checkouts.

### `clone_cvepath_repos.py`

```bash
python scripts/clone_cvepath_repos.py [OPTIONS]
```

Options:
- `--cvepath PATH` default: `data/CVEPath`
- `--out PATH` default: `output/original_repos`
- `--language {Java,Python,all}`
- `--limit N`
- `--dry-run`

### `run_detection_positives.py`

```bash
python scripts/run_detection_positives.py [OPTIONS]
```

Same target and distractor flags as `run_llms_on_cvepath.py`, plus `--workers` (default `1`). Default `--prompt-mode` is `baseline`.

### `run_detection_negatives.py`

```bash
python scripts/run_detection_negatives.py [OPTIONS]
```

Oracle RQ4 negatives with `--runs` / `--temperature` / `--seed` / `--workers` / `--out-dir`. Does not take `--distractors`.

### `run_llms_on_negative_samples.py`

```bash
python scripts/run_llms_on_negative_samples.py [OPTIONS]
```

Options:
- `--language {Java,Python,all}`
- `--model MODEL_NAME`
- `--provider PROVIDER_NAME`
- `--prompt-mode {llmpath,baseline,all}`
- `--actual-label INT` default: `0`

Notes:
- Negative-sample runs default to a negative ground-truth label.

### `analyze_runs.py`

```bash
python scripts/analyze_runs.py [OPTIONS]
```

Options:
- `--logs-dir PATH`
- `--cvepath-dataset-dir PATH`
- `--negative-dataset-dir PATH`
- `--output-dir PATH`
- `--recursive`
- `--no-recursive`
- `--thresholds FLOAT [FLOAT ...]`
- `--analysis-model MODEL_NAME`

Notes:
- You should use either `--recursive` or `--no-recursive`, not both.
- The default analysis model in the code is `claude-sonnet-4-5`.
- Model-level NOR/LCNR are the median of per-CVE medians across runs, not the max-NOR run.

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

The exact schema differs slightly between CVEPath and negative-sample runs.

### Analysis outputs

The analysis script writes under:

```text
output/analysis/
├── data/
└── plots/
```

Examples of generated outputs include CSV summaries and PDF plots. `data/cvepath_results.csv` keeps every run; `data/rq1_model_summary.csv` aggregates with median-of-runs per CVE.

---