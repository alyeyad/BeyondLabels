# BeyondLabels

This repository contains the datasets and replication package for the paper: ***Beyond Labels: Evaluating LLMs on Vulnerable-Path Reconstruction***

It supports three main workflows:

- **CVEPath runs**: evaluate models on vulnerable multi-file CVE examples.
- **Negative-sample runs**: evaluate models on non-vulnerable single-file samples.
- **Log analysis**: analyze model run logs into CSV summaries and plots.

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
  - [Negative samples](#negative-samples)
- [How to run the project](#how-to-run-the-project)
  - [1. Run one CVEPath CVE](#1-run-one-cvepath-cve)
  - [2. Run all CVEPath CVEs](#2-run-all-cvepath-cves)
  - [3. Run negative samples](#3-run-negative-samples)
  - [4. Analyze saved logs](#4-analyze-saved-logs)
- [CLI reference](#cli-reference)
  - [`run_llms_on_cvepath.py`](#run_llms_on_cvepathpy)
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
│   ├── run_llms_on_negative_samples.py
│   └── run_llms_on_cvepath.py
└── src/
    ├── llm_runner/
    ├── log_analyzer/
    ├── log_analysis_pipeline.py
    ├── negative_pipeline.py
    ├── cvepath_pipeline.py
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

It loads prompt templates from `prompt_templates/`, reads source files from `data/CVEPath/`, queries the selected provider, and saves one JSON log per run under `output/runs/`.

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
  --cvepath-dataset-dir data/CVEPath \
  --negative-dataset-dir data/negative_samples \
  --output-dir output/analysis \
  --analysis-model claude-sonnet-4-5 \
  --recursive
```

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
- `--actual-label ` default: `1`

Notes:
- `--cve` and `--all-cves` are mutually exclusive.
- CVEPath runs default to a positive ground-truth label.

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

Examples of generated outputs include CSV summaries and PDF plots.

---