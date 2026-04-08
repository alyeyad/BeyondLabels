# PathVul log analysis scripts

This package converts the `examine_claude2.ipynb` notebook into reusable Python files.

## Files

- `analyze_logs.py`: CLI entry point
- `pathvul_log_analysis/io_utils.py`: log loading, dataset lookup, output parsing
- `pathvul_log_analysis/matching.py`: node matching, line matching, LCS matching
- `pathvul_log_analysis/reporting.py`: refined matches, source/sink detection, plots, JSON/CSV export
- `pathvul_log_analysis/stats_utils.py`: complexity metrics and threshold-based statistical tests

## Expected inputs

### Logs directory
A directory of JSON log files where each log contains fields like:
- `language`
- `prompt_name`
- `input`
- `output`
- `item_id` or `group_key`

The `output` can be either:
1. Path-based output with `findings` and `taint_path`
2. File/line-based output with `vulnerable_lines`

### Dataset directory
A PathVul-style dataset root:

```text
DATASET_ROOT/
  Java/
    CVE-.../
      vulnerable_paths_dedup.json
      cve_metadata.json
  Python/
    CVE-.../
      vulnerable_paths_dedup.json
      cve_metadata.json
```

## Usage

```bash
python analyze_runs.py \
  --logs-dir /path/to/logs \
  --dataset-dir /path/to/PathVul \
  --output-dir /path/to/output
```

Recursive scan:

```bash
python analyze_runs.py \
  --logs-dir /path/to/logs \
  --dataset-dir /path/to/PathVul \
  --output-dir /path/to/output \
  --recursive
```

## Main outputs

Written under `output/data/`:
- `excluded_files.json`
- `source_sink_det.json`
- `node_refined_match.json`
- `node_refined_match.csv`
- `node_numeric_df.csv`
- `node_tests_thresholds.json`
- `lcs_refined_match.json`
- `lcs_refined_match.csv`
- `lcs_numeric_df.csv`
- `lcs_tests_thresholds.json`

Written under `output/images/`:
- `cve_vs_nor.png`
- `cve_vs_lcs.png`

## Notes on notebook fixes

This Python version removes a few notebook-specific issues:
- duplicated `load_cve_data`
- hardcoded `prompt_1` in source/sink detection
- noisy debug print inside best-match selection
- LCS processing is driven by `output_format == "path"` instead of a hardcoded prompt label


## Latest output files
- `data/combined_refined_match.csv`: single CSV with both NOR (`overlap`) and LCS (`lcs_overlap`) results side by side, plus `model` from each log.
- `data/node_refined_match.csv`: NOR-focused detailed table.
- `data/lcs_refined_match.csv`: LCS-focused detailed table.
