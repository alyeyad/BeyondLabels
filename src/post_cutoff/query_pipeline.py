#!/usr/bin/env python3
"""PC-1 / PC-2 / PF-1 for one CVE folder and one CWE.

Copied from the study-design pipeline used to build CVEPath, with the query
directories re-homed to the package-local ``query_packs/``. Copies the base and
CWE queries into the run folder, writes ``MySources.qll`` / ``MySinks.qll`` /
``MySummaries.qll`` from the vulnerable hunks (PC-1), runs ``codeql database
analyze`` (PC-2), turns the SARIF code flows into raw paths, and keeps the paths
with maximum vulnerable-hunk overlap (PF-1).

Invoked per CVE by ``src/post_cutoff/run_queries.py``; can also be run directly.
"""
import argparse
import hashlib
import json
import logging
import logging.handlers
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime

try:
    import javalang
except ImportError:
    javalang = None
try:
    import pandas as pd
except ImportError:
    pd = None
try:
    from graphviz import Digraph
    from IPython.display import Image
except ImportError:
    Digraph = None
    Image = None
try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        return iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.post_cutoff.constants import PREDICATES  # noqa: E402

DEFAULT_QUERY_PACKS = PROJECT_ROOT / "query_packs"

PRIMITIVE_TYPES = {
    "void","int","boolean","long","Integer","Boolean","Object",
}

# -----------------------------
# Logging & Cleanup management
# -----------------------------
class CleanupManager:
    """Tracks files/dirs created during this run, and can remove them on failure."""
    def __init__(self, logger: logging.Logger):
        self.files = []
        self.dirs = []
        self.logger = logger

    def track_file(self, path: str | Path):
        p = str(path)
        if p not in self.files:
            self.files.append(p)
        return path

    def track_dir(self, path: str | Path):
        p = str(path)
        if p not in self.dirs:
            self.dirs.append(p)
        return path

    def cleanup(self):
        # Remove files (ignore errors)
        for f in self.files:
            try:
                if os.path.isfile(f):
                    os.remove(f)
                    self.logger.info(f"[cleanup] removed file: {f}")
            except Exception as e:
                self.logger.warning(f"[cleanup] failed to remove file {f}: {e}")

        # Remove empty dirs (from deepest to shallowest)
        for d in sorted(self.dirs, key=lambda x: len(x), reverse=True):
            try:
                if os.path.isdir(d) and not os.listdir(d):
                    os.rmdir(d)
                    self.logger.info(f"[cleanup] removed empty dir: {d}")
            except Exception as e:
                self.logger.debug(f"[cleanup] cannot remove dir {d}: {e}")

def setup_logging(base_op_dir: Path, proj_folder_name: str, level: str) -> logging.Logger:
    base_op_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = base_op_dir / proj_folder_name / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    logfile = logs_dir / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logger = logging.getLogger("codeql_pipeline")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(getattr(logging, level.upper(), logging.INFO))
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = logging.handlers.RotatingFileHandler(str(logfile), maxBytes=10_000_000, backupCount=5)
    fh.setLevel(getattr(logging, level.upper(), logging.INFO))
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    logger.info(f"Logging to {logfile}")
    return logger

# -----------------------------
# Original helper functions
# -----------------------------
def plot_call_path(nodes__):
    if Digraph is None or Image is None:
        raise RuntimeError("graphviz/IPython not installed")
    dot = Digraph(comment="Call Path")
    for i_, node__ in enumerate(nodes__):
        dot.node(str(i_), node__, shape="ellipse", width="2", height="1", fontsize="14")
        if i_ > 0:
            dot.edge(str(i_-1), str(i_))
    return Image(dot.pipe(format='png'))

def filter_internal_function_parameters(func_param_path, filtered_params_path, internal_pkg_p):
    def func_parameter_is_candidate(row):
        def func_parameter_has_non_trivial_parameter(row):
            param_types_raw = "" if isinstance(row["parameter_types"], float) else row["parameter_types"]
            param_types = param_types_raw.split(";")
            return any(param_ty not in PRIMITIVE_TYPES for param_ty in param_types)

        def func_parameter_not_on_blacklist(row):
            if row["func"] in {"isEqual","toString","equals","canConvert","compareTo","compare"}:
                return False
            elif "src/test" in row["location"]:
                return False
            else:
                return True

        return func_parameter_not_on_blacklist(row) and func_parameter_has_non_trivial_parameter(row)

    def keep_internal_packages(candidates_df, internal_pkg_path):
        packages = [p.strip() for p in open(internal_pkg_path).readlines()]
        return candidates_df[candidates_df["package"].isin(packages)]

    func_param_candidates = pd.read_csv(func_param_path, keep_default_na=False)
    func_param_candidates = keep_internal_packages(func_param_candidates, internal_pkg_p)
    func_param_candidates = func_param_candidates[func_param_candidates.apply(func_parameter_is_candidate, axis=1)]
    func_param_candidates = func_param_candidates[["package","clazz","func","full_signature","doc"]]
    func_param_candidates.to_csv(filtered_params_path, index=False, header=True, sep=",", encoding="utf-8")

def api_is_candidate(candidate, num_external_apis):
    def api_candidate_has_non_trivial_return(r):
        return r["callstr"].startswith("new ") or r["return_type"] not in PRIMITIVE_TYPES
    def api_candidate_has_non_trivial_parameter(r):
        if r["is_static"]:
            param_types_raw = "" if isinstance(r["parameter_types"], float) else r["parameter_types"]
            return any(pt not in PRIMITIVE_TYPES for pt in param_types_raw.split(";"))
        return True
    def api_candidate_not_on_blacklist(r):
        if r["package"] == "java.util" and r["clazz"] in {"String","EnumSet","LinkedList","List"}: return False
        if r["package"] == "java.io" and r["clazz"] == "PrintStream": return False
        return True
    return api_candidate_not_on_blacklist(candidate) and (api_candidate_has_non_trivial_parameter(candidate) or api_candidate_has_non_trivial_return(candidate))

def extract_arg_names(signature: str):
    match = re.search(r"\(([^)]*)\)", signature)
    if not match: return []
    args_str = match.group(1).strip()
    if not args_str: return []
    arg_names = []
    for arg in [a.strip() for a in args_str.split(",")]:
        parts = arg.split()
        if parts:
            arg_names.append(parts[-1])
    return arg_names

def save_package_names(packages, output_path):
    with open(output_path, "w") as f:
        for pkg in packages:
            f.write(pkg + "\n")

def extract_internal_packages(repo_path):
    package_pattern = re.compile(r'^\s*package\s+([a-zA-Z0-9_.]+)\s*;')
    internal_packages = set()
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            match = package_pattern.match(line)
                            if match:
                                internal_packages.add(match.group(1))
                                break
                except Exception as e:
                    # log at caller
                    pass
    return internal_packages

def filter_invoked_external_apis(source_apis_path_, internal_package_path, repo_path, output_apis_path, logger):
    def keep_external_packages(api_candidates_df, internal_pkg_path):
        packages = [p.strip() for p in open(internal_pkg_path).readlines()]
        return api_candidates_df[~api_candidates_df["package"].isin(packages)]

    external_api_candidates = pd.read_csv(source_apis_path_)
    if not os.path.exists(internal_package_path):
        try:
            packages = extract_internal_packages(repo_path)
            save_package_names(packages, internal_package_path)
            logger.info("[CUSTOM IMPL] Packages fetched and saved.")
        except Exception as e:
            logger.exception(f"Failed computing internal packages: {e}")
            raise

    external_api_candidates = keep_external_packages(external_api_candidates, internal_package_path)
    possible_src_snk_tp = external_api_candidates.apply(lambda row: api_is_candidate(row, len(external_api_candidates)), axis=1)
    external_api_candidates = external_api_candidates[possible_src_snk_tp]
    external_api_candidates = external_api_candidates[["package","clazz","func","full_signature"]].drop_duplicates()
    external_api_candidates.to_csv(output_apis_path, index=False, header=True, sep=',', encoding='utf-8')

def run_codeql_query(db_path_: str, query_path: str, output_path_: str, codeql_path_: str,
                     logger: logging.Logger, output_format_: str = "csv", query_type="query run",
                     threads: int = 6, ram_mb: int = 8192):
    logger.info(f"Running Query | type={query_type} | query={query_path}")
    Path(output_path_).parent.mkdir(parents=True, exist_ok=True)

    if query_type == "database analyze":
        cmdd = [codeql_path_, "database", "analyze", "--rerun", db_path_,
                f"--format={output_format_}", f"--threads={threads}", f"--ram={ram_mb}",
                f"--output={output_path_}", query_path]
    elif query_type == "query run":
        output_path_ = f"{output_path_.split('.', 1)[0]}.bqrs"
        cmdd = [codeql_path_, "query", "run", f"--database={db_path_}",
                f"--output={output_path_}", "--", query_path]
    elif query_type == "bqrs decode":
        bqrs_path = f"{output_path_.split('.', 1)[0]}.bqrs"
        output_path_ = f"{output_path_.split('.', 1)[0]}.{output_format_}"
        cmdd = [codeql_path_, "bqrs", "decode", bqrs_path, f"--format={output_format_}", f"--output={output_path_}"]
    else:
        raise ValueError(f"Unknown query_type: {query_type}")

    # Stream live output
    process = subprocess.Popen(cmdd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for line in process.stdout:
            logger.info(line.rstrip())
    finally:
        process.stdout.close()
        rc = process.wait()

    if rc == 0:
        logger.info(f"✅ Query finished, results at {output_path_}")
        if query_type == "query run":
            # Now decode BQRS
            run_codeql_query(db_path_, query_path, output_path_, codeql_path_, logger,
                             query_type="bqrs decode", output_format_=output_format_, threads=threads, ram_mb=ram_mb)
        elif query_type == "bqrs decode":
            try:
                if bqrs_path and os.path.exists(bqrs_path):
                    os.remove(bqrs_path)
            except Exception as e:
                logger.warning(f"Could not remove temp bqrs: {e}")
    else:
        logger.error(f"❌ Query failed with exit code {rc}")
        raise RuntimeError(f"CodeQL command failed: {' '.join(cmdd)}")
import ast
import os
from typing import Dict, List, Optional, Tuple

# Types
FuncEntry = Tuple[str, int, int]  # (qualname, start, end)

# --- Cache: {abs_path: (mtime, [FuncEntry, ...])}
_FUNC_CACHE: Dict[str, Tuple[float, List[FuncEntry]]] = {}

def _node_span(n: ast.AST) -> Tuple[int, int]:
    start = getattr(n, "lineno", None)
    end = getattr(n, "end_lineno", None)
    if start is None:
        return (0, 0)
    if end is not None:
        return (start, end)
    # Fallback for older Python: scan descendants
    max_line = start
    for ch in ast.walk(n):
        ln = getattr(ch, "lineno", None)
        if isinstance(ln, int) and ln > max_line:
            max_line = ln
    return (start, max_line)

class _FuncCollector(ast.NodeVisitor):
    def __init__(self):
        self.stack: List[str] = []
        self.items: List[FuncEntry] = []

    def visit_ClassDef(self, node: ast.ClassDef):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def _handle_func(self, node):
        start, end = _node_span(node)
        qualname = ".".join(self.stack + [node.name]) if self.stack else node.name
        self.items.append((qualname, start, end))
        # include nested functions
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._handle_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._handle_func(node)

def _index_file(py_file: str) -> List[FuncEntry]:
    """Parse and return all (qualname, start, end) for functions in a file."""
    with open(py_file, "r", encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source, filename=py_file)
    c = _FuncCollector()
    c.visit(tree)
    # Sort by start line to make later searches deterministic
    c.items.sort(key=lambda t: (t[1], t[2], t[0]))
    return c.items

def _get_index(py_file: str) -> List[FuncEntry]:
    """Return cached index for file (rebuild if missing or outdated)."""
    path = os.path.abspath(py_file)
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        # If file disappeared, drop any stale cache and return empty list
        _FUNC_CACHE.pop(path, None)
        return []

    cached = _FUNC_CACHE.get(path)
    if cached is not None and cached[0] == mtime:
        return cached[1]

    # (Re)build
    items = _index_file(path)
    _FUNC_CACHE[path] = (mtime, items)
    return items

def find_function_at_line_cached(py_file: str, line_number: int) -> Tuple[Optional[str], Optional[int]]:
    """
    Return (qualified_function_name, start_line) for the innermost function
    containing `line_number`, using a per-file cache with mtime invalidation.
    """
    try:
        items = _get_index(py_file)
    except SyntaxError:
        return None, None

    # Find all functions that contain the line; pick the most specific
    containing = [it for it in items if it[1] <= line_number <= it[2]]
    if not containing:
        return None, None

    # choose the one with the greatest start (closest/innermost)
    name, start, _ = max(containing, key=lambda t: t[1])
    return name, start

# --- Optional helpers

def preload_files(paths: List[str]) -> None:
    """Warm the cache for a list of files (ignores parse errors)."""
    for p in paths:
        try:
            _get_index(p)
        except SyntaxError:
            pass

def clear_cache() -> None:
    """Clear all cached indexes."""
    _FUNC_CACHE.clear()

def invalidate_file(py_file: str) -> None:
    """Force reindex on next access for this file."""
    _FUNC_CACHE.pop(os.path.abspath(py_file), None)

def get_source_line(location, project_source_code_dir):
    relative_file_url = location["location"]["physicalLocation"]["artifactLocation"]["uri"]
    line_num = location["location"]["physicalLocation"]["region"]["startLine"]
    file_dir = os.path.join(project_source_code_dir, relative_file_url)
    if not os.path.exists(file_dir):
        return ""
    try:
        file_lines = list(open(file_dir, 'r', encoding="utf-8").readlines())
    except Exception:
        return ""
    if line_num > len(file_lines):
        return ""
    return file_lines[line_num - 1]

def get_paths_from_sarif(sarif_path, repo_root, logger, language):
    def is_valid_code_flow(code_flow, repo_root):
        thread_flow = code_flow["threadFlows"][0]
        locations = thread_flow["locations"]
        snk_line = get_source_line(locations[-1], repo_root)
        if ".println(" in snk_line or ".print(" in snk_line:
            return False
        for loc in locations:
            file_url = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
            if "test" in file_url or "anaconda" in file_url:
                return False
        return True

    def find_method_at_line_java(java_file, line_number):
        with open(java_file, "r", encoding="utf-8") as f:
            source = f.read()
        tree = javalang.parse.parse(source)
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                if hasattr(node, 'position') and node.position:
                    start_line = node.position.line
                    if start_line <= line_number:
                        return node.name, start_line
        return None, None

    try:
        tqdm.write("\n===> Loading SARIF file ...")
        with open(sarif_path, encoding="utf-8") as f:
            sarif_data = json.load(f)
        results_list = sarif_data["runs"][0]["results"]
        final_path_list = []

        tqdm.write("\n===> Filtering Invalid Paths ...")
        for result in tqdm(results_list, desc=f"Filtering Invalid Paths", file=sys.stdout):
            if "codeFlows" not in result:
                continue
            flows = result["codeFlows"]
            for flow in flows:
                if is_valid_code_flow(flow, repo_root):
                    final_path_list.append(flow["threadFlows"][0]["locations"])

        tqdm.write("\n===> Processing Relevant Paths ...")
        processed_paths = []
        for path in tqdm(final_path_list, desc=f"Processing Relevant Paths", file=sys.stdout):
            try:
                path_nodes = []
                for node in path:
                    src_code = get_source_line(node, repo_root).strip()
                    processed = {
                        "lineInfo": node["location"]["physicalLocation"]["region"],
                        "fileInfo": node["location"]["physicalLocation"]["artifactLocation"]["uri"],
                        "sourceCode": src_code,
                    }
                    abs_file_path = os.path.join(repo_root, processed["fileInfo"])
                    if language == "Java":
                        method_name, method_start_line = find_method_at_line_java(abs_file_path, processed["lineInfo"]["startLine"])
                    else:
                        method_name, method_start_line = find_function_at_line_cached(abs_file_path, processed["lineInfo"]["startLine"])
                    processed["function"] = {"name": method_name, "startLine": method_start_line}
                    path_nodes.append(processed)
                processed_paths.append(path_nodes)
            except Exception as e:
                logger.warning(f"Path processing exception: {e}")
                continue

        logger.info(f"===> {len(processed_paths)} paths obtained")
        return processed_paths
    except Exception as e:
        logger.exception(f"Failed to parse SARIF {sarif_path}: {e}")
        return []

def _interval_overlap(a1: int, a2: int, b1: int, b2: int) -> bool:
    return not (a2 < b1 or b2 < a1)

def match_hunk_and_node(node, hunk):
    node_filename = node["fileInfo"]
    node_start_line = node["lineInfo"]["startLine"]
    node_end_line = node_start_line if "endLine" not in node["lineInfo"] else node["lineInfo"]["endLine"]
    hunk_start_line = hunk["start_line"]
    hunk_end_line = hunk["end_line"]
    hunk_file_name = hunk["fileName"]
    # print("HUNK: ", hunk_file_name, node_start_line, node_end_line, hunk_start_line, hunk_end_line)
    if hunk_file_name != node_filename:
        return False, False

    return True, _interval_overlap(hunk_start_line, hunk_end_line, node_start_line, node_end_line)

def get_paths_one_file(all_paths_content, hunk_list):
    matches = []
    # print("all paths: ", all_paths_content)
    for path_ind, cur_path in enumerate(all_paths_content):
        unique_hash = hashlib.sha256(
            json.dumps(cur_path, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        for node_ind, cur_node in enumerate(cur_path):
            for hunk_ind, cur_hunk in enumerate(hunk_list):
                file_match, lines_match = match_hunk_and_node(cur_node, cur_hunk)
                if file_match and lines_match:
                    matches.append({
                        "pathHash": unique_hash,
                        "nodeInd": node_ind,
                        "hunkInd": hunk_ind,
                        "path": cur_path
                    })
    # print("matches: ", matches)
    return matches

def count_matches_per_path(matches_list):
    counts = {}
    for item in matches_list:
        counts.setdefault(item["pathHash"], set()).add(item["hunkInd"])
    return counts

def copy_queries(original_folder, dst_folder):
    os.makedirs(dst_folder, exist_ok=True)
    for file in os.listdir(original_folder):
        src = os.path.join(original_folder, file)
        if os.path.isfile(src):
            shutil.copy(src, os.path.join(dst_folder, file))

def build_sink_qll_with_enumeration(fix_sources_path, language):
    hunk_info = json.load(open(fix_sources_path, encoding="utf-8"))
    all_hunks = []
    for hunk_file in hunk_info:
        for filename, file_data in hunk_file.items():
            file_hunks = file_data["hunks"]
            for cur_hunk in file_hunks:
                all_hunks.append({
                    "sink_args": cur_hunk.get("parameters", []),
                    "file_path": filename,
                    "method": cur_hunk["method_name"],
                })
    hunk_body_entries = []
    for item in all_hunks:
        file_path = item["file_path"]
        method = item["method"]
        if item["sink_args"]:
            sink_args = [f"p{i}" for i in range(len(item["sink_args"]))]
        else:
            sink_args = []

        if method:
            method_part = PREDICATES[language]["HUNK_SINK_BODY_ENTRY_METHOD_PART"].format(method=method)
        if file_path:
            file_part = PREDICATES[language]["HUNK_SINK_BODY_ENTRY_FILE_PART"].format(file_path=file_path)
        if sink_args:
            args_part=" or ".join([
                        PREDICATES[language]["QL_SINK_ARG_NAME_ENTRY"].format(
                            arg_id=int(re.findall(r"[\S\s]*p([0-9]+)", sink_arg)[0]),
                        )
                        for sink_arg in sink_args
                        if len(re.findall(r"[\S\s]*p([0-9]+)", str(sink_arg))) > 0 or str(sink_arg) == "this"
                    ])
        if method and file_path and sink_args:
            cur_entry = PREDICATES[language]["HUNK_SINK_BODY_ENTRY_FULL"].format(method_part=method_part, file_part=file_part, args=args_part)
            hunk_body_entries.append(cur_entry)
        # elif method and file_path and not sink_args:
        #     cur_entry = PREDICATES[language]["HUNK_SINK_BODY_ENTRY_METHOD_NO_ARGS"].format(method_part=method_part,
        #                                                                          file_part=file_part)
        #     hunk_body_entries.append(cur_entry)
        # elif not method and file_path and not sink_args:
        #     cur_entry = PREDICATES[language]["HUNK_SINK_BODY_ENTRY_NO_METHOD"].format(file_part=file_part)
        #     hunk_body_entries.append(cur_entry)


    if not hunk_body_entries:
        body, additional = "1 = 0", ""
    else:
        batch_size = 300
        if len(hunk_body_entries) > batch_size:
            num_batches = int(math.ceil(len(hunk_body_entries) / batch_size))
            body = " or\n".join([
                PREDICATES[language]["CALL_QL_SUBSET_PREDICATE"].format(part_id=i, kind="Sink", node="snk")
                for i in range(num_batches)])
            add_list = []
            for ind in range(num_batches):
                cur = PREDICATES[language]["QL_SUBSET_PREDICATE"].format(
                    part_id=ind, kind="Sink", node="snk",
                    body=PREDICATES[language]["QL_BODY_OR_SEPARATOR"].join(hunk_body_entries[ind * batch_size: (ind + 1) * batch_size]))
                add_list.append(cur)
            additional = "\n\n".join(add_list)
        else:
            body = PREDICATES[language]["QL_BODY_OR_SEPARATOR"].join(hunk_body_entries)
            additional = ""
    return PREDICATES[language]["QL_SINK_PREDICATE"].format(body=body, additional=additional)

def build_source_qll_with_enumeration(fix_sources_path, language):
    hunk_info = json.load(open(fix_sources_path, encoding="utf-8"))
    all_hunks = set()

    for hunk_file in hunk_info:
        for filename, file_data in hunk_file.items():
            file_hunks = file_data["hunks"]
            for cur_hunk in file_hunks:
                all_hunks.add((filename, cur_hunk["method_name"]))
    hunk_src_api_entries = []
    for h in all_hunks:
        file_part = PREDICATES[language]["HUNK_SRC_ENTRY_API_FILE"].format(file_path=h[0])
        if h[1]:
            method_part = PREDICATES[language]["HUNK_SRC_ENTRY_API_METHOD"].format(method=h[1])
            full_entry = PREDICATES[language]["HUNK_SRC_ENTRY_API_FULL"].format(method_part=method_part, file_part=file_part)
        else:
            full_entry = PREDICATES[language]["HUNK_SRC_ENTRY_API_NO_METHOD"].format(file_part=file_part)
        hunk_src_api_entries.append(full_entry)

    # hunk_params_entries = [
    #     PREDICATES[language]["HUNK_FUNC_PARAM_SOURCE_ENTRY"].format(file_path=h[0], method=h[1]) for h in all_hunks
    # ]

    hunk_params_entries = []
    for h in all_hunks:
        if h[1]:
            cur_entry = PREDICATES[language]["HUNK_FUNC_PARAM_SOURCE_ENTRY_WITH_METHOD"].format(file_path=h[0], method=h[1])
        else:
            cur_entry = PREDICATES[language]["HUNK_FUNC_PARAM_SOURCE_ENTRY_NO_METHOD"].format(file_path=h[0])
        hunk_params_entries.append(cur_entry)

    all_entries = hunk_src_api_entries + hunk_params_entries or ["1 = 0"]
    body = PREDICATES[language]["CALL_QL_SUBSET_PREDICATE"].format(part_id=0, kind="Source", node="src")
    additional = PREDICATES[language]["QL_SUBSET_PREDICATE"].format(
        part_id=0, kind="Source", node="src", body=PREDICATES[language]["QL_BODY_OR_SEPARATOR"].join(all_entries))
    return PREDICATES[language]["QL_SOURCE_PREDICATE"].format(body=body, additional=additional if additional else "")

def build_taint_propagator_qll_with_enumeration(fix_sources_path, language):
    hunk_info = json.load(open(fix_sources_path, encoding="utf-8"))


    hunk_entries = []
    for hunk_file in hunk_info:
        for filename, file_data in hunk_file.items():
            file_hunks = file_data["hunks"]
            func_entries = []
            for cur_hunk in file_hunks:
                if not cur_hunk["method_name"]:
                    continue
                func_entry = PREDICATES[language]["HUNK_SUMMARY_FUNC_ENTRY"].format(
                    method=cur_hunk["method_name"]
                )
                func_entries.append(func_entry)
            joined_funcs = PREDICATES[language]["QL_BODY_OR_SEPARATOR"].join(func_entries)

            # Build the final entry for this file
            if joined_funcs:
                entry = PREDICATES[language]["HUNK_SUMMARY_ENTRY"].format(
                file_path=filename,
                funcs=joined_funcs
                )
            else:
                entry = PREDICATES[language]["HUNK_SUMMARY_ENTRY_NOFUNC"].format(
                    file_path=filename
                )

            hunk_entries.append(entry)
    if not hunk_entries:
        hunk_entries.append("1 = 0")
    #
    # for hunk_file in hunk_info:
    #     for filename, file_data in hunk_file.items():
    #
    #         # Build list of formatted function entries for each hunk in this file
    #         func_entries = []
    #         for h in file_data["hunks"]:
    #             func_entry = PREDICATES[language]["HUNK_SUMMARY_FUNC_ENTRY"].format(
    #                 method=h["method_name"]
    #             )
    #             func_entries.append(func_entry)
    #         # Join the function entries using the language-specific separator
    #         joined_funcs = PREDICATES[language]["QL_BODY_OR_SEPARATOR"].join(func_entries)
    #
    #         # Build the final entry for this file
    #         entry = PREDICATES[language]["HUNK_SUMMARY_ENTRY"].format(
    #             file_path=filename,
    #             funcs=joined_funcs
    #         )
    #         hunk_entries.append(entry)


    body = PREDICATES[language]["QL_BODY_OR_SEPARATOR"].join(hunk_entries)
    return PREDICATES[language]["QL_STEP_PREDICATE"].format(body=body)

# -----------------------------
# Main workflow
# -----------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Build/Run CodeQL queries, extract and visualize paths, with logging and cleanup."
    )
    p.add_argument("--language", default="Python")
    p.add_argument("--proj-folder-name", required=True)
    p.add_argument("--codeql-path", required=True)
    p.add_argument("--dbs-dir", required=True)
    p.add_argument("--repos-dir", required=True)
    p.add_argument("--base-op-dir", default="outputs")
    p.add_argument("--cwe", required=True, help="e.g., CWE-089")
    p.add_argument("--threads", type=int, default=6)
    p.add_argument("--ram", type=int, default=8192, help="RAM for CodeQL in MB")
    p.add_argument("--force", action="store_true", help="Force re-run even if outputs exist.")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    p.add_argument("--cleanup-on-failure", action="store_true", help="Delete partial outputs if the run fails.")
    p.add_argument(
        "--flat-dbs",
        action="store_true",
        help="DB path is {dbs-dir}/{slug} instead of {dbs-dir}/{language}/{slug}.",
    )
    p.add_argument(
        "--hunks-path",
        default=None,
        help="Path to CVEPath-shaped hunks.json. Default: {repo}/hunks.json.",
    )
    p.add_argument(
        "--query-packs",
        default=str(DEFAULT_QUERY_PACKS),
        help="Root holding base_queries/ and custom-cwe-queries/.",
    )
    return p.parse_args()

def main():
    args = parse_args()
    base_op_dir = Path(args.base_op_dir)
    logger = setup_logging(base_op_dir, args.proj_folder_name, args.log_level)
    cleaner = CleanupManager(logger)

    try:
        language = args.language
        proj_folder_name = args.proj_folder_name
        codeql_path = args.codeql_path
        dbs_dir = Path(args.dbs_dir)
        repos_dir = Path(args.repos_dir)
        cwe = args.cwe

        # Derived paths
        query_packs = Path(args.query_packs)
        base_query_dir = query_packs / "base_queries" / language
        base_cwe_q_dir = query_packs / "custom-cwe-queries" / language / cwe.lower()
        if not base_query_dir.is_dir():
            raise SystemExit(f"missing base queries: {base_query_dir}")
        if not base_cwe_q_dir.is_dir():
            raise SystemExit(f"missing CWE queries: {base_cwe_q_dir}")

        db_path = (dbs_dir / proj_folder_name) if args.flat_dbs else (dbs_dir / language / proj_folder_name)
        proj_op_dir = base_op_dir / proj_folder_name
        all_paths_path = proj_op_dir / f"raw_paths_{cwe.lower()}.json"
        processed_paths_path = proj_op_dir / f"processed_paths_{cwe.lower()}.json"
        path_img_dir = proj_op_dir / f"path_images_{cwe.lower()}"
        project_repo_dir = repos_dir / language / proj_folder_name
        hunks_path = Path(args.hunks_path) if args.hunks_path else (project_repo_dir / "hunks.json")
        proj_query_dir = proj_op_dir / f"codeql_queries_{cwe.lower()}"
        cwe_query_dir = proj_query_dir / f"cwe_{cwe.lower()}"
        source_queries_dir = proj_op_dir / f"source_queries_{cwe.lower()}"
        result_paths_dir = cwe_query_dir / f"result_paths_{cwe.lower()}"

        # Create dirs (tracked for cleanup if empty later)
        for d in [base_op_dir, proj_op_dir, proj_query_dir, cwe_query_dir, source_queries_dir, result_paths_dir, path_img_dir]:
            d.mkdir(parents=True, exist_ok=True)
            cleaner.track_dir(d)

        # 1) Copy base queries
        logger.info("Copying base queries ...")
        copy_queries(base_query_dir, proj_query_dir)
        copy_queries(base_cwe_q_dir, cwe_query_dir)

        # 2) Build Source/Sink/Summary QLL
        logger.info("Building MySources/MySinks/MySummaries ...")
        mysources_path = cwe_query_dir / "MySources.qll"
        mysinks_path = cwe_query_dir / "MySinks.qll"
        mysummaries_path = cwe_query_dir / "MySummaries.qll"

        source_qll = build_source_qll_with_enumeration(str(hunks_path), language)
        cleaner.track_file(mysources_path)
        with open(mysources_path, "w", encoding="utf-8") as f:
            f.write(source_qll)

        sink_content = build_sink_qll_with_enumeration(str(hunks_path), language)
        cleaner.track_file(mysinks_path)
        with open(mysinks_path, "w", encoding="utf-8") as f:
            f.write(sink_content)

        summary_content = build_taint_propagator_qll_with_enumeration(str(hunks_path), language)
        cleaner.track_file(mysummaries_path)
        with open(mysummaries_path, "w", encoding="utf-8") as f:
            f.write(summary_content)

        # 3) Run CWE queries
        logger.info("Running CWE queries ...")
        cwe_query_paths = [x for x in os.listdir(cwe_query_dir) if x.endswith(".ql")]
        for cwe_query_file in cwe_query_paths:
            full_path = str(cwe_query_dir / cwe_query_file)
            op_path = str(result_paths_dir / cwe_query_file.replace(".ql", ".sarif"))
            if os.path.exists(op_path) and not args.force:
                logger.info(f"Output exists, skipping: {op_path}")
                continue
            # track result file for cleanup if needed
            cleaner.track_file(op_path)
            try:
                run_codeql_query(
                str(db_path), full_path, op_path, codeql_path, logger,
                output_format_="sarif-latest", query_type="database analyze",
                threads=args.threads, ram_mb=args.ram
                )
            except Exception as e:
                print(e)

        # 4) Extract paths from SARIF (cache-aware)

        logger.info("Extracting Paths from SARIF ...")
        if not all_paths_path.exists() or args.force:
            sarif_files = [x for x in os.listdir(result_paths_dir) if x.endswith(".sarif")]
            all_paths = []
            for sarif_file in sarif_files:
                full_path = str(result_paths_dir / sarif_file)
                paths = get_paths_from_sarif(full_path, str(project_repo_dir), logger, language)
                all_paths.extend(paths)
            cleaner.track_file(all_paths_path)
            with open(all_paths_path, "w", encoding="utf-8") as f:
                json.dump(all_paths, f)
        else:
            with open(all_paths_path, "r", encoding="utf-8") as f:
                all_paths = json.load(f)

        # 5) Load hunks and find best matches
        logger.info("Processing Paths ...")
        all_hunks = []

        with open(hunks_path, 'r', encoding="utf-8") as f:
            ch_files = json.load(f)
            # print("HUNK FILE CONTENT: ", ch_files)
            for hunk_file in ch_files:
                for filename, file_data in hunk_file.items():
                    file_hunks = file_data["hunks"]
                    for cur_hunk in file_hunks:
                        all_hunks.append(cur_hunk|{"fileName": filename})
            # print(all_hunks)
            # for file in ch_files:
            #     fileName = file["fileName"]
            #     for hunk in file["hunks"]:
            #         hunk = dict(hunk)
            #         hunk["fileName"] = fileName
            #         all_hunks.append(hunk)


        processed_paths = get_paths_one_file(all_paths, all_hunks)
        counts = count_matches_per_path(processed_paths)
        counts_len = {k: len(v) for k, v in counts.items()}
        max_overlaps = max(counts_len.values()) if counts_len else 0
        matching_path_hashes = {k for k, v in counts.items() if len(v) == max_overlaps and max_overlaps > 0}
        refined_matches = [item for item in processed_paths if item["pathHash"] in matching_path_hashes]
        logger.info(f"Maximum overlap with {max_overlaps} hunks. Matching paths: {len(matching_path_hashes)}")

        # 6) Final processing & save
        logger.info("Final Processing ...")
        if not processed_paths_path.exists() or args.force:
            final_matches = {}
            cleaner.track_file(processed_paths_path)
            for item in refined_matches:
                path_hash = item["pathHash"]
                path = item["path"]
                if path_hash not in final_matches:
                    final_matches[path_hash] = {"path": path, "matches": []}
                final_matches[path_hash]["matches"].append({
                    "nodeInd": item["nodeInd"],
                    "hunkInd": item["hunkInd"],
                    "hunk": all_hunks[item["hunkInd"]]
                })
            with open(processed_paths_path, "w", encoding="utf-8") as f:
                json.dump(final_matches, f)
        else:
            with open(processed_paths_path, "r", encoding="utf-8") as f:
                final_matches = json.load(f)
        logger.info(f"Final Processing Done. Paths saved to {processed_paths_path}")

        # 7) Render path images
        try:
            for p_hash, path in final_matches.items():
                processed_nodes = [
                    f"{i + 1}: {cur_n['fileInfo'].split('/')[-1]}:{cur_n['lineInfo']['startLine']}"
                    for i, cur_n in enumerate(path["path"])
                ]
                img = plot_call_path(processed_nodes)
                img_path = path_img_dir / f"{p_hash}.png"
                if img_path.exists() and not args.force:
                    continue
                cleaner.track_file(img_path)
                with open(img_path, "wb") as f:
                    f.write(img.data)
        except Exception as e:
            logger.warning(f"Path image rendering skipped: {e}")

        logger.info("✅ Run completed successfully.")

    except KeyboardInterrupt:
        logger.error("Interrupted by user (Ctrl+C).")
        if args.cleanup_on_failure:
            logger.info("Performing cleanup after interruption ...")
            cleaner.cleanup()
        sys.exit(130)
    except Exception as e:
        logging.getLogger("codeql_pipeline").exception(f"Fatal error: {e}")
        if args.cleanup_on_failure:
            logging.getLogger("codeql_pipeline").info("Performing cleanup after failure ...")
            cleaner.cleanup()
        sys.exit(1)
    finally:
        # Ensure all handlers are flushed/closed cleanly
        for h in logging.getLogger("codeql_pipeline").handlers[:]:
            try:
                h.flush()
                if hasattr(h, "close"):
                    h.close()
            except Exception:
                pass

if __name__ == "__main__":
    main()
