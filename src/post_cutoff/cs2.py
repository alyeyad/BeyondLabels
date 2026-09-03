"""CS-2: keep CVEs whose fix commit touches a vulnerability-path-fixing file.

Single-file fixing commits are kept without an LLM call. Multi-file commits are
labelled with the paper few-shot prompt
(``prompt_templates/llm_multifile_labelling.txt``); the CVE survives when at
least one changed file is labelled ``vulnerability-path-fixing``. The default
model is the one used for the post-cutoff run, Claude Opus 5.

Per-CVE results are cached under ``<out>/cs2/``, so re-running only issues calls
for CVEs that are missing or previously errored.
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from src.post_cutoff.config import PROMPT_PATH, Layout, log

KEEP_LABEL = "vulnerability-path-fixing"
_THREAD = threading.local()


def sanitize(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value.replace("/", "__"))


def changed_files(record: dict) -> list[dict]:
    files: list[dict] = []
    for detail in record.get("details") or []:
        if not isinstance(detail, dict):
            continue
        name = detail.get("file_name") or ""
        if not name:
            continue
        files.append(
            {"file_path": name, "file_name": name, "patch": detail.get("patch") or ""}
        )
    return files


def model_input(record: dict) -> dict:
    commit_id = record.get("commit_id") or ""
    project = record.get("project") or ""
    return {
        "cve_id": record.get("cve_id"),
        "cwe_id": record.get("cwe_id"),
        "cve_language": record.get("cve_language"),
        "cve_description": record.get("cve_description"),
        "commit_id": commit_id,
        "commit_message": record.get("commit_message"),
        "project": project,
        "commit_url": record.get("html_url")
        or f"https://github.com/{project}/commit/{commit_id}",
        "changed_files": changed_files(record),
    }


def parse_model_json(raw: str):
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def _as_items(parsed) -> list:
    if isinstance(parsed, dict):
        parsed = parsed.get("files") or parsed.get("results") or [parsed]
    return parsed if isinstance(parsed, list) else []


def has_path_fixing(parsed) -> bool:
    return any(
        isinstance(item, dict) and item.get("decision") == KEEP_LABEL
        for item in _as_items(parsed)
    )


def output_path(record: dict, model: str, dest: Path) -> Path:
    cve = record.get("cve_id") or "unknown"
    project = sanitize(record.get("project") or "unknown")
    commit = record.get("commit_id") or "unknown"
    return dest / f"{cve}_{project}_{commit}_{sanitize(model)}.json"


def kept_file_names(record: dict, cs2_dir: Path, model: str) -> set[str]:
    """Files the classifier labelled ``vulnerability-path-fixing``."""
    names: set[str] = set()
    dest = output_path(record, model, cs2_dir)
    if dest.is_file():
        try:
            data = json.loads(dest.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        for item in _as_items(data.get("parsed_output")):
            if not isinstance(item, dict) or item.get("decision") != KEEP_LABEL:
                continue
            name = item.get("file_path") or item.get("file_name") or ""
            if name:
                names.add(name)
    if names:
        return names
    files = changed_files(record)
    if len(files) <= 1:
        return {f["file_path"] for f in files if f.get("file_path")}
    return set()


def _write_result(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _retryable(exc: Exception) -> bool:
    if type(exc).__name__ in {
        "RateLimitError",
        "APITimeoutError",
        "InternalServerError",
        "APIConnectionError",
    }:
        return True
    text = str(exc).lower()
    return "429" in text or "rate limit" in text or "overloaded" in text


def _client(provider: str):
    from src.llm_runner.runner import setup_client

    client = getattr(_THREAD, "client", None)
    if client is None:
        client = setup_client(provider)
        _THREAD.client = client
    return client


def _classify_one(
    rec: dict,
    *,
    context: str,
    model: str,
    provider: str,
    out_dir: Path,
    retries: int = 6,
) -> tuple[str, str | None]:
    from src.llm_runner.runner import send_prompt

    payload = model_input(rec)
    cve = rec.get("cve_id") or ""
    raw, reasoning, parsed, err = "", "", None, None
    for attempt in range(retries):
        try:
            raw, reasoning, _usage = send_prompt(
                _client(provider),
                context,
                json.dumps(payload, ensure_ascii=False),
                model,
                temperature=None,
            )
            parsed = parse_model_json(raw)
            err = None
            break
        except Exception as exc:  # noqa: BLE001 - recorded in the result file
            err = f"{type(exc).__name__}: {exc}"
            if _retryable(exc) and attempt + 1 < retries:
                wait = min(2**attempt, 60)
                log(f"[cs2] retry {cve} in {wait}s ({err})")
                time.sleep(wait)
                continue
            raw, reasoning, parsed = "", "", None
            break
    _write_result(
        output_path(rec, model, out_dir),
        {
            "model": model,
            "input": payload,
            "raw_output": raw,
            "parsed_output": parsed,
            "reasoning_content": reasoning,
            "error": err,
        },
    )
    return cve, err


def classify(
    layout: Layout,
    records: list[dict],
    *,
    model: str,
    provider: str = "anthropic",
    workers: int = 4,
    limit: int | None = None,
    prompt: Path = PROMPT_PATH,
    dry_run: bool = False,
) -> set[str]:
    """Label the pool and return the CVEs that keep at least one file."""
    if not prompt.is_file():
        raise SystemExit(f"missing CS-2 prompt: {prompt}")
    context = prompt.read_text(encoding="utf-8")
    layout.cs2.mkdir(parents=True, exist_ok=True)

    n_single = 0
    n_cached = 0
    pending: list[dict] = []
    for rec in records:
        files = changed_files(rec)
        if len(files) <= 1:
            n_single += 1
            _write_result(
                output_path(rec, model, layout.cs2),
                {
                    "model": model,
                    "skipped": "single_file_commit",
                    "input": model_input(rec),
                    "parsed_output": [
                        {
                            "file_path": files[0]["file_path"],
                            "file_name": files[0]["file_name"],
                            "decision": KEEP_LABEL,
                            "why": "Single-file fixing commit; CS-2 classifier skipped.",
                            "roles": [],
                            "confidence": 1.0,
                        }
                    ]
                    if files
                    else [],
                },
            )
            continue
        dest = output_path(rec, model, layout.cs2)
        if dest.is_file():
            try:
                existing = json.loads(dest.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = {}
            if not existing.get("error"):
                n_cached += 1
                continue
        pending.append(rec)

    log(
        f"[cs2] pool={len(records)} single_file={n_single} cached={n_cached} "
        f"pending={len(pending)} model={model} workers={max(1, workers)}"
    )
    if dry_run:
        return set()

    to_run = pending[:limit] if limit is not None else pending
    if to_run:
        n = len(to_run)
        done = 0

        def _job(rec: dict) -> tuple[str, str | None]:
            return _classify_one(
                rec,
                context=context,
                model=model,
                provider=provider,
                out_dir=layout.cs2,
            )

        if max(1, workers) == 1:
            for rec in to_run:
                cve, err = _job(rec)
                done += 1
                log(f"[cs2] [{done}/{n}] {cve} {err or 'ok'}")
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool_ex:
                futures = [pool_ex.submit(_job, rec) for rec in to_run]
                for fut in as_completed(futures):
                    cve, err = fut.result()
                    done += 1
                    log(f"[cs2] [{done}/{n}] {cve} {err or 'ok'}")

    passed: set[str] = set()
    for rec in records:
        cve = rec.get("cve_id") or ""
        if len(changed_files(rec)) <= 1:
            passed.add(cve)
            continue
        dest = output_path(rec, model, layout.cs2)
        if not dest.is_file():
            continue
        try:
            data = json.loads(dest.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if has_path_fixing(data.get("parsed_output")):
            passed.add(cve)

    log(f"[cs2] keep {len(passed)} / {len(records)}")
    return passed
