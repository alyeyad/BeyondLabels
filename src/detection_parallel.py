"""Shared thread-pool helper for the RQ4 detection runs (R3C12).

The detection runs are I/O-bound network calls, so a thread pool gives a large
speedup. ``workers <= 1`` falls back to sequential execution (identical behaviour
to the original pipelines). Task order is not guaranteed under parallelism, but
each task writes a uniquely named log file, so results are order-independent.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, List


def run_parallel(
    tasks: Iterable[Any],
    worker: Callable[[Any], None],
    workers: int,
    desc: str = "tasks",
) -> None:
    task_list: List[Any] = list(tasks)
    total = len(task_list)
    if total == 0:
        print(f"[parallel] no {desc} to run")
        return

    if workers is None or workers <= 1:
        for i, task in enumerate(task_list, 1):
            try:
                worker(task)
            except Exception as exc:  # noqa: BLE001 - keep going on per-task failure
                print(f"[parallel] {desc} {i}/{total} failed: {exc}", flush=True)
        return

    print(f"[parallel] running {total} {desc} with {workers} workers", flush=True)
    done = 0
    failed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(worker, task): task for task in task_list}
        for future in as_completed(futures):
            done += 1
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print(f"[parallel] {desc} failed: {exc}", flush=True)
            if done % 25 == 0 or done == total:
                print(f"[parallel] {desc}: {done}/{total} done "
                      f"({failed} failed)", flush=True)

    if failed:
        print(f"[parallel] WARNING: {failed}/{total} {desc} failed", flush=True)
