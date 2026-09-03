"""Removed-line hunks from unified diffs, as used by the CVEPath study design."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class Hunk:
    start_line: int
    end_line: int
    lines: list[str]


_HUNK_HEADER = re.compile(
    r"^@@\s*-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s*@@"
)


def extract_removed_hunks(diff_content: str) -> list[Hunk]:
    if not diff_content or not isinstance(diff_content, str):
        return []

    hunks: list[Hunk] = []
    old_line_num = None
    current_removed_lines: list[str] = []
    current_start_line = None

    for line in diff_content.splitlines():
        if line.startswith(("diff ", "index ", "--- ", "+++ ")):
            continue

        header_match = _HUNK_HEADER.match(line)
        if header_match:
            if current_removed_lines and current_start_line is not None and old_line_num is not None:
                hunks.append(
                    Hunk(
                        start_line=current_start_line,
                        end_line=old_line_num - 1,
                        lines=current_removed_lines[:],
                    )
                )
            old_line_num = int(header_match.group(1))
            current_removed_lines = []
            current_start_line = None
            continue

        if old_line_num is None:
            continue

        if line.startswith("-") and not line.startswith("---"):
            if current_start_line is None:
                current_start_line = old_line_num
            current_removed_lines.append(line[1:])
            old_line_num += 1
        elif line.startswith("+") and not line.startswith("+++"):
            if current_removed_lines and current_start_line is not None:
                hunks.append(
                    Hunk(
                        start_line=current_start_line,
                        end_line=old_line_num - 1,
                        lines=current_removed_lines[:],
                    )
                )
                current_removed_lines = []
                current_start_line = None
        elif line.startswith(" "):
            if current_removed_lines and current_start_line is not None:
                hunks.append(
                    Hunk(
                        start_line=current_start_line,
                        end_line=old_line_num - 1,
                        lines=current_removed_lines[:],
                    )
                )
                current_removed_lines = []
                current_start_line = None
            old_line_num += 1

    if current_removed_lines and current_start_line is not None and old_line_num is not None:
        hunks.append(
            Hunk(
                start_line=current_start_line,
                end_line=old_line_num - 1,
                lines=current_removed_lines[:],
            )
        )
    return hunks


def hunk_list_to_output(hunks: list[Hunk]) -> dict[str, Any]:
    hunk_entries = []
    total_lines = 0
    for idx, hunk in enumerate(hunks, start=1):
        num_lines = len(hunk.lines)
        total_lines += num_lines
        hunk_entries.append(
            {
                "index": idx,
                "start_line": hunk.start_line,
                "end_line": hunk.end_line,
                "num_lines": num_lines,
                "lines": hunk.lines,
            }
        )
    return {
        "hunks": hunk_entries,
        "summary": {"total_hunks": len(hunk_entries), "total_lines": total_lines},
    }
