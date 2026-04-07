from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .io_utils import json_ready


def save_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(json_ready(payload), f, indent=2)