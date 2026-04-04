
import json
import os
import uuid
from datetime import datetime

def save_log(log_data: dict, out_dir="logs", name_prefix="run", fname=None):
    os.makedirs(out_dir, exist_ok=True)
    log_data["timestamp"] = log_data.get("timestamp", datetime.utcnow().isoformat() + "Z")
    log_data["experiment_id"] = log_data.get("experiment_id", str(uuid.uuid4()))
    if not fname:
        fname = f"{name_prefix}_{log_data['experiment_id']}.json"

    with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=2)

    print(f"📝 Saved log to {fname}")
    return fname