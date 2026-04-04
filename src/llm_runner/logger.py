
import json
import os
import uuid
from datetime import datetime

def save_log(log_data: dict, fname:str, out_dir):
    log_data["timestamp"] = log_data.get("timestamp", datetime.utcnow().isoformat() + "Z")

    with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=2)

    print(f"📝 Saved log to {fname}")
    return fname