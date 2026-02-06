import json
import threading
import time
from pathlib import Path

# Use absolute path for logs to avoid CWD issues
LOG_FILE = Path("/home/socks/Documents/AegisSentinal/logs/security_events.json")
LOG_LOCK = threading.Lock()

def log_security_event(event_data: dict):
    """
    Logs a security event to the JSONL log file (Line-delimited JSON).
    """
    # Ensure timestamp exists
    if "timestamp" not in event_data:
        event_data["timestamp"] = time.strftime('%Y-%m-%d %H:%M:%S')

    with LOG_LOCK:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(event_data) + "\n")
        except Exception as e:
            print(f"Error logging security event: {e}")
