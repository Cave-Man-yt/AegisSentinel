import json
import threading
import time
from pathlib import Path

# Use absolute path to ensure logs are found regardless of CWD
LOG_FILE = Path("/home/socks/Documents/AegisSentinal/security_events.json")
LOG_LOCK = threading.Lock()

def log_security_event(event_data: dict):
    """
    Logs a security event to the JSON log file in a thread-safe manner.
    
    Args:
        event_data: Dictionary containing event details.
    """
    # Ensure timestamp exists
    if "timestamp" not in event_data:
        event_data["timestamp"] = time.strftime('%Y-%m-%d %H:%M:%S')

    with LOG_LOCK:
        try:
            if LOG_FILE.exists() and LOG_FILE.stat().st_size > 0:
                with open(LOG_FILE, "r") as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []
            else:
                logs = []
            
            # Prepend new event to keep latest at top if desired, 
            # or append. Dashboard usually reads all. Let's append.
            logs.append(event_data)
            
            with open(LOG_FILE, "w") as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            print(f"Error logging security event: {e}")
