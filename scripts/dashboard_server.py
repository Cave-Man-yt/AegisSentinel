import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
import json
import logging

# Configuration
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs/security_events.json"
DASHBOARD_DIR = BASE_DIR / "dashboard"

app = FastAPI(title="AegisSentinel Dashboard")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_logs():
    """Reads security events from the log file."""
    if not LOG_FILE.exists():
        return []
    
    events = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        logging.error(f"Error reading logs: {e}")
    return events

@app.get("/api/security/metrics")
async def get_metrics():
    events = get_logs()
    
    total_requests = len(events)
    blocked_events = [e for e in events if e.get("action") == "BLOCKED"]
    threats_blocked = len(blocked_events)
    
    # Calculate Threat Vectors
    threat_counts = {}
    for e in blocked_events:
        # Extract reason/vector
        details = e.get("details", {})
        reason = details.get("reason", "Unknown")
        
        # Simplified vector mapping
        vector = "Generic"
        if "Heuristic" in reason: vector = "Known Jailbreak"
        elif "Prompt Injection" in reason: vector = "Prompt Injection"
        elif "Semantic" in reason: vector = "Social Engineering"
        elif "PII" in reason: vector = "PII Data Leak"
        
        threat_counts[vector] = threat_counts.get(vector, 0) + 1
        
    # Top Threat
    top_threat_vector = {"name": "None detected", "count": 0, "severity": "low"}
    if threat_counts:
        top_name = max(threat_counts, key=threat_counts.get)
        top_threat_vector = {
            "name": top_name,
            "count": threat_counts[top_name],
            "severity": "high" if "Jailbreak" in top_name or "Injection" in top_name else "medium"
        }

    # All Vectors for Chart
    all_threat_vectors = [
        {"threat_type": k, "count": v} for k, v in threat_counts.items()
    ]
    
    return {
        "total_requests": total_requests,
        "threats_blocked": threats_blocked,
        "block_rate": round((threats_blocked / total_requests * 100) if total_requests > 0 else 0, 1),
        "top_threat_vector": top_threat_vector,
        "all_threat_vectors": all_threat_vectors
    }

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
async def login(request: LoginRequest):
    if request.username == "admin" and request.password == "Admin@123":
        return {"success": True, "message": "Login successful"}
    return {"success": False, "message": "Invalid credentials"}

class ScanRequest(BaseModel):
    prompt: str

@app.get("/metrics/latency")
async def get_latency_metrics():
    # In a real scenario, we would parse start/end times from logs.
    # For this dashboard/demo, we return calculated mock values based on request count.
    events = get_logs()
    count = len(events)
    
    # Simulate realistic variability
    avg_latency = 120 + (count % 10) * 5
    p95 = avg_latency * 1.5
    
    # Generate mock history for the bar graph (last 6 4-hour buckets)
    # In a real app, this would be aggregated from timestamps
    import random
    history_native = [random.randint(20, 50) for _ in range(6)]
    history_secured = [random.randint(100, 150) for _ in range(6)]
    
    return {
        "avg_latency_ms": round(avg_latency, 1),
        "median_latency_ms": round(avg_latency * 0.9, 1),
        "p95_latency_ms": round(p95, 1),
        "percentage_impact": 15.2, # Mock overhead
        "sla_status": "within_sla",
        "total_requests": count,
        "sla_breaches": 0,
        "breach_rate": 0.0,
        "history": {
            "labels": ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
            "native": history_native,
            "secured": history_secured
        }
    }

@app.get("/api/security/alerts")
async def get_alerts():
    """Returns formatted alerts for the dashboard."""
    events = get_logs()
    alerts = []
    
    # Iterate backwards to get latest first
    for i, e in enumerate(reversed(events)):
        # Only show relevant security events
        if e.get("event_type") not in ["LLM_INPUT_SCAN", "LLM_OUTPUT_SCAN"]:
            continue
            
        risk_score = e.get("risk_score", 0)
        action = e.get("action", "UNKNOWN")
        
        # Determine Severity based on risk/action
        severity = "low"
        if risk_score >= 80 or action == "BLOCKED": severity = "critical"
        elif risk_score >= 50: severity = "high"
        elif action == "REDACTED": severity = "medium"
        
        details = e.get("details", {})
        prompt_preview = details.get("original") or details.get("sanitized") or "N/A"
        
        alerts.append({
            "id": f"ALT-{len(events)-i:04d}",
            "timestamp": e.get("timestamp"),
            "attackType": details.get("reason", "Anomaly"),
            "severity": severity,
            "prompt": prompt_preview[:50] + "..." if len(prompt_preview) > 50 else prompt_preview,
            "fullPrompt": prompt_preview,
            "sourceIp": "127.0.0.1", # Mock IP
            "status": action.lower(),
            "userAgent": "Antigravity Agent",
            "confidence": f"{risk_score}%"
        })
        
    return alerts

@app.post("/metrics/scan")
async def simulate_scan(request: ScanRequest):
    # Simulate a scan event for the dashboard demo
    # This allows the "Generate Sample Scans" JS to work and populate the graphs
    import random
    import time
    
    # Basic logic to generate variety
    is_safe = True
    risk_score = 0
    reason = "None"
    action = "ALLOWED"
    
    if "reset" in request.prompt or "password" in request.prompt:
        action = "REDACTED"
        risk_score = 10
        reason = "PII Data Leak"
        
    if "ignore" in request.prompt.lower():
        is_safe = False
        risk_score = 100
        reason = "Prompt Injection"
        action = "BLOCKED"

    event = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "event_type": "LLM_INPUT_SCAN",
        "action": action,
        "risk_score": risk_score,
        "details": {"reason": reason, "original": request.prompt}
    }
    
    # Append to log
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
        
    return {"status": "scanned", "risk_score": risk_score}

@app.post("/api/security/reset")
async def reset_metrics():
    # In a real app, we might archive logs. Here we just wipe/truncate.
    with open(LOG_FILE, "w") as f:
        f.write("")
    return {"status": "success"}

# Serve Static Files (Dashboard UI)
app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="static")

if __name__ == "__main__":
    print(f"Starting Dashboard on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
