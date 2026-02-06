import sys
import os
import contextlib
import json

# TRICK: Redirect stdout to stderr immediately to prevent libraries (llm-guard, transformers)
# from polluting the MCP stdio stream.
original_stdout = sys.stdout
sys.stdout = sys.stderr

import yaml
from fastmcp.server.server import FastMCP
from pydantic import BaseModel
import logging

# Ensure all logging goes to stderr
logging.basicConfig(stream=sys.stderr, level=logging.INFO)

import llm_guard.util
from llm_guard import scan_prompt
from llm_guard.input_scanners import (
    Anonymize,
    PromptInjection,
    BanTopics,
    BanSubstrings,
)
from llm_guard.vault import Vault
from src.utils.logger import log_security_event
from llm_guard.input_scanners.anonymize_helpers.regex_patterns import DEFAULT_REGEX_PATTERNS
from llm_guard.input_scanners.anonymize import DEFAULT_ENTITY_TYPES
# Load config
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.yaml"
SIGNATURES_PATH = BASE_DIR / "jailbreak_signatures.json"

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

# Load Externalized Heuristic Signatures (Report Requirement 6.3.2)
try:
    with open(SIGNATURES_PATH, "r") as f:
        JAILBREAK_SIGNATURES = json.load(f)
except FileNotFoundError:
    logging.error("jailbreak_signatures.json not found! Using fallback.")
    JAILBREAK_SIGNATURES = ["DAN", "Jailbreak"]

INJECTION_MODEL = config.get("injection_model", {})

app = FastMCP("Sentinel-AI-Defense-2026")

# --- 1. CONFIGURATION (Defense in Depth) ---

# A. Heuristic Firewall (The Rule Layer)
heuristic_scanner = BanSubstrings(
    substrings=JAILBREAK_SIGNATURES,
    match_type="str",
    case_sensitive=False
)

# B. Semantic Scanner (The Model Layer)
# Generalized detection for novel attacks
topic_scanner = BanTopics(
    topics=[
        "jailbreak", "prompt injection", "social engineering", 
        "emotional blackmail", "ignoring system instructions"
    ],
    threshold=0.6,
    use_onnx=True
)

# Structural Injection detection
injection_scanner = PromptInjection(
    threshold=0.5,
    use_onnx=INJECTION_MODEL.get("use_onnx", True)
)

# C. PII Scanner (Context-Aware Privacy Layer)
vault = Vault()

# Custom Recognizers (Report Requirement 4.4)
tracking_id_pattern = {
    "name": "TRACKING_ID",
    "expressions": [r"TRK-[0-9]{4}"],
    "context": [],
    "score": 0.85,
    "languages": ["en"]
}
db_password_pattern = {
    "name": "DB_PASSWORD",
    "expressions": [r"(?<=Password: )\S+"],
    "context": ["Password"],
    "score": 1.0, 
    "languages": ["en"]  
}
db_phone_pattern = {
    "name": "DB_PHONE",
    "expressions": [r"(?<=Phone Number: )\d+"],
    "context": ["Phone"],
    "score": 1.0,
    "languages": ["en"]
}

all_patterns = DEFAULT_REGEX_PATTERNS + [tracking_id_pattern, db_password_pattern, db_phone_pattern]
enabled_entity_types = DEFAULT_ENTITY_TYPES + ["TRACKING_ID", "DB_PASSWORD", "DB_PHONE"]

anonymize_scanner = Anonymize(
    vault=vault,
    regex_patterns=all_patterns,
    entity_types=enabled_entity_types,
    allowed_names=config["pii"].get("allowed_names", [])
)

# Group scanners for different phases
# (We run them explicitly in the flow, but keep lists for convenience)
input_scanners = [heuristic_scanner, topic_scanner, injection_scanner, anonymize_scanner]

# Warmup
logging.getLogger("src.server").info("System warming up...")
try:
    scan_prompt(input_scanners, "warmup")
    logging.getLogger("src.server").info("Enterprise Security Stack Loaded.")
except Exception as e:
    logging.getLogger("src.server").error(f"Warmup failed: {e}")


# --- 2. RISK NORMALIZATION LOGIC (Report Requirement 5.3) ---

def calculate_enterprise_risk(
    model_score: float, 
    heuristic_triggered: bool,
    pii_found: bool
) -> int:
    """
    Normalizes risk to 0-100 scale using Heuristic-Dominant logic.
    Reflects sections 5.2 and 5.3 of the Technical Report.
    """
    if heuristic_triggered:
        return 100  # Known signature = Critical Risk (Deterministic)
    
    # Scale model probability (0.0-1.0) to Risk (0-100)
    model_risk = int(model_score * 100)
    
    # PII presence adds a baseline risk
    pii_risk = 20 if pii_found else 0
    
    # Max-Pooling: The Risk is the highest of any component
    return max(model_risk, pii_risk)


# --- 3. MCP TOOL DEFINITION (End-to-End Workflow) ---

@app.tool()
def secure_prompt_gateway(user_prompt: str) -> dict:
    """
    The main entry point for the Anti-Prompt Injection Framework.
    Workflow: Heuristic -> Injection Check -> Risk Scoring -> PII Redaction -> Safe Output
    """
    with contextlib.redirect_stdout(sys.stderr):
        return _execute_security_pipeline(user_prompt)

def _execute_security_pipeline(user_prompt: str) -> dict:
    # STEP 1: Heuristic Firewall (Deterministic)
    # Checks against 'jailbreak_signatures.json'
    prompt_after_heuristic, is_safe_heuristic, heuristic_score = heuristic_scanner.scan(user_prompt)
    
    # STEP 2: Semantic Injection Scan (Deep Learning)
    # We run 'BanTopics' and 'PromptInjection'
    _, is_safe_topic, topic_score = topic_scanner.scan(user_prompt)
    _, is_safe_injection, injection_score = injection_scanner.scan(user_prompt)
    
    # Normalize Model Scores (taking the max of the AI models)
    max_model_score = max(topic_score, injection_score)
    if max_model_score < 0: max_model_score = 0 # Handle -1 for safe
    
    # STEP 3: Risk Calculation (Enterprise Standard)
    risk_score = calculate_enterprise_risk(
        model_score=max_model_score,
        heuristic_triggered=(not is_safe_heuristic),
        pii_found=False # PII check comes next
    )
    
    # BLOCKING LOGIC (Threshold = 80, as per Report 6.3.2)
    reason = []
    if not is_safe_heuristic: reason.append("Heuristic Signature Match")
    if not is_safe_topic: reason.append(f"Semantic Policy Violation ({topic_score})")
    if not is_safe_injection: reason.append(f"Prompt Injection Detected ({injection_score})")
    
    if risk_score >= 80:
        event = {
            "event_type": "LLM_INPUT_SCAN",
            "action": "BLOCKED",
            "risk_score": risk_score,
            "details": {"reason": ", ".join(reason), "original": user_prompt}
        }
        log_security_event(event)
        
        # Enforce Block: Raise Exception to stop the Agent
        raise ValueError(f"SECURITY BLOCK: {', '.join(reason)}. Request Dropped.")

    # STEP 4: PII Redaction (Privacy Layer)
    # Only run if prompt is clean of injection
    safe_prompt, is_pii_clean, pii_score = anonymize_scanner.scan(user_prompt)
    
    # Log Success
    event = {
        "event_type": "LLM_INPUT_SCAN",
        "action": "ALLOWED" if safe_prompt == user_prompt else "REDACTED",
        "risk_score": risk_score,
        "details": {"sanitized": safe_prompt}
    }
    log_security_event(event)

    # STEP 5: Return Safe Payload
    return {
        "status": "SAFE",
        "risk_score": risk_score,
        "safe_prompt": safe_prompt, # Redacted string
        "pii_redacted": not is_pii_clean,
        "reason": "PII Redacted" if not is_pii_clean else ""
    }

@app.tool()
def secure_output_scanner(model_response: str) -> dict:
    """
    Scans the LLM's output for accidental PII leakage.
    """
    with contextlib.redirect_stdout(sys.stderr):
        sanitized_text, is_valid, risk_score = anonymize_scanner.scan(model_response)
        
        status = "SAFE"
        if sanitized_text != model_response:
            status = "REDACTED"
            
        event = {
            "event_type": "LLM_OUTPUT_SCAN",
            "action": "REDACTED" if status == "REDACTED" else "ALLOWED",
            "details": {"redacted": status == "REDACTED"}
        }
        log_security_event(event)

        return {
            "status": status,
            "sanitized_content": sanitized_text,
            "details": "PII redacted" if status == "REDACTED" else "No PII found"
        }

if __name__ == "__main__":
    # Restore stdout for MCP communication
    sys.stdout = original_stdout
    app.run()
