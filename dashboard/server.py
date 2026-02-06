"""
MCP server with scan_content (PromptInjection) and get_sensitive_data (Anonymize) tools.
"""

import uvicorn
from fastmcp import FastMCP
from llm_guard.input_scanners import PromptInjection, Anonymize
from llm_guard.input_scanners.prompt_injection import MatchType
from llm_guard.vault import Vault

# Global taint flag set when malicious prompt is detected
IS_TAINTED = False

MOCK_DB = {
    "Alice": "555-0199",
    "Bob": "SECRET-DATA",
    "Caveman": "999-0000",
}

# Lazy-init scanners (they load models on first use)
_prompt_injection_scanner = None
_anonymize_scanner = None
_anonymize_vault = None


def _get_prompt_injection():
    global _prompt_injection_scanner
    if _prompt_injection_scanner is None:
        _prompt_injection_scanner = PromptInjection(
            threshold=0.5,
            match_type=MatchType.FULL,
        )
    return _prompt_injection_scanner


def _get_anonymize():
    global _anonymize_scanner, _anonymize_vault
    if _anonymize_vault is None:
        _anonymize_vault = Vault()
    if _anonymize_scanner is None:
        _anonymize_scanner = Anonymize(
            _anonymize_vault,
            entity_types=["PHONE_NUMBER"],
        )
    return _anonymize_scanner


mcp = FastMCP("Security MCP Server", json_response=True)


@mcp.tool()
def scan_content(text: str) -> str:
    """
    Scan text for malicious prompt injection. Uses llm-guard PromptInjection.
    If malicious, sets IS_TAINTED and returns a warning; otherwise returns safe.
    """
    global IS_TAINTED
    if not text or not text.strip():
        return "safe"
    scanner = _get_prompt_injection()
    _sanitized, is_valid, _risk_score = scanner.scan(text)
    if not is_valid:
        IS_TAINTED = True
        return "Warning: Malicious prompt injection detected. Access to sensitive data is now restricted."
    return "safe"


@mcp.tool()
def get_sensitive_data(name: str) -> str:
    """
    Fetch sensitive data for a person by name. Checks IS_TAINTED; if tainted, denies access.
    Otherwise fetches from the mock DB and redacts phone numbers using llm-guard Anonymize.
    """
    global IS_TAINTED
    if IS_TAINTED:
        return "Access denied: session is tainted due to prior malicious prompt. Cannot return sensitive data."
    if name not in MOCK_DB:
        return f"Unknown name: {name}"
    raw = MOCK_DB[name]
    scanner = _get_anonymize()
    redacted, _valid, _score = scanner.scan(raw)
    return redacted


# ASGI app for uvicorn (streamable HTTP at root)
app = mcp.http_app(path="/")

if __name__ == "__main__":
    import server
    uvicorn.run(server.app, host="0.0.0.0", port=8000)
