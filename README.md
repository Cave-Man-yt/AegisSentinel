# AegisSentinel: Enterprise-Grade GenAI Security Gateway (MCP)

**AegisSentinel** is a production-ready Model Context Protocol (MCP) server designed to secure Generative AI pipelines against Prompt Injection, Jailbreaks, and PII leakage. It implements a **Defense-in-Depth** architecture compliant with the *2026 Enterprise Anti-Prompt Injection Defense Framework*.

## 🛡️ Key Features

-   **Hybrid Input Defense (Layer 1-3)**:
    -   **Heuristic Firewall**: Deterministic blocking of known jailbreaks (e.g., "DAN", "Mongo Tom") using externalized signatures (`jailbreak_signatures.json`).
    -   **Semantic Scan**: Zero-Shot Classification (`BanTopics`) to detect "Social Engineering" and "Persona Adoption" attempts.
    -   **Structural Injection Model**: `ProtectAI/DeBERTa-v3` model to detect instruction overrides.
-   **Context-Aware Privacy (Layer 4)**:
    -   **PII Redaction**: Automatically sanitizes names, phones, and passwords using `Anonymize` + `Presidio`.
    -   **Context Intelligence**: Distinguishes between business data (e.g., `TRK-1234`) and sensitive PII.
-   **Enterprise Risk Scoring**:
    -   Zero-Tolerance logic: `Risk = max(Heuristic ? 100 : 0, Model * 100)`.
-   **Output Scanning**:
    -   Dedicated `secure_output_scanner` tool to redact PII from LLM-generated responses before they reach the user.

## 🚀 Installation & Setup

### Prerequisites
-   Python 3.10+
-   `uv` or `pip`

### 1. Clone & Install
```bash
git clone https://github.com/your-org/AegisSentinel.git
cd AegisSentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configuration
Edit `config.yaml` to defend against specific threats:
```yaml
risk_threshold: 80
pii:
  allowed_names: ["CompanyBot", "Support"] # Whitelist entities
```
Edit `jailbreak_signatures.json` to add new blocklist rules dynamically.

### 3. Run the Server
```bash
./start.sh
```

## 🖥️ Usage

### MCP Tools
AegisSentinel exposes two primary tools to your agent:

1.  **`secure_prompt_gateway(user_prompt: str)`**:
    -   Call this *before* processing any user input.
    -   Returns: JSON with `status` ("SAFE" / "BLOCKED") and `risk_score`.
    -   **Effect**: Raises a `ValueError` if blocked, forcibly stopping the agent.

2.  **`secure_output_scanner(model_response: str)`**:
    -   Call this *after* generating a response.
    -   Returns: Redacted string (e.g., "My password is [REDACTED_DB_PASSWORD]").

### Streamlit UI (Coming Soon)
We are integrating a Streamlit-based Admin Dashboard to visualize:
-   Real-time Risk Scores.
-   Attack Vectors (Jailbreak vs. Injection).
-   PII Redaction logs.
*(Code to be added shortly)*

## 📊 Architecture

```mermaid
graph TD
    User[User Input] --> Heuristic[Heuristic Firewall<br/>(Signatures)]
    Heuristic -->|Blocked| Log[Security Log]
    Heuristic -->|Safe| Model[DeBERTa Semantic Scan]
    Model -->|High Risk| Log
    Model -->|Safe| PII[PII Redaction Layer]
    PII --> Agent[GenAI Agent]
    Agent --> Output[LLM Output]
    Output --> OutputScan[Output Scanner]
    OutputScan --> Final[User Response]
```

## 🔒 Security Policy
Reliable security requires **layers**. Do not rely solely on the AI model. Keep `jailbreak_signatures.json` updated with the latest community findings (e.g., from JailbreakChat).
