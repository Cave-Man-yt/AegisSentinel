# 🛡️ AegisSentinel: Enterprise GenAI Defense System

> **A fortress for your LLMs.** AegisSentinel is a production-grade Model Context Protocol (MCP) server that sits between your users and your Large Language Models (LLMs), filtering malicious inputs, preventing data leakage, and ensuring compliance.

![Architecture Diagram](Images/archDiagram.jpeg)

---

## 🚀 Evolution: MVP vs. AegisSentinel

This project is a massive evolution from the original POC.

| Feature | [MVP (PromptCheckMCP)](https://github.com/Cave-Man-yt/PromptCheckMCP) | **AegisSentinel (This Project)** |
| :--- | :--- | :--- |
| **Architecture** | Simple Python Script | **FastMCP Server** with Modular architecture |
| **Detection** | Basic String Matching | **Multi-Layered Defense** (Heuristic + Deep Learning + PII) |
| **Models** | None (Regex only) | **Ensemble of DeBERTa-v3 Models** (Zero-Shot + Injection Specific) |
| **Visibility** | Console Logs | **Real-time Cyberpunk Dashboard** (Web UI) |
| **Configuration** | Hardcoded | **Externalized Policy** (`config.yaml`, `jailbreak_signatures.json`) |
| **Response** | Exception / Crash | **Structured Security Events** (JSON) |

---

## 🏗️ Architecture & Security Layers

AegisSentinel employs a **Defense-in-Depth** strategy, ensuring that if one layer fails, another catches the threat.

### 1. The Heuristic Firewall (Layer 1)
*   **Mechanism**: High-speed regex and substring matching against known signatures.
*   **Purpose**: Instantly blocks known jailbreaks (e.g., "DAN", "Developer Mode") and obvious attacks with zero latency penalty.
*   **Config**: Managed via `config/jailbreak_signatures.json`.

### 2. The Semantic Neural Engine (Layer 2)
*   **Mechanism**: Deep Learning models analyze the *intent* of the prompt, not just keywords.
*   **Models Used**:
    *   **Zero-Shot Detection**: Uses `MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli`. This model is capable of understanding concepts like "Social Engineering" or "Emotional Blackmail" without specific training on those exact phrases.
    *   **Injection Specific**: Uses `protectai/deberta-v3-base-prompt-injection`. A specialized model fine-tuned specifically to detect structural prompt injection attacks.
*   **How DeBERTa Works**: DeBERTa (Decoding-enhanced BERT with disentangled attention) improves upon BERT by representing words and their positions separately. This allows it to understand the subtle context of a sentence better than standard transformers, making it highly effective at distinguishing between a user asking *about* a hack vs. *attempting* a hack.

### 3. The PII Privacy Vault (Layer 3)
*   **Mechanism**: Context-aware Entity Recognition (NER) + Regex.
*   **Purpose**: Detects and redacts sensitive data (Names, Phone Numbers, Database Credentials) *before* it leaves the secure enclave.
*   **Models**: Microsoft Presidio + Custom Regex Patterns.

### 4. The Risk Engine (Layer 4)
*   **Mechanism**: A normalization algorithm that aggregates scores from all layers.
*   **Logic**:
    *   **Heuristic Match**: Risk Score = **100** (Immediate Block).
    *   **Model Detection**: Risk Score = Model Confidence % (e.g., 0.98 -> 98).
    *   **PII Found**: Adds baseline risk (20).
    *   **Final Score**: `Max(Heuristic, Model, PII)`.
    *   **Threshold**: Any request with a Risk Score ≥ **80** is dropped.

---

## 📊 Datasets & Training

The intelligence behind AegisSentinel comes from robust datasets used to train the underlying models:

*   **NLI Datasets (MNLI, FEVER, ANLI)**: Used for the Zero-Shot classifier to understand logical relationships and intent.
*   **Deepset Prompt Injections**: A curated dataset of thousands of adversarial prompts used to train the injection-specific model.
*   **WikiText & CommonCrawl**: Foundation datasets for the DeBERTa-v3 base model.

---

## 🖥️ Dashboard & Monitoring

Includes a standalone **Security Operations Center (SOC) Dashboard**:
*   **Live Threat Map**: Visualizes attack origins (simulated).
*   **Real-time Metrics**: Latency impact, Block rates, and RPM.
*   **Incident Log**: Detailed breakdown of every blocked attempt with full forensic data.

### Running the Dashboard
```bash
./venv/bin/python scripts/dashboard_server.py
```
Access at: `http://localhost:8000`

---

## 🛠️ Usage

### Start the Server
```bash
./scripts/start.sh
```

### Connect with Inspector
```bash
npx @modelcontextprotocol/inspector ./scripts/start.sh
```
