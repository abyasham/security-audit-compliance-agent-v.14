<p align="center">
  <img src="media/saca.jpg" alt="SACA Logo" width="300">
</p>

<p align="center">
  <a href="https://youtu.be/rGiHmws6qfw">
    <img src="media/sacayt.png" alt="SACA v14 Demo" width="600">
  </a>
  <br>
  <a href="https://youtu.be/rGiHmws6qfw"><b>Watch the SACA v14 Video Demo</b></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v14-blue" alt="Version">
  <img src="https://img.shields.io/badge/status-active%20development-success" alt="Status">
  <img src="https://img.shields.io/badge/node-%3E%3D20-339933" alt="Node">
  <img src="https://img.shields.io/badge/python-3.11+-3776AB" alt="Python">
  <img src="https://img.shields.io/badge/docker-compose-2496ED" alt="Docker">
</p>

<p align="center">
  🔍 Hello Cybersecurity colleagues! We are conducting research at Cardiff University to test <strong>LLM + RAG</strong> accuracy in explaining network security violations. We invite you to contribute your expertise to this study.
</p>

<p><strong>Why join?</strong></p>
<ul>
  <li>As an expert, your judgement helps to reshape the human-in-the-loop of our AI system.</li>
  <li>Help bridge the gap between AI audit tools and real-world practice.</li>
</ul>

<p><strong>How to help:</strong></p>
<p>
  It's simple! Complete this form: <a href="https://obrina.page">https://obrina.page</a>.
  You can skip the FGD session (choose any available date) and just watch the
  <a href="https://youtu.be/rGiHmws6qfw">video</a> instead.
  After submitting stage 1, you can directly go to
  <a href="https://obrina.page/2">stage 2</a> and finish the questionnaire.
</p>

<p><strong>Ethics & Privacy:</strong></p>
<ul>
  <li><strong>Anonymous:</strong> Your identity remains confidential; your email is used only for correspondence.</li>
  <li><strong>Approved:</strong> This research is cleared by the Cardiff University Ethics Committee (Ref: COMSC/Ethics/2026/006).</li>
</ul>

<p align="center">
  Ready to advance cybersecurity and IT audit? Fill out the form now! 🚀
</p>

<p align="center">
  #ITAudit #InfoSec #CyberSecurityIndonesia #AIinAudit #CardiffUniversity
</p>

**SACA** (Security Audit Compliance Agent) is a research prototype for automated, explainable IoT network compliance auditing. It combines a **ground-truth-calibrated attack detector layer**, an **LLM-as-Judge compliance reasoning engine**, and a **RAGAS-based hallucination detection evaluator** to produce defensible security findings from network packet captures (pcap) against standards such as ETSI EN 303 645.

**v14** introduces a hybrid TypeScript + Python architecture with unified multi-provider LLM support.

## Research Contributions

SACA v14 makes three novel contributions to automated compliance auditing:

### 1. Extensible, Ground-Truth-Calibrated Attack Detector Architecture

The `NetworkAgent` provides a **modular, additive detector layer** built on direct `tshark` CLI queries. Each detector is an isolated function — `file_path → List[Dict]` — that can be added, tuned, or removed without affecting any other detector. The architecture is currently calibrated against **all 11 available attack scenarios in the CICIoT 2023 dataset** (GT-01 to GT-13):

| Detector | Attack Type | GT Coverage |
|---|---|---|
| `detect_web_app_attacks` | XSS, SQLi, file upload, web shell, traversal | GT-01, 02, 03, 16 |
| `detect_brute_force` | SSH/HTTP/IoT password cracking (incl. port 9999) | GT-08 |
| `detect_syn_scans` | Reconnaissance / host discovery | GT-04, 06 |
| `detect_dns_hijacking` | Rogue DNS responders, cache poisoning | GT-07 |
| `detect_session_hijacking` | PHPSESSID/token reuse across IPs | GT-13 |
| `detect_log4shell` | JNDI callbacks, `.class` payload fetch | GT-12 |
| `detect_ddos` | Many-to-one TCP flood | GT-09 |
| `detect_token_injection` | UDP credential/token theft (IoT-specific) | GT-11 |
| `detect_arp_spoofing` | IP–MAC conflicts, gratuitous ARP | GT-05 |
| `detect_udp_floods` | Mirai-style botnet flooding | GT-06 |
| `detect_os_fingerprinting` | Malformed TCP flag probing | GT-10 |

Each detector produces **structured anomaly records** — carrying `srcIp`, `dstIp`, `dstPort`, `packetNumbers`, `confidence`, and `payloadEvidence` — that serve as the ground-level evidence fed to the LLM analysis pipeline.

**Extensibility:** Adding support for a new attack type requires only writing one new `detect_*()` function, registering it in the `analyze()` call, and mapping its anomaly type to an ETSI provision in the `_ANOMALY_CATEGORY_MAP` table. No other part of the system needs to change.

### 2. LLM-as-Judge Compliance Reasoning Pipeline

The `ComplianceJudge` implements a **five-phase cross-referencing pipeline** that bridges the structured detector output to human-readable, auditor-ready compliance verdicts:

```
Detector anomalies ──┐
                     ▼
Phase 1: Rule-Based Matching   ← Category-driven dispatch; single-best-evidence constraint
Phase 2: Anomaly Promotion     ← Anomaly type → ETSI clause mapping via hint table
Phase 3: LLM Judgment          ← LangGraph tool-loop; LLM calls tshark tools to verify
Phase 4: Merge + Deduplication ← Per-rule dedup + evidence-level dedup (prevents noise)
Phase 5: Summary               ← Violated / Compliant / Suspicious counts
```

The **evidence-deduplication** step is the key innovation: when multiple policy rules all point to the same network observation (e.g., 12 encryption rules all citing Stream 5), only the highest-confidence violation is kept as `violated` — the rest are demoted to `suspicious`. This reduces the "12 identical violations" artefact to 3–5 actionable findings.

The LLM judge's written reasoning is grounded in observed traffic facts (IP addresses, packet numbers, protocol details), not policy document boilerplate — making each finding directly verifiable in a packet analyser.

### 3. RAGAS Hallucination Detection for Audit Quality Assurance

Compliance audit reports generated by LLMs carry an inherent risk of **hallucination** — the AI producing plausible-sounding explanations that are not supported by actual packet evidence. For auditors who may use findings in regulatory or legal contexts, this is a critical problem.

SACA v14 integrates the **RAGAS Faithfulness metric** as a mandatory post-processing quality gate:

- **What it measures:** Whether the LLM judge's written reasoning for each finding is grounded in the observed network evidence (the retrieved contexts), not invented.
- **How it works:** For up to 3 violated findings (sampled across severity levels), an independent LLM scores each finding's reasoning against the structured packet evidence contexts. Scores range from 0.0 (pure hallucination) to 1.0 (fully grounded).
- **Why it matters for auditors:** A faithfulness score < 0.5 signals that the AI's explanation departs significantly from observed traffic — the finding should be reviewed by a human before being cited in a compliance report. A score ≥ 0.7 indicates the reasoning is well-grounded and can be acted upon.
- **Performance drift detection:** Running RAGAS across multiple audits over time reveals if changes to the LLM provider, policy documents, or detector tuning are degrading reasoning quality — functioning as a continuous quality monitor.

Validated scores on real CICIoT 2023 captures: GT-08 (0.607 faithfulness), GT-02 (0.643 faithfulness).

---

## Key Capabilities

- **11-Detector Network Analysis**: Modular, extensible tshark-based detectors covering all CICIoT 2023 attack categories — new detectors can be added without modifying existing code
- **Policy Processing**: Automatic rule extraction from compliance documents (PDF, markdown) using NLP + LLM
- **LLM-as-Judge Compliance Reasoning**: Five-phase pipeline with evidence deduplication that reduces finding noise by ~70%
- **Multi-Provider LLM**: Unified abstraction supporting 7 LLM backends with automatic fallback
- **RAGAS Hallucination Detection**: Per-finding faithfulness scoring to catch AI-generated audit explanations not grounded in packet evidence
- **Explainable Findings**: Every violation includes specific packet numbers, IP addresses, and verifiable evidence

## Docker Quick Start (Recommended)

SACA v14 is designed to run entirely via Docker Desktop. This avoids local Python/Node setup and keeps all services consistent.

### Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine (Linux)
- A configured `.env` file at repo root with at least one LLM provider key

### One-Time Setup

```bash
cp .env.example .env
# Edit .env with your API keys (at minimum OPENAI_API_KEY for RAGAS)
```

### Start

```bash
npm run docker:up
# or
docker compose -f docker/docker-compose.yml up --build
```

### Stop

```bash
npm run docker:down
# or
docker compose -f docker/docker-compose.yml down
```

**Access points:**
- Frontend: http://localhost:5173
- Express API: http://localhost:3001/api/health
- Python Core: http://localhost:8000/health

> If you rely on local Ollama, it must be reachable from containers (expose it or use a cloud provider in `.env`).

## Where You Can Contribute (Most Valuable Areas)

### 1) Attack Detector Tuning (Highest Impact)

The detector layer is modular and additive. Each detector is a single function in:

```
apps/core-py/network_analyzer_tshark.py
```

To add a new attack signature:

1. Write `detect_myattack(file_path: str) -> List[Dict]` with a targeted tshark filter.
2. Call it in `analyze()` and append results to `anomaly_dicts`.
3. Add a mapping in `apps/core-py/agents/compliance_judge.py`:
  `"my_attack_type": "etsi keyword"` inside `_ANOMALY_CATEGORY_MAP`.

This design means you can add new attack signatures without touching any other detectors.

### 2) Compliance Judge Improvements

Improve how findings are mapped to policy rules or how evidence is summarized:

- `apps/core-py/agents/compliance_judge.py`
- Focus areas: rule matching heuristics, evidence deduplication, reasoning clarity

### 3) RAGAS Quality & Drift Monitoring

Improve hallucination detection and QA thresholds:

- `apps/core-py/eval/ragas_runner.py`
- Focus areas: better sampling strategy, threshold policies, new metrics

### 4) Frontend Visualization (Optional)

Improve visibility and trust in findings:

- `apps/web/src/`
- Focus areas: evidence drill-down, packet-level trace views, RAGAS score display

## Configuration (.env)

All configuration lives in a single `.env` file at the repository root. This file is **git-ignored** and should never be committed.

**Minimum required settings:**
```env
PORT=3001
PYTHON_CORE_URL=http://core-py:8000
OPENAI_API_KEY=<your-key>   # Required for RAGAS evaluation
```

**Optional LLM providers (any one is enough):**
```env
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=deepseek-r1:8b
DEEPSEEK_API_KEY=<your-key>
DEEPSEEK_MODEL=deepseek-chat
OPENROUTER1_API_KEY=<your-key>
OPENROUTER1_MODEL=<model-name>
KIMI_API_KEY=<your-key>
KIMI_MODEL=kimi-k2.5
NVIDIA_API_KEY=<your-key>
NVIDIA_MODEL=mistralai/mistral-large-3-675b-instruct-2512
```

> ⚠️ **Never commit `.env`** with real API keys. Use `.env.example` for documentation.

## License

See LICENSE file in repository root.

## Acknowledgments

Built with:
- [LiteLLM](https://github.com/BerriAI/litellm) — Multi-provider LLM abstraction
- [LangGraph](https://github.com/langchain-ai/langgraph) — State machine orchestration
- [pyshark](https://github.com/KimiNewt/pyshark) — Packet analysis
- [spaCy](https://spacy.io/) — NLP for policy processing
- [FastAPI](https://fastapi.tiangolo.com/) — Python web framework
- [React](https://react.dev/) + [Vite](https://vitejs.dev/) — Frontend

---
<p align="center">
  <strong>SACA v14</strong> — made in the UK by OCB ©2026
</p>
