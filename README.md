# RiskLens AI — Cyber Risk Assistant

RiskLens AI is a practical intern-level cyber risk analysis assistant built using FastAPI, pandas, ChromaDB, and Groq LLM API. It analyzes synthetic vulnerability, asset, and threat intelligence datasets, calculates deterministic cyber risk scores, retrieves relevant NIST SP 800-53 controls, and generates readable executive-style cyber risk briefs.

---

# Live Demo

Dashboard:
```text
https://risklens-ai-ms0j.onrender.com/dashboard
```

Generate Report:
```text
https://risklens-ai-ms0j.onrender.com/analyze
```

Health Check:
```text
https://risklens-ai-ms0j.onrender.com/
```

---

# Architecture

The system uses a hybrid deterministic + semantic retrieval architecture.

Structured cybersecurity datasets such as assets, vulnerabilities, business services, and threat intelligence are processed using pandas-based joins and deterministic scoring logic. This ensures explainable and reproducible risk prioritization instead of relying on LLM reasoning for calculations.

For remediation guidance, the system uses semantic retrieval over embedded NIST SP 800-53 control descriptions using sentence-transformers and ChromaDB. Only NIST control text is embedded — no asset or vulnerability records are stored in the vector database.

The application is exposed through a lightweight FastAPI backend with:
- `/` → health check
- `/dashboard` → UI dashboard
- `/analyze` → generates the cyber risk brief

The Groq LLM (`llama-3.3-70b-versatile`) is only used for formatting narratives, executive summaries, and readable explanations. Risk scoring, prioritization, and control mapping remain fully deterministic.

---

# Scope

The project focuses on practical cyber risk prioritization for a synthetic fintech environment.

The system:
- loads vulnerability, asset, business service, and threat intelligence datasets
- correlates technical and business risk signals
- identifies actively exploited vulnerabilities using CISA KEV
- retrieves relevant NIST remediation controls
- generates readable executive-style cyber risk reports

The project is intentionally scoped as an intern-level implementation:
- lightweight architecture
- minimal infrastructure
- explainable scoring
- simple deployment
- no autonomous agents or complex orchestration

The goal was to prioritize correctness, reasoning quality, and practical AI engineering decisions over enterprise-scale complexity.

---

# How to Run Locally

## 1. Clone the Repository

```bash
git clone <your-github-repo>
cd RiskLens-AI
```

---

## 2. Install Requirements

```bash
pip install -r requirements.txt
```

---

## 3. Add Environment Variables

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key
PORT=8000
```

---

## 4. Start the Application

```bash
python main.py
```

OR

```bash
uvicorn main:app --reload --port 8000
```

---

## 5. Open in Browser

Health check:

```text
http://127.0.0.1:8000/
```

Dashboard:

```text
http://127.0.0.1:8000/dashboard
```

Generate report:

```text
http://127.0.0.1:8000/analyze
```

---

# Supporting Question 1 — The Data Split

## What data did I embed and why?

I only embedded NIST SP 800-53 security control descriptions because retrieving the correct remediation guidance is a semantic search problem. Queries like “SQL Injection mitigation” or “VPN authentication bypass” map better through embeddings than exact keyword matching. I used sentence-transformers with ChromaDB to retrieve the most relevant controls.

## What data did I query structurally and why?

Assets, vulnerabilities, business services, and threat intelligence were handled using structured pandas operations because they contain deterministic fields like CVSS, internet exposure, region, RTO, compliance scope, and business criticality. Using structured querying keeps scoring explainable, fast, and mathematically consistent.

---

# Supporting Question 2 — Where the System Can Go Wrong

### 1. Missing KEV Matches

If a CVE in the vulnerabilities dataset does not exist in the CISA KEV catalog, the system may fail to identify it as actively exploited even if exploitation exists elsewhere. To reduce this issue, I also use threat intelligence correlation and fallback exploit indicators instead of relying only on KEV presence.

### 2. Incorrect Semantic Retrieval

A semantically similar but incorrect NIST control may sometimes be retrieved for a vulnerability type. To reduce this, I added retrieval thresholds and deterministic fallback mappings for common categories like RCE, IDOR, authentication bypass, and unsupported software.

### 3. Incomplete Threat Correlation

Threat campaigns may incorrectly match unrelated vulnerabilities if only broad keywords are used. To reduce false positives, the system prioritizes exact CVE matches and region-based matching before attaching campaign context.

---

# Supporting Question 3 — One Thing I Would Improve

If I had another day, I would improve business dependency scoring using a graph-based approach instead of flat service lookups. Right now, risks are scored mostly at the asset level. A dependency graph would allow vulnerabilities on shared backend systems (like authentication or payment databases) to inherit the combined business impact of all upstream services depending on them, making prioritization more realistic.

---

# Technical Notes

- Risk scoring is fully deterministic and handled in Python code
- The LLM is only used for formatting explanations and executive summaries
- No asset or vulnerability records are embedded into the vector database
- Heavy AI components are lazy-loaded to support deployment on low-memory free-tier environments
- The application includes fallback handling for API failures and retrieval issues

---

# Tech Stack

- FastAPI
- pandas
- ChromaDB
- sentence-transformers
- Groq API
- scikit-learn
- Python

---

# Deployment

The project is deployed publicly on Render.

Production endpoints:
- `/` → health check
- `/dashboard` → dashboard UI
- `/analyze` → generate cyber risk report

The deployment uses lazy loading for embedding models and vector retrieval components to remain compatible with free-tier infrastructure limits.
