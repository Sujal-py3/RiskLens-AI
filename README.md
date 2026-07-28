# 🔍 RiskLens AI — Cyber Risk Assessment Engine

> **Deterministic scoring. Semantic retrieval. AI narration. Zero hallucinated risk scores.**

RiskLens AI is a production-architecture cyber risk assessment backend that transforms raw asset and vulnerability data into prioritised, NIST-mapped executive risk briefs. Built with FastAPI, it uses a hybrid intelligence model: **100% deterministic scoring in code** paired with **LLM-only narration** — a deliberate separation that eliminates the core failure mode of AI security tools.

---

## 🧠 The Core Design Thesis

Most AI security tools make a fundamental mistake: they let the LLM calculate the risk. LLMs are non-deterministic, hallucinate numbers, and cannot reliably rank across hundreds of rows of structured data.

RiskLens AI enforces a strict boundary:

| Responsibility | Handled By |
|---|---|
| Risk scoring & ranking | `utils/scoring.py` — pure Python math |
| Threat intel correlation | `pandas` structural queries on CSV datasets |
| NIST control retrieval | `ChromaDB` vector search (semantic RAG) |
| Narrative generation | Groq LLM — **formatting only** |
| Vendor compliance checks | Plan-Act-Check agentic loop |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     FastAPI Backend                     │
│                                                         │
│  GET /analyze                    POST /assess           │
│  ┌─────────────────┐             ┌──────────────────┐   │
│  │  Risk Pipeline  │             │  Agentic Loop    │   │
│  │                 │             │  (Plan-Act-Check)│   │
│  │ 1. Load CSVs    │             └────────┬─────────┘   │
│  │ 2. CISA KEV     │                      │              │
│  │ 3. Score vulns  │             ┌────────▼─────────┐   │
│  │ 4. Rank Top 5   │             │  VendorRAG       │   │
│  │ 5. NIST RAG     │             │  (FAISS / Chroma)│   │
│  │ 6. LLM format   │             └──────────────────┘   │
│  └────────┬────────┘                                     │
│           │                                              │
│  ┌────────▼────────────────────────────────────────────┐ │
│  │  Groq LLM  (llama-3.3-70b-versatile)               │ │
│  │  Role: Markdown formatter + narrative writer ONLY   │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## ⚙️ The Risk Scoring Model (`utils/scoring.py`)

Every open vulnerability is scored using a **deterministic 6-factor weighted formula**, normalised to `[0.0, 1.0]`:

```
score = (
    0.15 × cvss_normalised       +   # CVSS base score / 10
    0.15 × exploit_available     +   # 1.0 if KEV-listed or PoC exists
    0.25 × threat_campaign       +   # 1.0 if CVE matches active campaign in region
    0.10 × internet_exposed      +   # 1.0 if asset is internet-facing
    0.30 × business_criticality  +   # Composite sub-score (see below)
    0.05 × days_open_normalised  -   # Days open / 365, capped at 1.0
    0.10 × compensating_controls     # EDR(0.5) + WAF(0.3) + Patch(0.2)
) normalised by: (raw + 0.10) / 1.10
```

### Business Criticality Sub-Score

The highest-weighted factor (`0.30`) is itself a composite of four service attributes:

```
business_criticality =
    0.50 × asset_criticality_tier   +   # critical/high/medium/low → 1.0/0.7/0.4/0.1
    0.20 × customer_facing          +   # Yes → 1.0
    0.30 × compliance_scope_match   +   # GDPR/PCI/PDPL/SOC/IFRS → 1.0
    0.30 × revenue_impact_tier      +   # critical/high/medium/low → 1.0/0.7/0.4/0.1
    0.20 × rto_urgency                  # ≤4h → 1.0, ≤12h → 0.7, ≤24h → 0.4
```

> **Why no LLM for scoring?** Scoring requires determinism. The same vulnerability on the same asset must always produce the same score. LLMs cannot guarantee this.

---

## 🔎 NIST Control Retrieval — Semantic RAG (`utils/retrieval.py`)

Finding the right NIST SP 800-53 Rev. 5 control for a technical finding is a **natural language mapping problem**. We solve it with vector search:

1. NIST control descriptions are embedded using `sentence-transformers/all-MiniLM-L6-v2`
2. Embeddings are stored in **ChromaDB** (with `numpy` cosine similarity as a Windows-safe fallback)
3. At analysis time, a query like `"SQL Injection mitigation for web application"` retrieves `SI-10: Information Input Validation`, `SI-11: Error Handling` — via semantic proximity, not keyword matching

**What is NOT embedded:** No asset data, vulnerability names, CVSS scores, or business data enters the vector store. The RAG index contains only NIST control text.

---

## 🤖 Agentic Vendor Assessment — Plan-Act-Check Loop (`utils/agentic_loop.py`)

For vendor compliance questions (e.g., *"Does this vendor meet SOC 2 Type II access control requirements?"*), RiskLens runs a full **Plan → Act → Check** agentic loop:

```
PLAN   LLM decomposes the main question into N atomic sub-checks
  ↓    e.g. ["MFA enforced?", "Audit logs retained?", "Encryption at rest?"]

ACT    For each sub-check (concurrent via asyncio.gather):
  ↓    → Retrieve top-3 vendor document chunks via VendorRAG
       → Fast LLM extracts: verdict (pass/fail/unclear) + citation

CHECK  Cross-validate: does the citation logically support the verdict?
  ↓    → If YES:  sub-check passes
       → If NO (hallucination): RETRY with reasoning model
       → If RETRY fails: verdict → "unclear", flag for Human Review

AGGREGATE  Compute overall vendor risk score + remediation actions
```

This loop prevents hallucinated compliance verdicts — the most dangerous failure mode in AI-assisted security audits.

---

## 🧱 Technology Stack

| Layer | Technology | Role |
|---|---|---|
| **API** | FastAPI | REST endpoints, lazy singleton loading |
| **Structured Data** | pandas | Deterministic scoring over CSV datasets |
| **Vector Search** | ChromaDB + `all-MiniLM-L6-v2` | Semantic NIST control retrieval |
| **Vector Fallback** | NumPy cosine similarity | Windows SQLite lock workaround |
| **LLM** | Groq API (`llama-3.3-70b-versatile`) | Report formatting + narrative generation |
| **Threat Intel** | CISA KEV API + local cache | Live exploit-in-the-wild enrichment |
| **Agentic Loop** | asyncio + GroqClient | Concurrent Plan-Act-Check execution |
| **Evaluation** | Custom harness (`utils/eval_harness.py`) | Accuracy + hallucination detection metrics |

---

## 🗂️ Data Model

```
data/
├── assets.csv                  # 50+ assets: criticality, location, EDR, WAF, internet exposure
├── vulnerabilities.csv         # Open vulns: CVE, CVSS, days_open, patch_available
├── business_services.csv       # Services: RTO, revenue_impact, compliance_scope, depends_on
├── threat_intelligence.csv     # Campaign data: CVE, region, sector, ransomware_association
├── remediation_guidance.csv    # Finding-type → recommended_action lookup
└── nist_embeddings.npy         # Pre-computed NIST control embeddings (1.5 MB)
```

---

## 🛡️ Resilience & Failure Handling

| Failure Scenario | Fallback Strategy |
|---|---|
| Groq API offline / rate-limited | Pre-coded Markdown templates + local remediation lookup |
| CISA KEV fetch fails | → Local `cache/kev.json` → built-in critical CVE set |
| NIST catalog unavailable | → `cache/nist_controls.csv` → built-in control dictionary |
| ChromaDB lock (Windows SQLite) | In-memory NumPy cosine similarity over same embeddings |
| Agentic hallucination detected | Smart retry with reasoning model → Human Review flag |

---

## 📊 What Was Cut (And Why)

| Feature | Decision |
|---|---|
| User auth / multi-tenancy | Cut — adds infra complexity without demonstrating AI architecture |
| Graph-based dependency scoring | Designed, not built — `depends_on` column exists in CSV, propagation logic pending |
| PDF export | Cut — Markdown output is more composable downstream |
| Real-time CVE stream ingestion | Cut — CISA KEV polling covers the highest-priority subset |

---

## 🚀 Running Locally

### Prerequisites
- Python 3.10+
- Groq API key (optional — system degrades gracefully without it)

### Install
```bash
pip install -r requirements.txt
```

### Configure
```env
# .env
GROQ_API_KEY=gsk_...
PORT=8000
```

### Run
```bash
python main.py
# or
python -m uvicorn main:app --reload --port 8000
```

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Health check |
| `/analyze` | GET | Run full risk pipeline → Markdown report |
| `/assess` | POST | Vendor compliance check (Plan-Act-Check loop) |
| `/eval` | GET | Run evaluation harness → accuracy metrics |
| `/dashboard` | GET | Static HTML dashboard |

---

## Architectural Rationale

### 1. Why CSVs were queried structurally
Vulnerability and asset tables contain relational security properties (e.g. CVSS, location, owner, internet exposure, RTO, and revenue impact). Querying these structurally using `pandas` guarantees **absolute mathematical determinism** and **high execution speed**. Letting an LLM parse raw CSV tables or calculate scores leads to hallucinated scores, calculation errors, and non-deterministic ranking.

### 2. Why NIST controls were embedded
NIST SP 800-53 Revision 5 contains hundreds of security controls. Finding the exact control that mitigates a technical finding (e.g. SQL Injection or VPN Buffer Overflow) is a natural language mapping problem. By embedding the control descriptions into a vector database (ChromaDB) using `all-MiniLM-L6-v2`, we can perform semantic search queries (e.g., searching for "SQL Injection mitigation" returns `SI-10: Information Input Validation` or `SI-11`) to retrieve matching recommendations. No asset, vulnerability, or business data is embedded.

---

## LLM Scope Boundary

> [!IMPORTANT]
> The Groq LLM (`llama-3.3-70b-versatile`) **ONLY** formats markdown reports, summarizes findings into brief narratives ("Why This Matters"), and generates executive brief introductions. 
> The LLM **NEVER** calculates risk scores, ranks threats, or invents control mappings. Scoring and ranking are 100% deterministic and handled by code in `utils/scoring.py`.

---

## Failure Cases & Handling

1. **Groq API / Network Offline**: If the Groq API key is missing or calls fail (rate limits/timeout), the formatting engine falls back to pre-coded templates and localized action guides without crashing.
2. **CISA KEV / NIST Catalog Fetch Fails**: If fetching the live feeds from CISA or NIST fails, the assistant falls back to a cached local version (`cache/kev.json`, `cache/nist_controls.csv`). If the cache is also empty, it uses a local fallback set of core CVEs and a built-in dictionary of critical NIST controls.
3. **Database / ChromaDB Lockups**: On Windows systems, SQLite/ChromaDB file locks can sometimes occur. If ChromaDB fails to initialize, the system falls back to a custom, lightweight, in-memory numpy-based cosine similarity search using the same sentence embeddings.

---

## Proposed Improvement
**Dynamic Graph-Based Dependency Scoring**: Currently, business service dependency is evaluated simple flat lookups. An improvement would build a dependency graph (using the `depends_on` column in `business_services.csv`) so that a vulnerability on an database server (e.g. `auth-db-01`) automatically inherits the combined risk weight of all upstream systems relying on it (e.g. `Customer Login` -> `Payment Processing`).

---

## How to Run Locally

### 1. Prerequisites
- Python 3.10+
- A Groq API key (optional but recommended for full AI narratives)

### 2. Installation
Clone the repository, then install requirements:
```bash
pip install -r requirements.txt
```

### 3. Configuration
Copy or edit `.env` in the root folder and add your Groq API key:
```env
GROQ_API_KEY=gsk_...
PORT=8000
```

### 4. Running the Dev Server
Start the FastAPI server:
```bash
python main.py
```
Or use `uvicorn`:
```bash
python -m uvicorn main:app --reload --port 8000
```

### 5. Accessing the Reports
- **Health Check**: Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Generate Cyber Risk Report**: Open [http://127.0.0.1:8000/analyze](http://127.0.0.1:8000/analyze)
