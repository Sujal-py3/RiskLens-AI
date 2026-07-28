# RiskLens AI — Cyber Risk Assistant

RiskLens AI is an intern-level, practical cyber risk assessment assistant built with FastAPI, pandas, ChromaDB, and Groq LLM API. It parses synthetic asset and threat intelligence datasets, calculates deterministic cyber risk scores, retrieves NIST SP 800-53 security controls, and formats readable executive briefs.

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
