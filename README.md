# RiskLens AI

> Deterministic scoring. Semantic retrieval. AI narration. Zero hallucinated risk scores.

RiskLens AI turns raw asset and vulnerability data into ranked, NIST-mapped risk reports.
Math handles all scoring. The LLM only writes the report.

---

## What It Does

1. Loads asset, vulnerability, and business service data from CSVs
2. Scores every open vulnerability using a 6-factor formula (no LLM involved)
3. Cross-references CVEs against the live **CISA KEV** exploit catalog
4. Finds matching **NIST SP 800-53** controls via semantic search (RAG)
5. Generates a ranked Markdown risk brief using **Groq LLM** (formatting only)

---

## Why the LLM Doesn't Score Risk

LLMs hallucinate numbers and produce different results each run.
All scoring in RiskLens is pure Python math — deterministic, auditable, fast.
The LLM only formats the final report.

---

## Risk Score Formula

Each vulnerability gets a score from 0 to 1:

```
score = 0.15 × CVSS
      + 0.15 × exploit available (KEV or PoC)
      + 0.25 × active threat campaign match
      + 0.10 × internet exposed
      + 0.30 × business criticality (RTO, revenue, compliance, customer-facing)
      + 0.05 × days open
      − 0.10 × compensating controls (EDR, WAF, patch)
```

---

## Agentic Vendor Assessment

For compliance questions like *"Does this vendor meet SOC 2 access control requirements?"*, the system runs a **Plan → Act → Check** loop:

- **Plan** — LLM breaks the question into atomic sub-checks
- **Act** — Retrieves vendor document chunks, extracts a verdict + citation
- **Check** — Cross-validates the citation; retries with a stronger model on failure; flags for **Human Review** if still invalid

---

## Tech Stack

| | |
|---|---|
| API | FastAPI |
| Scoring | pandas + pure Python |
| NIST RAG | ChromaDB + `all-MiniLM-L6-v2` |
| LLM | Groq (`llama-3.3-70b-versatile`) |
| Threat Intel | CISA KEV API |
| Vector Fallback | NumPy cosine similarity |

---

## Running Locally

```bash
pip install -r requirements.txt
```

Add to `.env`:
```
GROQ_API_KEY=gsk_...
```

Start:
```bash
python main.py
```

| Endpoint | Description |
|---|---|
| `GET /` | Health check |
| `GET /analyze` | Run full risk report |
| `POST /assess` | Vendor compliance check |
| `GET /eval` | Evaluation metrics |
| `GET /dashboard` | HTML dashboard |
