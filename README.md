# RiskLens AI — Cyber Risk Assistant

A deterministic cyber risk analysis API built with FastAPI, pandas, ChromaDB, and Groq LLM.

It scores open vulnerabilities against a 6-factor model, retrieves NIST SP 800-53 controls via semantic search, and generates concise executive risk briefs — with optional AI narrative enhancement via Groq Llama 3.3 70B.

---

## Architecture

| Component | Role |
|---|---|
| `utils/scoring.py` | 100% deterministic 6-factor risk scoring (CVSS, exploit status, threat intel, internet exposure, business criticality, days open) |
| `utils/retrieval.py` | Fetches CISA KEV + NIST SP 800-53 Rev 5 catalog; semantic RAG via ChromaDB / numpy fallback |
| `utils/formatter.py` | Report formatting; Groq LLM for narrative text only (never for scoring or ranking) |
| `main.py` | FastAPI app — loads CSVs, runs pipeline, returns Markdown report |

> **LLM scope boundary:** Groq is used only to summarise and narrate findings. All scoring, ranking, and control selection is deterministic Python.

---

## Local Setup

### Prerequisites
- Python 3.10+
- (Optional) A Groq API key for AI-enhanced narratives — the app works without one using deterministic fallbacks

### 1. Clone and install

```bash
git clone https://github.com/your-username/risklens-ai.git
cd risklens-ai
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
GROQ_API_KEY=gsk_your_key_here   # optional
PORT=8000
```

### 3. Run locally

```bash
python main.py
```

Or with uvicorn directly:

```bash
uvicorn main:app --reload --port 8000
```

### 4. API endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Health check |
| `GET /analyze` | Run full risk analysis — returns Markdown report |
| `GET /dashboard` | Frontend HTML dashboard |

Example:

```bash
curl http://127.0.0.1:8000/analyze
```

---

## Cache Behaviour

On first run, the app automatically fetches and caches:

| Cache file | Source | Fallback |
|---|---|---|
| `cache/nist_controls.csv` | NIST SP 800-53 Rev 5 OSCAL catalog (GitHub) | Built-in 12-control dictionary |
| `cache/kev.json` | CISA Known Exploited Vulnerabilities feed | Built-in core CVE set |

If either fetch fails (network unavailable), the fallback is used silently. The `cache/` directory is created automatically and is excluded from git.

---

## Railway Deployment

### 1. Push to GitHub

Make sure your repository includes:

```
├── main.py
├── Procfile
├── railway.toml
├── requirements.txt
├── .env.example
├── data/
└── utils/
```

### 2. Create a Railway project

1. Go to [railway.app](https://railway.app) and create a new project
2. Connect your GitHub repository
3. Railway auto-detects Python via nixpacks

### 3. Set environment variables

In the Railway dashboard → **Variables**, add:

```
GROQ_API_KEY = gsk_your_key_here
```

`PORT` is set automatically by Railway — do not override it.

### 4. Deploy

Railway will build and deploy automatically on every push to `main`.

The start command (from `railway.toml`) is:

```
uvicorn main:app --host 0.0.0.0 --port $PORT
```

### 5. Access the deployed API

```
https://your-project.up.railway.app/
https://your-project.up.railway.app/analyze
https://your-project.up.railway.app/dashboard
```

---

## Failure Handling

| Failure | Behaviour |
|---|---|
| Groq API key missing or rate-limited | Falls back to deterministic narrative templates — no crash |
| CISA KEV fetch fails | Uses local `cache/kev.json`; then built-in core CVE set |
| NIST catalog fetch fails | Uses local `cache/nist_controls.csv`; then built-in 12-control dictionary |
| ChromaDB unavailable | Falls back to in-memory numpy cosine similarity search |

---

## Design Notes

**Why CSVs + pandas instead of a database?**
The vulnerability and asset tables are small, relational, and change infrequently. pandas gives absolute determinism and fast startup with no external database dependency — ideal for a deployable, self-contained API.

**Why embed NIST controls instead of hardcoding mappings?**
NIST SP 800-53 Rev 5 has over 1,000 controls. Semantic embedding (via `all-MiniLM-L6-v2` + ChromaDB) lets the retriever find the most relevant control for any vulnerability description without maintaining a brittle manual mapping table.
