# RiskLens AI: Agentic Vendor Risk Assessment

RiskLens AI has been upgraded from a generic RAG tool into an **agentic vendor risk assessment system**. It processes vendor compliance documents (e.g., SOC2, PCI statements) using a sophisticated **Plan-Act-Check loop** to automatically extract verdicts and prevent hallucinations.

## Architecture: Plan-Act-Check Loop

The core orchestration operates in three steps for every compliance query:

1. **PLAN**: The reasoning model (`llama-3.3-70b-versatile`) decomposes the complex compliance question into distinct, verifiable sub-checks.
2. **ACT**: For each sub-check, the system retrieves relevant document chunks via RAG (FAISS + SentenceTransformers). It uses a fast classification model (`llama-3.1-8b-instant`) to extract a verdict (`pass`/`fail`/`unclear`) and the supporting citation.
3. **CHECK**: The fast model cross-validates the citation against the sub-check and verdict. If the citation does not logically support the verdict (a hallucination), the check is failed and flagged for **Human Review**.

Finally, an aggregation step computes an overall vendor risk score and lists concrete remediation actions.

## Evaluation Harness Metrics

We evaluate the agent using an automated test suite containing labeled vendor document snippets.

- **Accuracy on verdicts**: The rate at which the agent correctly identifies pass/fail/unclear states.
- **Hallucination detection**: The number of unsupported citations caught by the CHECK step.
- **Human Review**: The rate of correct delegation to humans for ambiguous or hallucinated results.

*(Run the Eval Harness in the dashboard to generate live metrics!)*

## Getting Started

1. Set your `GROQ_API_KEY` in the `.env` file.
2. Install requirements: `pip install -r requirements.txt`
3. Run the backend: `python main.py` or `uvicorn main:app --reload`
4. Access the dashboard at [http://localhost:8000/dashboard](http://localhost:8000/dashboard)
