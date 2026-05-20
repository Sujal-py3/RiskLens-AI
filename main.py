import os
import pandas as pd
from fastapi import FastAPI, Response, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

from utils.scoring import calculate_risk_score
from utils.retrieval import fetch_cisa_kev, NistRAG
from utils.formatter import GroqClientWrapper, format_markdown_report

load_dotenv()

app = FastAPI(
    title="RiskLens AI",
    description="Intern-Level AI Cyber Risk Assistant",
    version="1.0.0"
)

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    html_path = os.path.join(static_dir, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


# Lazy singletons — heavy components load only on first /analyze request.
_rag = None
_llm = None

def _get_rag():
    global _rag
    if _rag is None:
        print("First request — loading embedding model and building vector index...")
        _rag = NistRAG()
    return _rag

def _get_llm():
    global _llm
    if _llm is None:
        _llm = GroqClientWrapper()
    return _llm

print("RiskLens AI ready (lightweight mode — heavy components load on first /analyze request).")


def load_data() -> dict:
    """Load all required CSV datasets. Raises on any missing file."""
    data_dir = "data"
    files = {
        "assets":               "assets.csv",
        "vulnerabilities":      "vulnerabilities.csv",
        "business_services":    "business_services.csv",
        "threat_intelligence":  "threat_intelligence.csv",
        "remediation_guidance": "remediation_guidance.csv",
    }
    loaded = {}
    for key, filename in files.items():
        path = os.path.join(data_dir, filename)
        if not os.path.exists(path):
            alt_path = os.path.join("Dataset", filename)
            if os.path.exists(alt_path):
                path = alt_path
            else:
                raise FileNotFoundError(f"Required CSV file missing: {path}")
        try:
            loaded[key] = pd.read_csv(path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to load {filename}: {str(e)}")
    return loaded


def find_local_remediation(vuln_name: str, remediation_df: pd.DataFrame) -> str:
    """
    Match a vulnerability name to a local remediation action using substring
    and word-overlap matching. Returns a generic fallback if no match is found.
    """
    best_match = None
    best_score = 0
    vuln_lower = str(vuln_name).lower()

    for _, row in remediation_df.iterrows():
        finding = str(row.get("finding_type", "")).lower()
        if not finding:
            continue
        if finding in vuln_lower or vuln_lower in finding:
            return str(row.get("recommended_action", ""))
        overlap = len(set(vuln_lower.split()) & set(finding.split()))
        if overlap > best_score:
            best_score = overlap
            best_match = str(row.get("recommended_action", ""))

    return best_match or "Apply vendor patches immediately, review access configurations, and monitor system logs for indicators of compromise."


@app.get("/")
def health_check():
    return {"status": "healthy", "app": "RiskLens AI", "description": "Cyber Risk Assistant Online"}


@app.get("/analyze")
def analyze_risks():
    """
    Risk analysis pipeline:
      1. Load CSV datasets
      2. Fetch CISA KEV catalog
      3. Score all open vulnerabilities (deterministic 6-factor model)
      4. Rank and select Top 5
      5. Retrieve NIST SP 800-53 controls via RAG
      6. Generate and return a Markdown risk brief
    """
    rag = _get_rag()
    llm = _get_llm()

    try:
        data = load_data()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Data loading failed: {str(e)}")

    df_assets      = data["assets"]
    df_vulns       = data["vulnerabilities"]
    df_business    = data["business_services"]
    df_threat      = data["threat_intelligence"]
    df_remediation = data["remediation_guidance"]

    if "matched_cve_or_control" in df_threat.columns:
        df_threat.rename(columns={"matched_cve_or_control": "matched_cve"}, inplace=True)

    kev_cves     = fetch_cisa_kev()
    open_vulns   = df_vulns[df_vulns["status"].str.strip().str.lower() == "open"]
    scored_risks = []

    for _, vuln_row in open_vulns.iterrows():
        asset_id   = vuln_row.get("asset_id")
        asset_rows = df_assets[df_assets["asset_id"] == asset_id]
        if asset_rows.empty:
            continue

        asset_row    = asset_rows.iloc[0]
        risk_details = calculate_risk_score(
            vuln_row=vuln_row,
            asset_row=asset_row,
            business_services_df=df_business,
            threat_intel_df=df_threat,
            kev_cves=kev_cves,
        )

        service_name = str(asset_row.get("business_service", "")).strip().lower()
        service_rows = df_business[df_business["business_service"].str.strip().str.lower() == service_name]
        if not service_rows.empty:
            svc = service_rows.iloc[0]
            customer_facing  = str(svc.get("customer_facing",  "No")).strip()
            compliance_scope = str(svc.get("compliance_scope", "None")).strip()
            rto_val          = svc.get("rto_hours")
            rto              = f"{rto_val} h" if pd.notna(rto_val) else "N/A"
            revenue_impact   = str(svc.get("revenue_impact", "Low")).strip()
        else:
            customer_facing  = "No"
            compliance_scope = "None"
            rto              = "N/A"
            revenue_impact   = "Low"

        scored_risks.append({
            "asset_name":           str(asset_row.get("asset_name")),
            "vuln_name":            str(vuln_row.get("vulnerability_name")),
            "cve":                  str(vuln_row.get("cve")),
            "affected_component":   str(vuln_row.get("affected_component")),
            "business_service":     str(asset_row.get("business_service")),
            "internet_exposed":     str(asset_row.get("internet_exposed", "No")),
            "owner_team":           risk_details["owner_team"],
            "days_since_seen":      float(asset_row.get("last_seen_days", 0)),
            "score":                risk_details["score"],
            "cvss":                 risk_details["cvss"],
            "exploit_status":       risk_details["exploit_status"],
            "is_in_kev":            risk_details["is_in_kev"],
            "campaign_name":        risk_details["campaign_name"],
            "threat_confidence":    risk_details["threat_confidence"],
            "ransomware_association": risk_details["ransomware_association"],
            "target_region":        risk_details["target_region"],
            "is_orphaned":          risk_details["is_orphaned"],
            "is_stale":             risk_details["is_stale"],
            "asset_criticality_raw": str(asset_row.get("criticality", "medium")),
            "customer_facing":      customer_facing,
            "compliance_scope":     compliance_scope,
            "rto":                  rto,
            "revenue_impact":       revenue_impact,
            "local_remediation_guidance": find_local_remediation(
                vuln_row.get("vulnerability_name"), df_remediation
            ),
        })

    if not scored_risks:
        raise HTTPException(status_code=404, detail="No open vulnerabilities found to analyze.")

    scored_risks.sort(key=lambda x: (x["score"], x["cvss"], x["days_since_seen"]), reverse=True)
    top_risks = scored_risks[:5]

    for risk in top_risks:
        query = f"Vulnerability: {risk['vuln_name']} ({risk['cve']}). Affected component: {risk['affected_component']}."
        retrieved = rag.retrieve_controls(query, top_k=2)
        risk["nist_control"] = retrieved[0] if retrieved else None

    try:
        report_markdown = format_markdown_report(top_risks, llm)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Markdown generation failed: {str(e)}")

    return Response(content=report_markdown, media_type="text/markdown")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f"Starting RiskLens AI on port {port}...")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
