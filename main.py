import os
import pandas as pd
from fastapi import FastAPI, Response, HTTPException
from fastapi.responses import PlainTextResponse
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

# Initialize RAG and Groq Wrapper globally
# We wrap it in a try-except block to handle case when downloads fail
try:
    print("Pre-initializing systems...")
    rag = NistRAG()
    llm_wrapper = GroqClientWrapper()
except Exception as e:
    print(f"Error pre-initializing systems: {e}")
    rag = None
    llm_wrapper = None

def load_data():
    """
    Loads all CSV files and handles missing files/directories gracefully.
    """
    data_dir = "data"
    files = {
        "assets": "assets.csv",
        "vulnerabilities": "vulnerabilities.csv",
        "business_services": "business_services.csv",
        "threat_intelligence": "threat_intelligence.csv",
        "remediation_guidance": "remediation_guidance.csv"
    }
    
    loaded = {}
    for key, filename in files.items():
        path = os.path.join(data_dir, filename)
        if not os.path.exists(path):
            # Fallback path (maybe direct Dataset/ directory if data/ failed to copy somehow)
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

def find_local_remediation(vuln_name, remediation_df):
    """
    Finds the most relevant local remediation action from remediation_guidance.csv
    using word overlap and substring matching.
    """
    best_match = None
    best_score = 0
    vuln_name_lower = str(vuln_name).lower()
    
    for _, row in remediation_df.iterrows():
        finding_type = str(row.get("finding_type", "")).lower()
        if not finding_type:
            continue
            
        # Exact/substring match
        if finding_type in vuln_name_lower or vuln_name_lower in finding_type:
            return str(row.get("recommended_action", ""))
            
        # Word overlap
        vuln_words = set(vuln_name_lower.split())
        finding_words = set(finding_type.split())
        overlap = len(vuln_words.intersection(finding_words))
        
        if overlap > best_score:
            best_score = overlap
            best_match = str(row.get("recommended_action", ""))
            
    if best_match:
        return best_match
    return "Apply vendor patches immediately, review access configurations, and monitor system logs for indicators of compromise."

@app.get("/")
def health_check():
    """
    Simple health check endpoint.
    """
    return {
        "status": "healthy",
        "app": "RiskLens AI",
        "description": "Cyber Risk Assistant Online"
    }

@app.get("/analyze")
def analyze_risks():
    """
    Runs the risk analysis pipeline:
    1. Loads all CSV data
    2. Fetches CISA KEV
    3. Scores all open vulnerabilities
    4. Ranks and picks Top 5
    5. Retrieves NIST controls via RAG
    6. Generates executive summary and why-this-matters via Groq/mock LLM
    7. Returns Markdown report
    """
    global rag, llm_wrapper
    
    # Initialize components if not already initialized
    if rag is None:
        try:
            rag = NistRAG()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to initialize NIST RAG: {e}")
            
    if llm_wrapper is None:
        try:
            llm_wrapper = GroqClientWrapper()
        except Exception as e:
            print(f"LLM wrapper initialization error: {e}")
            llm_wrapper = GroqClientWrapper()

    # 1. Load Data
    try:
        data = load_data()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Data loading failed: {str(e)}")
        
    df_assets = data["assets"]
    df_vulns = data["vulnerabilities"]
    df_business = data["business_services"]
    df_threat = data["threat_intelligence"]
    df_remediation = data["remediation_guidance"]
    
    # User constraint: Rename matched_cve_or_control -> matched_cve during ingestion
    if "matched_cve_or_control" in df_threat.columns:
        df_threat.rename(columns={"matched_cve_or_control": "matched_cve"}, inplace=True)
        
    # 2. Fetch CISA KEV (with fallbacks built-in)
    kev_cves = fetch_cisa_kev()
    
    # 3. Score all Open Vulnerabilities
    scored_risks = []
    
    # Filter for open vulnerabilities only (case-insensitive)
    open_vulns = df_vulns[df_vulns["status"].str.strip().str.lower() == "open"]
    
    for _, vuln_row in open_vulns.iterrows():
        asset_id = vuln_row.get("asset_id")
        # Find corresponding asset
        asset_rows = df_assets[df_assets["asset_id"] == asset_id]
        if asset_rows.empty:
            continue  # skip vulnerability if asset not in inventory
            
        asset_row = asset_rows.iloc[0]
        
        # Calculate risk details
        risk_details = calculate_risk_score(
            vuln_row=vuln_row,
            asset_row=asset_row,
            business_services_df=df_business,
            threat_intel_df=df_threat,
            kev_cves=kev_cves
        )
        
        # Build combined risk record
        scored_risks.append({
            "asset_id": asset_id,
            "asset_name": str(asset_row.get("asset_name")),
            "vuln_id": vuln_row.get("vuln_id"),
            "vuln_name": str(vuln_row.get("vulnerability_name")),
            "cve": str(vuln_row.get("cve")),
            "affected_component": str(vuln_row.get("affected_component")),
            "business_service": str(asset_row.get("business_service")),
            "internet_exposed": str(asset_row.get("internet_exposed", "No")),
            "owner_team": risk_details["owner_team"],
            "days_since_seen": float(asset_row.get("last_seen_days", 0)),
            
            # Scoring inputs & outputs
            "score": risk_details["score"],
            "cvss": risk_details["cvss"],
            "exploit_status": risk_details["exploit_status"],
            "campaign_name": risk_details["campaign_name"],
            "threat_confidence": risk_details["threat_confidence"],
            "is_orphaned": risk_details["is_orphaned"],
            "is_stale": risk_details["is_stale"],
            "asset_criticality_raw": str(asset_row.get("criticality", "medium")),
            
            # Local remediation info
            "local_remediation_guidance": find_local_remediation(vuln_row.get("vulnerability_name"), df_remediation)
        })
        
    if not scored_risks:
        raise HTTPException(status_code=404, detail="No open vulnerabilities found to analyze.")
        
    # 4. Rank and select Top 5
    # Sort by score descending, then by CVSS descending, then by days open descending
    scored_risks.sort(key=lambda x: (x["score"], x["cvss"], x["days_since_seen"]), reverse=True)
    top_5_risks = scored_risks[:5]
    
    # 5. Retrieve NIST controls via RAG (top 1-3 controls only)
    for risk in top_5_risks:
        # Build query for NIST SP 800-53 retrieval
        query = f"Vulnerability: {risk['vuln_name']} ({risk['cve']}). Affected component: {risk['affected_component']}."
        retrieved = rag.retrieve_controls(query, top_k=2)
        
        # Attach the top retrieved control (or None if retrieval was empty)
        risk["nist_control"] = retrieved[0] if retrieved else None
        # We can also keep track of alternative controls if we want, but top 1 is enough for report formatting
        risk["all_retrieved_controls"] = retrieved
        
    # 6. Format Markdown Report using enriched LLM summaries
    try:
        report_markdown = format_markdown_report(top_5_risks, llm_wrapper)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Markdown generation failed: {str(e)}")
        
    return Response(content=report_markdown, media_type="text/markdown")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f"Starting RiskLens AI on port {port}...")
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
