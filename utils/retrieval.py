import os
import json
import csv
import requests
import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer

# Create cache directory if it doesn't exist
os.makedirs("cache", exist_ok=True)

# -------------------------------------------------------------
# CISA KEV Fetcher and Fallback
# -------------------------------------------------------------

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = os.path.join("cache", "kev.json")

# Core CVEs from our dataset to seed local fallback if network is down and cache is empty
CORE_KEV_FALLBACK = {
    "CVE-2024-21762", "CVE-2024-55591", "CVE-2023-22527", "CVE-2023-22515",
    "CVE-2024-27198", "CVE-2024-23897", "CVE-2023-4966", "CVE-2024-4577",
    "CVE-2024-10978", "CVE-2024-28986", "CVE-2024-28987", "CVE-2024-30051",
    "CVE-2024-43451", "CVE-2024-20353", "CVE-2024-20358"
}

def fetch_cisa_kev():
    """
    Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog.
    Falls back to cache or a local core list if network or parsing fails.
    """
    try:
        print(f"Fetching CISA KEV from {CISA_KEV_URL}...")
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Save to cache
        with open(KEV_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
        cves = {vuln["cveID"].strip().upper() for vuln in data.get("vulnerabilities", [])}
        print(f"Successfully loaded {len(cves)} CVEs from CISA KEV.")
        return cves
    except Exception as e:
        print(f"CISA KEV fetch failed: {e}. Checking local cache...")
        if os.path.exists(KEV_CACHE_PATH):
            try:
                with open(KEV_CACHE_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                cves = {vuln["cveID"].strip().upper() for vuln in data.get("vulnerabilities", [])}
                print(f"Successfully loaded {len(cves)} CVEs from local cache.")
                return cves
            except Exception as cache_err:
                print(f"Error reading KEV cache: {cache_err}")
                
        print("Using static core KEV fallback list.")
        return CORE_KEV_FALLBACK

# -------------------------------------------------------------
# NIST SP 800-53 Revision 5 Parsing, Caching, and Fallback
# -------------------------------------------------------------

NIST_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
NIST_CACHE_PATH = os.path.join("cache", "nist_controls.csv")

FALLBACK_NIST_CONTROLS = [
    {"control_id": "AC-2", "title": "Account Management", "prose": "The organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and terminating accounts in accordance with established procedures."},
    {"control_id": "AC-3", "title": "Access Enforcement", "prose": "The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies."},
    {"control_id": "AC-7", "title": "Unsuccessful Logon Attempts", "prose": "The information system enforces a limit of consecutive invalid logon attempts by a user during a specified time period and automatically locks the account."},
    {"control_id": "AC-12", "title": "Session Termination", "prose": "The information system automatically terminates a user session after a defined condition or period of inactivity."},
    {"control_id": "CA-7", "title": "Continuous Monitoring", "prose": "The organization establishes a continuous monitoring program that includes configuration management, security impact analyses of changes, and ongoing assessment of security controls."},
    {"control_id": "CM-2", "title": "Baseline Configuration", "prose": "The organization develops, documents, and maintains under configuration control, a current baseline configuration of the information system."},
    {"control_id": "IA-2", "title": "Identification and Authentication (Organizational Users)", "prose": "The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users). Enforces multi-factor authentication (MFA)."},
    {"control_id": "PE-3", "title": "Physical Access Control", "prose": "The organization enforces physical access authorizations for entry and exit at physical facilities containing information systems."},
    {"control_id": "SC-7", "title": "Boundary Protection", "prose": "The information system monitors and controls communications at the external boundary of the system and at key internal boundaries using firewalls, gateways, and proxies."},
    {"control_id": "SC-28", "title": "Protection of Information at Rest", "prose": "The information system protects the confidentiality and integrity of information at rest using cryptographic mechanisms."},
    {"control_id": "SI-2", "title": "Flaw Remediation", "prose": "The organization identifies, reports, and corrects information system flaws (patches) in a timely manner, deploying security updates to resolve known vulnerabilities."},
    {"control_id": "SI-4", "title": "Information System Monitoring", "prose": "The organization monitors the information system to detect attacks, unauthorized connections, and indicators of potential compromise."},
]

def collect_all_prose(obj):
    """
    Recursively collects all prose strings under the given object, skipping nested 'controls'.
    """
    prose_list = []
    if isinstance(obj, dict):
        if "prose" in obj and obj["prose"]:
            prose_list.append(str(obj["prose"]))
        for k, v in obj.items():
            if k != "controls":
                prose_list.extend(collect_all_prose(v))
    elif isinstance(obj, list):
        for item in obj:
            prose_list.extend(collect_all_prose(item))
    return prose_list

def extract_controls_recursive(control_list):
    """
    Recursively parses OSCAL control structures to extract control ID, title, and statement prose.
    """
    extracted = []
    for ctrl in control_list:
        # Check if control is withdrawn
        is_withdrawn = False
        for prop in ctrl.get("props", []):
            if prop.get("name") == "status" and str(prop.get("value")).strip().lower() == "withdrawn":
                is_withdrawn = True
                break
                
        if is_withdrawn:
            # Still process nested child controls if any exist
            if "controls" in ctrl:
                extracted.extend(extract_controls_recursive(ctrl["controls"]))
            continue
            
        ctrl_id = str(ctrl.get("id", "")).strip().upper()
        title = str(ctrl.get("title", "")).strip()
        
        # Recursively collect all prose blocks in the control object (excluding nested controls)
        prose_parts = collect_all_prose(ctrl)
        prose = " ".join(prose_parts).strip()
            
        if ctrl_id and (title or prose):
            extracted.append({
                "control_id": ctrl_id,
                "title": title,
                "prose": prose
            })
            
        # Recursive call for control enhancements
        if "controls" in ctrl:
            extracted.extend(extract_controls_recursive(ctrl["controls"]))
            
    return extracted

def parse_groups_recursive(group_list):
    """
    Recursively parses OSCAL groups to find controls.
    """
    extracted = []
    for group in group_list:
        # Parse controls in this group
        if "controls" in group:
            extracted.extend(extract_controls_recursive(group["controls"]))
            
        # Parse subgroups in this group
        if "groups" in group:
            extracted.extend(parse_groups_recursive(group["groups"]))
            
    return extracted

def fetch_and_cache_nist_controls():
    """
    Fetches the official NIST SP 800-53 Revision 5 catalog in OSCAL format, parses it, and caches it as CSV.
    Uses pre-populated fallback list if fetching fails.
    """
    if os.path.exists(NIST_CACHE_PATH):
        print(f"Loading NIST controls from existing cache: {NIST_CACHE_PATH}")
        return
        
    try:
        print(f"Downloading NIST SP 800-53 Rev 5 Catalog from {NIST_URL}...")
        response = requests.get(NIST_URL, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        groups = data.get("catalog", {}).get("groups", [])
        controls = parse_groups_recursive(groups)
        
        if not controls:
            raise ValueError("No controls parsed from JSON.")
            
        # Save to CSV
        with open(NIST_CACHE_PATH, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["control_id", "title", "prose"])
            writer.writeheader()
            writer.writerows(controls)
            
        print(f"Successfully cached {len(controls)} NIST controls to {NIST_CACHE_PATH}.")
    except Exception as e:
        print(f"NIST controls fetch failed: {e}. Writing fallback catalog to cache...")
        try:
            with open(NIST_CACHE_PATH, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["control_id", "title", "prose"])
                writer.writeheader()
                writer.writerows(FALLBACK_NIST_CONTROLS)
            print(f"Wrote {len(FALLBACK_NIST_CONTROLS)} fallback controls to {NIST_CACHE_PATH}.")
        except Exception as write_err:
            print(f"Critical error writing NIST controls fallback: {write_err}")

# -------------------------------------------------------------
# NIST SP 800-53 RAG (ChromaDB + In-Memory Fallback)
# -------------------------------------------------------------

class NistRAG:
    def __init__(self):
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.controls_df = None
        self.use_chromadb = False
        self.collection = None
        
        # Ensure controls are cached
        fetch_and_cache_nist_controls()
        
        # Load the catalog
        try:
            self.controls_df = pd.read_csv(NIST_CACHE_PATH)
            # Ensure text columns are clean
            self.controls_df["prose"] = self.controls_df["prose"].fillna("")
            self.controls_df["title"] = self.controls_df["title"].fillna("")
            self.controls_df["control_id"] = self.controls_df["control_id"].fillna("").astype(str).str.strip().str.upper()
            
            # Create set of valid control IDs for validation
            self.valid_control_ids = set(self.controls_df["control_id"].tolist())
        except Exception as e:
            print(f"Error loading cached NIST controls CSV: {e}")
            self.controls_df = pd.DataFrame(FALLBACK_NIST_CONTROLS)
            self.valid_control_ids = {c["control_id"] for c in FALLBACK_NIST_CONTROLS}
            
        # Initialize RAG index
        self._initialize_index()

    def _initialize_index(self):
        """
        Attempts to initialize ChromaDB. If it fails, sets up an in-memory numpy embedding database.
        """
        # Get descriptions to embed
        documents = []
        for _, row in self.controls_df.iterrows():
            doc = f"Control ID: {row['control_id']}\nTitle: {row['title']}\nDescription: {row['prose']}"
            documents.append(doc)
            
        try:
            print("Initializing ChromaDB collection...")
            import chromadb
            # Use in-memory ChromaDB client for maximum speed and zero locking issues
            self.chroma_client = chromadb.Client()
            self.collection = self.chroma_client.create_collection("nist_controls")
            
            # Embed all controls
            embeddings = self.model.encode(documents).tolist()
            metadatas = [
                {"control_id": row["control_id"], "title": row["title"], "prose": row["prose"]}
                for _, row in self.controls_df.iterrows()
            ]
            ids = self.controls_df["control_id"].tolist()
            
            self.collection.add(
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            self.use_chromadb = True
            print("ChromaDB initialized and populated successfully.")
        except Exception as e:
            print(f"ChromaDB initialization failed: {e}. Falling back to in-memory numpy vector similarity search.")
            self.use_chromadb = False
            # Precompute embeddings for fast in-memory search
            self.document_texts = documents
            self.control_embeddings = self.model.encode(documents)

    def retrieve_controls(self, query, top_k=2):
        """
        Retrieves the top_k NIST controls matching the query.
        Validates that retrieved control IDs exist in our catalog.
        """
        results = []
        
        if not query:
            return results
            
        try:
            if self.use_chromadb and self.collection is not None:
                # Query ChromaDB
                query_emb = self.model.encode(query).tolist()
                query_results = self.collection.query(
                    query_embeddings=[query_emb],
                    n_results=top_k
                )
                
                if query_results and "metadatas" in query_results and len(query_results["metadatas"]) > 0:
                    for meta in query_results["metadatas"][0]:
                        cid = str(meta["control_id"]).strip().upper()
                        # Simple validation: ensure control ID exists in NIST
                        if cid in self.valid_control_ids:
                            results.append({
                                "control_id": cid,
                                "title": meta["title"],
                                "prose": meta["prose"]
                            })
            else:
                # Pure in-memory numpy search
                query_emb = self.model.encode(query)
                # Compute cosine similarities
                norm_docs = np.linalg.norm(self.control_embeddings, axis=1)
                norm_query = np.linalg.norm(query_emb)
                
                # Prevent division by zero
                if norm_query > 0 and len(norm_docs) > 0:
                    sims = np.dot(self.control_embeddings, query_emb) / (norm_docs * norm_query)
                    top_indices = np.argsort(sims)[::-1][:top_k]
                    
                    for idx in top_indices:
                        row = self.controls_df.iloc[int(idx)]
                        cid = str(row["control_id"]).strip().upper()
                        if cid in self.valid_control_ids:
                            results.append({
                                "control_id": cid,
                                "title": row["title"],
                                "prose": row["prose"]
                            })
        except Exception as e:
            print(f"RAG retrieval error: {e}. Falling back to basic text matching...")
            # Fallback to simple keyword match
            keywords = query.lower().split()
            matched_indices = []
            for idx, row in self.controls_df.iterrows():
                text = f"{row['control_id']} {row['title']} {row['prose']}".lower()
                matches = sum(1 for kw in keywords if kw in text)
                if matches > 0:
                    matched_indices.append((matches, idx))
                    
            matched_indices.sort(reverse=True)
            for _, idx in matched_indices[:top_k]:
                row = self.controls_df.iloc[idx]
                results.append({
                    "control_id": str(row["control_id"]).strip().upper(),
                    "title": row["title"],
                    "prose": row["prose"]
                })
                
        return results
