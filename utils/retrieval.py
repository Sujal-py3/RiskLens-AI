import os
import json
import csv
import requests
import pandas as pd
import numpy as np
from sentence_transformers import SentenceTransformer

os.makedirs("cache", exist_ok=True)

# ── CISA KEV ──────────────────────────────────────────────────────────────────

CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = os.path.join("cache", "kev.json")

# Core CVEs present in our vulnerability dataset — used as a last-resort fallback.
_KEV_CORE_FALLBACK = {
    "CVE-2024-21762", "CVE-2024-55591", "CVE-2023-22527", "CVE-2023-22515",
    "CVE-2024-27198", "CVE-2024-23897", "CVE-2023-4966",  "CVE-2024-4577",
    "CVE-2024-10978", "CVE-2024-28986", "CVE-2024-28987", "CVE-2024-30051",
    "CVE-2024-43451", "CVE-2024-20353", "CVE-2024-20358",
}


def fetch_cisa_kev() -> set:
    """
    Return a set of CVE IDs from the CISA KEV catalog.
    Falls back to the local cache, then to a hard-coded core set.
    """
    try:
        print(f"Fetching CISA KEV from {CISA_KEV_URL}...")
        r = requests.get(CISA_KEV_URL, timeout=10)
        r.raise_for_status()
        data = r.json()
        with open(KEV_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        cves = {v["cveID"].strip().upper() for v in data.get("vulnerabilities", [])}
        print(f"Successfully loaded {len(cves)} CVEs from CISA KEV.")
        return cves
    except Exception as e:
        print(f"CISA KEV fetch failed: {e}. Checking local cache...")

    if os.path.exists(KEV_CACHE_PATH):
        try:
            with open(KEV_CACHE_PATH, encoding="utf-8") as f:
                data = json.load(f)
            cves = {v["cveID"].strip().upper() for v in data.get("vulnerabilities", [])}
            print(f"Successfully loaded {len(cves)} CVEs from local cache.")
            return cves
        except Exception as e:
            print(f"Error reading KEV cache: {e}")

    print("Using static core KEV fallback list.")
    return _KEV_CORE_FALLBACK


# ── NIST SP 800-53 Rev 5 ──────────────────────────────────────────────────────

NIST_URL        = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
NIST_CACHE_PATH = os.path.join("cache", "nist_controls.csv")

# Minimal fallback catalog used only when the download and cache both fail.
_NIST_FALLBACK = [
    {"control_id": "AC-2",  "title": "Account Management",                          "prose": "The organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and terminating accounts in accordance with established procedures."},
    {"control_id": "AC-3",  "title": "Access Enforcement",                          "prose": "The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies."},
    {"control_id": "AC-7",  "title": "Unsuccessful Logon Attempts",                 "prose": "The information system enforces a limit of consecutive invalid logon attempts by a user during a specified time period and automatically locks the account."},
    {"control_id": "AC-12", "title": "Session Termination",                         "prose": "The information system automatically terminates a user session after a defined condition or period of inactivity."},
    {"control_id": "CA-7",  "title": "Continuous Monitoring",                       "prose": "The organization establishes a continuous monitoring program that includes configuration management, security impact analyses of changes, and ongoing assessment of security controls."},
    {"control_id": "CM-2",  "title": "Baseline Configuration",                      "prose": "The organization develops, documents, and maintains under configuration control, a current baseline configuration of the information system."},
    {"control_id": "IA-2",  "title": "Identification and Authentication",            "prose": "The information system uniquely identifies and authenticates organizational users. Enforces multi-factor authentication (MFA)."},
    {"control_id": "PE-3",  "title": "Physical Access Control",                     "prose": "The organization enforces physical access authorizations for entry and exit at physical facilities containing information systems."},
    {"control_id": "SC-7",  "title": "Boundary Protection",                         "prose": "The information system monitors and controls communications at the external boundary of the system and at key internal boundaries using firewalls, gateways, and proxies."},
    {"control_id": "SC-28", "title": "Protection of Information at Rest",            "prose": "The information system protects the confidentiality and integrity of information at rest using cryptographic mechanisms."},
    {"control_id": "SI-2",  "title": "Flaw Remediation",                            "prose": "The organization identifies, reports, and corrects information system flaws (patches) in a timely manner, deploying security updates to resolve known vulnerabilities."},
    {"control_id": "SI-4",  "title": "Information System Monitoring",               "prose": "The organization monitors the information system to detect attacks, unauthorized connections, and indicators of potential compromise."},
]


def _collect_statement_prose(parts: list) -> list:
    """Recursively collect prose only from 'statement' and 'item' parts in an OSCAL control."""
    result = []
    for part in (parts or []):
        if not isinstance(part, dict):
            continue
        if part.get("name") in ("statement", "item"):
            if part.get("prose"):
                result.append(str(part["prose"]))
            result.extend(_collect_statement_prose(part.get("parts", [])))
    return result


def _collect_all_prose(obj) -> list:
    """Recursively collect all prose strings from an object, skipping nested controls."""
    result = []
    if isinstance(obj, dict):
        if obj.get("prose"):
            result.append(str(obj["prose"]))
        for k, v in obj.items():
            if k != "controls":
                result.extend(_collect_all_prose(v))
    elif isinstance(obj, list):
        for item in obj:
            result.extend(_collect_all_prose(item))
    return result


def _extract_controls(control_list: list) -> list:
    """
    Recursively extract controls from an OSCAL control list.
    Skips withdrawn controls but still processes their children.
    Prose is taken from statement/item parts; falls back to all prose if empty.
    """
    extracted = []
    for ctrl in control_list:
        withdrawn = any(
            p.get("name") == "status" and str(p.get("value", "")).strip().lower() == "withdrawn"
            for p in ctrl.get("props", [])
        )
        if withdrawn:
            extracted.extend(_extract_controls(ctrl.get("controls", [])))
            continue

        ctrl_id = str(ctrl.get("id", "")).strip().upper()
        title   = str(ctrl.get("title", "")).strip()
        prose_parts = _collect_statement_prose(ctrl.get("parts", []))
        if not prose_parts:
            prose_parts = _collect_all_prose(ctrl)
        prose = " ".join(prose_parts).strip()

        if ctrl_id and (title or prose):
            extracted.append({"control_id": ctrl_id, "title": title, "prose": prose})

        extracted.extend(_extract_controls(ctrl.get("controls", [])))

    return extracted


def _parse_groups(group_list: list) -> list:
    """Recursively parse OSCAL groups to extract all controls."""
    extracted = []
    for group in group_list:
        extracted.extend(_extract_controls(group.get("controls", [])))
        extracted.extend(_parse_groups(group.get("groups", [])))
    return extracted


def _fetch_and_cache_nist() -> None:
    """
    Download the NIST SP 800-53 Rev 5 OSCAL catalog and cache it as CSV.
    Writes the fallback catalog if the download fails.
    """
    if os.path.exists(NIST_CACHE_PATH):
        print(f"Loading NIST controls from existing cache: {NIST_CACHE_PATH}")
        return

    try:
        print(f"Downloading catalog from {NIST_URL}...")
        r = requests.get(NIST_URL, timeout=15)
        r.raise_for_status()
        groups   = r.json().get("catalog", {}).get("groups", [])
        controls = _parse_groups(groups)
        if not controls:
            raise ValueError("No controls parsed from JSON.")
        with open(NIST_CACHE_PATH, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["control_id", "title", "prose"])
            writer.writeheader()
            writer.writerows(controls)
        print(f"Parsing OSCAL catalog and extracting controls...")
        print(f"Rebuilding NIST control cache: {NIST_CACHE_PATH} ({len(controls)} controls)")
        print("NIST control cache saved successfully.")
    except Exception as e:
        print(f"NIST catalog download failed: {e}. Writing fallback catalog...")
        with open(NIST_CACHE_PATH, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["control_id", "title", "prose"])
            writer.writeheader()
            writer.writerows(_NIST_FALLBACK)


# ── RAG: ChromaDB + in-memory numpy fallback ──────────────────────────────────

class NistRAG:
    """
    Semantic retrieval for NIST SP 800-53 controls.
    Uses ChromaDB when available; falls back to an in-memory numpy cosine search.
    Results are validated against similarity thresholds to prevent irrelevant matches.
    """

    def __init__(self):
        self.model        = SentenceTransformer("all-MiniLM-L6-v2")
        self.use_chromadb = False
        self.collection   = None

        _fetch_and_cache_nist()

        try:
            self.controls_df = pd.read_csv(NIST_CACHE_PATH)
            self.controls_df["prose"]      = self.controls_df["prose"].fillna("")
            self.controls_df["title"]      = self.controls_df["title"].fillna("")
            self.controls_df["control_id"] = (
                self.controls_df["control_id"].fillna("").astype(str).str.strip().str.upper()
            )
        except Exception as e:
            print(f"Error loading NIST controls CSV: {e}")
            self.controls_df = pd.DataFrame(_NIST_FALLBACK)

        self.valid_ids = set(self.controls_df["control_id"].tolist())
        self._build_index()

    def _build_index(self) -> None:
        """Embed all controls and populate the ChromaDB collection (or numpy fallback)."""
        documents = [
            f"Control ID: {row['control_id']}\nTitle: {row['title']}\nDescription: {row['prose']}"
            for _, row in self.controls_df.iterrows()
        ]
        try:
            import chromadb
            print("Initializing ChromaDB collection...")
            self.chroma_client = chromadb.Client()
            self.collection    = self.chroma_client.create_collection("nist_controls")
            embeddings = self.model.encode(documents).tolist()
            self.collection.add(
                embeddings=embeddings,
                documents=documents,
                metadatas=[
                    {"control_id": row["control_id"], "title": row["title"], "prose": row["prose"]}
                    for _, row in self.controls_df.iterrows()
                ],
                ids=self.controls_df["control_id"].tolist(),
            )
            self.use_chromadb = True
            print("ChromaDB initialized and populated successfully.")
        except Exception as e:
            print(f"ChromaDB unavailable: {e}. Using in-memory numpy search.")
            self._doc_texts        = documents
            self._ctrl_embeddings  = self.model.encode(documents)

    def retrieve_controls(self, query: str, top_k: int = 2) -> list:
        """
        Retrieve the top_k NIST controls for a query.

        Similarity thresholds:
          ChromaDB (L2 distance): max 1.3
          Numpy (cosine similarity): min 0.35
        Controls below threshold are discarded to prevent irrelevant matches.
        """
        if not query:
            return []

        try:
            if self.use_chromadb and self.collection:
                query_emb = self.model.encode(query).tolist()
                res       = self.collection.query(query_embeddings=[query_emb], n_results=top_k)
                results   = []
                if res and res.get("metadatas"):
                    for meta, dist in zip(res["metadatas"][0], res.get("distances", [[]])[0]):
                        if dist > 1.3:
                            continue
                        cid = str(meta["control_id"]).strip().upper()
                        if cid in self.valid_ids:
                            results.append({"control_id": cid, "title": meta["title"], "prose": meta["prose"]})
                return results

            # Numpy cosine similarity fallback
            query_emb = self.model.encode(query)
            norms     = np.linalg.norm(self._ctrl_embeddings, axis=1)
            norm_q    = np.linalg.norm(query_emb)
            if norm_q == 0 or len(norms) == 0:
                return []
            sims       = np.dot(self._ctrl_embeddings, query_emb) / (norms * norm_q)
            top_idx    = np.argsort(sims)[::-1][:top_k]
            results    = []
            for idx in top_idx:
                if sims[idx] < 0.35:
                    continue
                row = self.controls_df.iloc[int(idx)]
                cid = str(row["control_id"]).strip().upper()
                if cid in self.valid_ids:
                    results.append({"control_id": cid, "title": row["title"], "prose": row["prose"]})
            return results

        except Exception as e:
            print(f"RAG retrieval error: {e}. Falling back to keyword search...")
            # Keyword overlap fallback — requires at least 2 matching tokens
            keywords = query.lower().split()
            scored   = []
            for idx, row in self.controls_df.iterrows():
                text  = f"{row['control_id']} {row['title']} {row['prose']}".lower()
                score = sum(1 for kw in keywords if kw in text)
                if score >= 2:
                    scored.append((score, idx))
            scored.sort(reverse=True)
            return [
                {
                    "control_id": str(self.controls_df.iloc[idx]["control_id"]).strip().upper(),
                    "title":      self.controls_df.iloc[idx]["title"],
                    "prose":      self.controls_df.iloc[idx]["prose"],
                }
                for _, idx in scored[:top_k]
            ]
