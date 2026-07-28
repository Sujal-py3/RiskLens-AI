import os
import json
import requests
import pandas as pd
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

CISA_KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = os.path.join("cache", "kev.json")

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
    os.makedirs("cache", exist_ok=True)
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


# ── RAG: Precomputed Embeddings + Sklearn Cosine Similarity ──────────────────

class NistRAG:
    """
    Retrieves NIST SP 800-53 controls matching vulnerability queries.
    Uses precomputed embeddings loaded from data/precomputed_embeddings.npz and
    sklearn cosine similarity for low-memory, high-speed execution.
    """

    def __init__(self):
        npz_path = os.path.join("data", "precomputed_embeddings.npz")
        if not os.path.exists(npz_path):
            error_msg = (
                f"CRITICAL ERROR: Precomputed embeddings cache file '{npz_path}' is missing! "
                "Please run 'python scratch/precompute_embeddings.py' locally to generate it."
            )
            print(error_msg)
            raise FileNotFoundError(error_msg)

        print(f"Loading precomputed embeddings from {npz_path}...")
        try:
            data = np.load(npz_path, allow_pickle=True)
            self.nist_embeddings = data["nist_embeddings"]
            self.nist_ids        = [str(x).strip().upper() for x in data["nist_ids"]]
            self.nist_titles     = [str(x).strip() for x in data["nist_titles"]]
            self.nist_proses     = [str(x).strip() for x in data["nist_proses"]]
            
            # Map query text to its precomputed embedding
            self.query_texts       = [str(x).strip() for x in data["query_texts"]]
            self.query_embeddings = data["query_embeddings"]
            
            self.query_to_emb = {
                q: self.query_embeddings[idx]
                for idx, q in enumerate(self.query_texts)
            }
            
            print(f"Successfully loaded {len(self.nist_ids)} controls and {len(self.query_texts)} precomputed queries.")
        except Exception as e:
            error_msg = f"CRITICAL ERROR: Failed to load precomputed embeddings: {e}"
            print(error_msg)
            raise RuntimeError(error_msg)

    def retrieve_controls(self, query: str, top_k: int = 2) -> list:
        """
        Retrieve the top_k NIST controls for a query.
        Uses sklearn cosine similarity between precomputed control and query embeddings.
        """
        query = query.strip()
        if not query:
            return []

        # Check if the query exists in the precomputed embeddings cache
        if query not in self.query_to_emb:
            print(f"WARNING: Query not found in precomputed embeddings cache: '{query}'")
            # Fallback keyword match if embedding is missing
            keywords = query.lower().split()
            scored = []
            for idx in range(len(self.nist_ids)):
                text = f"{self.nist_ids[idx]} {self.nist_titles[idx]} {self.nist_proses[idx]}".lower()
                score = sum(1 for kw in keywords if kw in text)
                if score >= 2:
                    scored.append((score, idx))
            scored.sort(reverse=True)
            return [
                {
                    "control_id": self.nist_ids[idx],
                    "title":      self.nist_titles[idx],
                    "prose":      self.nist_proses[idx]
                }
                for _, idx in scored[:top_k]
            ]

        try:
            query_emb = self.query_to_emb[query].reshape(1, -1)
            # Compute cosine similarities using sklearn
            sims = cosine_similarity(self.nist_embeddings, query_emb).flatten()
            
            # Get sorted indices in descending order
            top_idx = np.argsort(sims)[::-1][:top_k]
            results = []
            for idx in top_idx:
                if sims[idx] < 0.35:  # Cosine similarity threshold
                    continue
                results.append({
                    "control_id": self.nist_ids[idx],
                    "title":      self.nist_titles[idx],
                    "prose":      self.nist_proses[idx]
                })
            return results
        except Exception as e:
            print(f"Error during cosine similarity retrieval: {e}")
            return []


# ── Vendor RAG: FAISS + SentenceTransformers ──────────────────────────────

class VendorRAG:
    """
    Retrieves vendor compliance documents using FAISS and SentenceTransformers.
    """
    def __init__(self):
        try:
            from sentence_transformers import SentenceTransformer
            import faiss
            self.model = SentenceTransformer('all-MiniLM-L6-v2')
            self.index = None
            self.chunks = []
            self._build_index()
        except Exception as e:
            print(f"Error initializing VendorRAG: {e}")
            self.model = None

    def _build_index(self):
        vendor_docs_dir = os.path.join("data", "vendor_docs")
        if not os.path.exists(vendor_docs_dir):
            return
            
        for filename in os.listdir(vendor_docs_dir):
            if filename.endswith(".txt"):
                vendor_id = filename.split(".")[0]
                filepath = os.path.join(vendor_docs_dir, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    
                paragraphs = [p.strip() for p in content.split("\n\n") if len(p.strip()) > 20]
                for p in paragraphs:
                    self.chunks.append({
                        "vendor_id": vendor_id,
                        "text": p
                    })
                    
        if not self.chunks:
            return
            
        import faiss
        import numpy as np
        
        texts = [c["text"] for c in self.chunks]
        embeddings = self.model.encode(texts)
        
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatL2(dimension)
        self.index.add(np.array(embeddings).astype('float32'))

    def retrieve(self, vendor_id: str, query: str, top_k: int = 3) -> list:
        if not self.model or not self.index:
            return []
            
        import numpy as np
        query_emb = self.model.encode([query])
        
        distances, indices = self.index.search(np.array(query_emb).astype('float32'), top_k * 3)
        
        results = []
        for idx in indices[0]:
            if idx == -1:
                continue
            chunk = self.chunks[idx]
            if chunk["vendor_id"] == vendor_id or vendor_id == "any":
                results.append(chunk)
                if len(results) >= top_k:
                    break
                    
        return results
