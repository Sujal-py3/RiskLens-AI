import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

class GroqClientWrapper:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        self.client = None
        # Handle cases where API key is placeholder or empty
        if self.api_key and "your_groq_api_key" not in self.api_key and len(self.api_key.strip()) > 10:
            try:
                self.client = Groq(api_key=self.api_key.strip())
                print("Groq client initialized successfully.")
            except Exception as e:
                print(f"Error initializing Groq client: {e}")
        else:
            print("Groq API key not configured or is a placeholder. Using mock narratives fallback.")

    def generate_executive_summary(self, top_risks_text):
        if not self.client:
            return (
                "RiskLens AI has completed a comprehensive cyber risk analysis for TawasolPay. "
                "The assessment identified critical security exposures, primarily concentrated on "
                "production payment gateways, authentication interfaces, and API services. Active threat "
                "campaigns in the Middle East region targeting these specific vulnerabilities underscore the "
                "need for immediate patch applications and verification of EDR and WAF defenses."
            )
        try:
            prompt = (
                f"Based on the following top cyber risks, write a concise 3-4 sentence executive cyber risk brief summary for TawasolPay. "
                f"Focus on the most critical exposures and overall urgency. Do not invent any numbers, scores, or CVEs.\n\n"
                f"Risks Summary:\n{top_risks_text}"
            )
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cyber security analyst. Write a concise executive summary for a risk report based only on the provided facts. Do not invent details. Keep it to 3-4 sentences maximum."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.3
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Groq API error in executive summary: {e}")
            return "Critical threat campaigns matching payment gateways and internet-facing systems require immediate intervention. Enforce EDR and WAF policies."

    def generate_why_this_matters(self, asset_name, vuln_name, cvss, ie, criticality, campaign_name, owner):
        if not self.client:
            exposure_text = "actively exposed to the internet" if ie else "internal, but reachable via lateral movement"
            threat_text = f" and matches the active campaign '{campaign_name}' targeting our sector" if campaign_name else ""
            return (
                f"Vulnerability '{vuln_name}' on asset '{asset_name}' ({owner}) is critical because the host is {exposure_text}{threat_text}. "
                f"Given the system's business criticality ({criticality}) and severity score ({cvss}), "
                f"exploitation would lead to immediate compromise of critical customer transaction and payment pathways."
            )
        try:
            prompt = (
                f"Write a concise 2-3 sentence explanation ('Why This Matters') for the following vulnerability:\n"
                f"Asset: {asset_name}\n"
                f"Vulnerability: {vuln_name}\n"
                f"CVSS Score: {cvss}\n"
                f"Internet Exposed: {'Yes' if ie else 'No'}\n"
                f"Business Criticality: {criticality}\n"
                f"Active Threat Campaign: {campaign_name if campaign_name else 'None'}\n"
                f"Asset Owner: {owner}\n"
                f"Explain the technical impact and business consequence of this risk. Do not invent any new statistics or scores. Keep it to 2-3 sentences."
            )
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cyber security advisor. Explain why a specific vulnerability matters based on the provided parameters in 2-3 sentences. Do not invent any new facts or numbers."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=150,
                temperature=0.3
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Groq API error in why_this_matters: {e}")
            return f"Vulnerability '{vuln_name}' on '{asset_name}' is highly critical due to its severity ({cvss}) and target profile. Active scanning or campaigns make exploitation highly likely if unremediated."

    def generate_remediation_wording(self, control_id, control_title, control_prose, recommended_actions):
        if not self.client:
            return f"[{control_id}] {control_title} — {control_prose} (Actions: {recommended_actions})"
        try:
            prompt = (
                f"NIST Control: [{control_id}] {control_title}\n"
                f"NIST Prose: {control_prose}\n"
                f"Local Guidance: {recommended_actions}\n"
                f"Summarize this NIST control and the recommended actions into a single, concise remediation guidance paragraph (2-3 sentences). "
                f"Integrate both local action steps and the NIST framework wording. Do not invent any new controls or guidelines."
            )
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cyber compliance expert. Combine and summarize the NIST control prose and local remediation actions into a clean, single paragraph. Do not invent or add unmentioned details. Limit to 2-3 sentences."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=150,
                temperature=0.3
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Groq API error in remediation: {e}")
            return f"[{control_id}] {control_title}: {control_prose} (Local Action: {recommended_actions})"

    def generate_immediate_actions(self, vuln_name, recommended_actions):
        if not self.client:
            actions = [a.strip() for a in recommended_actions.split(";") if a.strip()]
            if len(actions) < 3:
                actions.extend(["Deploy/verify EDR and security logging on the host.", "Audit access logs for indicators of compromise."])
            return actions[:3]
        try:
            prompt = (
                f"Vulnerability: {vuln_name}\n"
                f"Local Recommended Action List: {recommended_actions}\n"
                f"Generate exactly 3 concise, numbered action items for a security team to execute immediately to contain or fix this issue. "
                f"Each action item should be a short one-liner sentence. Do not add intro or outro text."
            )
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a security operations lead. Output exactly 3 numbered action items, one per line. Do not write any conversational text before or after the items."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=100,
                temperature=0.3
            )
            lines = response.choices[0].message.content.strip().split("\n")
            actions = []
            for line in lines:
                cleaned = line.strip()
                if cleaned:
                    # Remove list numbers like "1. " if they exist
                    if cleaned[0].isdigit() and cleaned[1:3] in [". ", ") "]:
                        cleaned = cleaned[2:].strip()
                    elif cleaned[0].isdigit() and cleaned[1] in [".", ")"]:
                        cleaned = cleaned[1:].strip()
                    actions.append(cleaned)
            while len(actions) < 3:
                actions.append("Verify and monitor host event logs for anomalous activity.")
            return actions[:3]
        except Exception as e:
            print(f"Groq API error in immediate_actions: {e}")
            actions = [a.strip() for a in recommended_actions.split(";") if a.strip()]
            while len(actions) < 3:
                actions.append("Audit and lock down network access to the affected system.")
            return actions[:3]


def format_markdown_report(top_risks, llm_wrapper):
    """
    Formats the list of top 5 risks into the required Markdown structure, 
    enriching the details with narrative summaries from Groq/mock LLM.
    """
    # Create simple summary string of risks for the executive brief
    risks_summary_lines = []
    for idx, r in enumerate(top_risks):
        risks_summary_lines.append(f"{idx+1}. Asset: {r['asset_name']}, Vuln: {r['vuln_name']} (CVE: {r['cve']}), Risk Score: {r['score']:.4f}")
    top_risks_text = "\n".join(risks_summary_lines)
    
    exec_summary = llm_wrapper.generate_executive_summary(top_risks_text)
    
    markdown_content = []
    markdown_content.append("CYBER RISK BRIEF — TAWASOLPAY\n")
    markdown_content.append(f"{exec_summary}\n")
    
    for idx, risk in enumerate(top_risks):
        rank = idx + 1
        asset_name = risk["asset_name"]
        vuln_name = risk["vuln_name"]
        cve = risk["cve"] if risk["cve"] else "N/A"
        
        # Threat Match field
        campaign = risk["campaign_name"]
        confidence = risk["threat_confidence"]
        if campaign:
            threat_match_str = f"{campaign} ({confidence} Confidence)"
        else:
            threat_match_str = "None"
            
        business_service = risk["business_service"] if risk["business_service"] else "N/A"
        score = f"{risk['score']:.4f}"
        
        # Stale asset or missing owner warning annotations
        warnings = []
        if risk["is_orphaned"]:
            warnings.append("Orphaned Asset (Unassigned Owner)")
        if risk["is_stale"]:
            warnings.append(f"Stale Asset (Last seen {int(risk['days_since_seen'])} days ago)")
            
        warning_str = f" [WARNING: {', '.join(warnings)}]" if warnings else ""
        
        markdown_content.append(f"RISK #{rank} — {asset_name}{warning_str}\n")
        markdown_content.append(f"Asset: {asset_name}")
        markdown_content.append(f"Vulnerability: {vuln_name} ({cve})")
        markdown_content.append(f"Threat Match: {threat_match_str}")
        markdown_content.append(f"Business Service: {business_service}")
        markdown_content.append(f"Risk Score: {score}\n")
        
        # Generate Narrative Narratives via LLM Wrapper
        why_matters = llm_wrapper.generate_why_this_matters(
            asset_name=asset_name,
            vuln_name=vuln_name,
            cvss=risk["cvss"],
            ie=(risk["internet_exposed"] == "Yes"),
            criticality=risk["asset_criticality_raw"],
            campaign_name=campaign,
            owner=risk["owner_team"]
        )
        markdown_content.append("Why This Matters:")
        markdown_content.append(f"{why_matters}\n")
        
        # NIST Control Retrieval Remediation Guidance
        nist_control = risk["nist_control"]
        local_guidance = risk["local_remediation_guidance"]
        
        if nist_control:
            cid = nist_control["control_id"]
            title = nist_control["title"]
            prose = nist_control["prose"]
            remediation_guidance = llm_wrapper.generate_remediation_wording(cid, title, prose, local_guidance)
        else:
            remediation_guidance = local_guidance
            
        markdown_content.append("Remediation Guidance:")
        markdown_content.append(f"{remediation_guidance}\n")
        
        # 3 Immediate Actions
        actions = llm_wrapper.generate_immediate_actions(vuln_name, local_guidance)
        markdown_content.append("Immediate Actions:")
        for action_idx, action in enumerate(actions):
            markdown_content.append(f"{action_idx+1}. {action}")
        markdown_content.append("") # Newline separator between risks
        
    return "\n".join(markdown_content)
