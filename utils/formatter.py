import os
import re
from dotenv import load_dotenv

load_dotenv()


# ── Utility helpers ────────────────────────────────────────────────────────────

def truncate_to_word_limit(text: str, max_words: int = 150) -> str:
    """Truncate text at the last complete sentence within max_words."""
    if not text:
        return ""
    words = text.split()
    if len(words) <= max_words:
        return text
    sentences = re.split(r"(?<=[.!?])\s+", text)
    selected, count = [], 0
    for s in sentences:
        n = len(s.split())
        if count + n <= max_words:
            selected.append(s)
            count += n
        else:
            break
    return " ".join(selected) if selected else " ".join(words[:max_words]) + "..."


def clean_nist_prose(prose: str, max_sentences: int = 3) -> str:
    """
    Strip OSCAL artefacts from NIST control prose and return a short,
    human-readable summary.

    Removes: {{ }} placeholders, markdown cross-reference links, boilerplate
    policy/audit sentences, very short fragments. Caps at 400 characters.
    """
    if not prose or not isinstance(prose, str):
        return ""

    text = re.sub(r"\{\{[^}]+\}\}", "", prose)
    text = re.sub(r"\[([A-Z]+-[\w.()\s]+)\]\(#[\w.-]+\)", r"\1", text)

    _BOILERPLATE = {
        "insert: param", "odp.", "prm_", "access control policy\n",
        "system security plan", "privacy plan", "other relevant documents",
        "organizational personnel with", "mechanisms for implementing",
        "procedures addressing", "system design documentation",
        "system configuration settings", "system audit records", "audit tracking",
        "list of active", "list of conditions", "notifications of recent",
        "access authorization records", "account management compliance",
        "system monitoring records", "is defined;", "are defined;",
        "is/are defined;", "_prm_", "_odp",
    }
    cleaned = []
    for s in re.split(r"(?<=[.!?])\s+", text):
        s = s.strip()
        if not s or len(s) < 30:
            continue
        if any(sig in s.lower() for sig in _BOILERPLATE):
            continue
        cleaned.append(s)

    result = re.sub(r"\s{2,}", " ", " ".join(cleaned[:max_sentences])).strip()
    if len(result) > 400:
        result = result[:397] + "..."
    return result or "Apply the relevant access and patch management controls per NIST SP 800-53."


# ── Business impact lookup ─────────────────────────────────────────────────────

_SERVICE_IMPACT = {
    "payment processing":      "payment disruption, PCI exposure, and client transaction failures",
    "customer login":          "credential theft, identity fraud, and unauthorized session hijacking",
    "identity verification":   "identity fraud, KYC failure, and regulatory exposure under GDPR and UAE PDPL",
    "fraud detection":         "undetected fraudulent transactions passing through the payment pipeline",
    "partner api gateway":     "SLA violations with bank and fintech partners, disrupting payment rails",
    "crm platform":            "loss of customer data access and disruption to support workflows",
    "customer support portal": "inability to manage customer escalations and support queues",
    "financial reporting":     "delayed board and regulator reporting, risking CBUAE/VARA fines",
    "compliance reporting":    "missed regulatory submission deadlines and potential regulatory penalties",
    "employee services":       "payroll processing failures and exposure of sensitive employee PII",
    "remote access":           "administrator and remote employee lockout, enabling pivot attacks",
    "software delivery":       "CI/CD compromise, unauthorized release deployment, and code repository access",
    "devops platform":         "CI/CD compromise, build toolchain poisoning, and staging environment compromise",
    "analytics platform":      "loss of business intelligence and ML model training pipeline",
    "data warehouse":          "corruption or exfiltration of historical customer and financial records",
    "backup and recovery":     "loss of disaster-recovery capability, leaving the organisation defenceless post-breach",
    "internal communications": "loss of internal coordination and potential exfiltration of executive comms",
    "corporate website":       "brand presence takedown and investor/press disruption",
    "executive operations":    "compromise of strategic files and C-suite communications",
    "testing platform":        "delayed QA cycles and risk of untested code reaching production",
}


def get_business_impact(business_service: str, is_customer_facing: bool) -> str:
    impact = _SERVICE_IMPACT.get(str(business_service).strip().lower())
    if impact:
        return impact
    if is_customer_facing:
        return "disruption to customer-facing operations and potential revenue loss"
    return "internal service disruption with potential compliance or operational consequences"


# ── Threat metadata formatter ──────────────────────────────────────────────────

def format_threat_metadata(campaign_name, confidence, exploit_status,
                            is_in_kev=False, target_region=None, ransomware=False) -> str:
    """Build a concise threat intelligence summary line."""
    parts = []
    if campaign_name and campaign_name.lower() not in ("none", "unknown", "n/a"):
        parts.append(f"**Campaign:** {campaign_name}")
    if exploit_status and exploit_status.lower() not in ("none", "n/a"):
        if is_in_kev:
            parts.append("**Status:** ✅ Confirmed in CISA KEV — active exploitation in the wild")
        else:
            parts.append(f"**Status:** {exploit_status}")
    if confidence and confidence.lower() not in ("none", "n/a"):
        parts.append(f"**Confidence:** {confidence}")
    if target_region and target_region.lower() not in ("none", "n/a"):
        parts.append(f"**Region:** {target_region}")
    if ransomware:
        parts.append("⚠️ **Ransomware association confirmed** in this campaign")
    return " · ".join(parts) if parts else "No active campaign intelligence matched."


# ── Immediate actions lookup ───────────────────────────────────────────────────

# Time-tagged action templates keyed by vulnerability-name keywords.
_ACTION_TEMPLATES = {
    "citrix": [
        "Within 24 h — Apply Citrix NetScaler CitrixBleed hotfix or patch; terminate all active sessions via CLI/GUI.",
        "Within 48 h — Rotate user credentials and API tokens that were active during the breach window; inspect NetScaler logs for token harvesting.",
        "Within 72 h — Deploy WAF rules protecting the Citrix NetScaler endpoint and perform external threat hunts for persistence indicators.",
    ],
    "teamcity": [
        "Within 24 h — Restrict access to TeamCity server ports to authorized subnets only; update JetBrains TeamCity to version 2023.11.4 or higher.",
        "Within 48 h — Inspect build agents for rogue processes or unauthorized SSH keys; rotate all secrets stored in TeamCity settings.",
        "Within 72 h — Verify EDR agent coverage on all build servers and isolate the build network from the production database network.",
    ],
    "fortinet": [
        "Within 24 h — Disable FortiOS SSL-VPN service or restrict access via firewall IP allowlists; apply FortiOS version 7.4.3 or higher.",
        "Within 48 h — Search FortiGate logs for successful admin logins from unexpected IPs or anomalous SSL-VPN connections.",
        "Within 72 h — Force MFA for all VPN profiles and rotate all local administrator and VPN user credentials.",
    ],
    "fortios": [
        "Within 24 h — Disable FortiOS SSL-VPN service or restrict access via firewall IP allowlists; apply FortiOS version 7.4.3 or higher.",
        "Within 48 h — Search FortiGate logs for successful admin logins from unexpected IPs or anomalous SSL-VPN connections.",
        "Within 72 h — Force MFA for all VPN profiles and rotate all local administrator and VPN user credentials.",
    ],
    "insecure direct object reference": [
        "Within 24 h — Deploy WAF signature or patch API endpoint to validate that authorization tokens match the requested object ID.",
        "Within 48 h — Implement automated API security testing in the pipeline to detect parameter tampering and IDOR vulnerabilities.",
        "Within 72 h — Audit application database access logs to check if other accounts were queried using tampered identifiers.",
    ],
    "rce": [
        "Within 24 h — Block inbound traffic to the vulnerable web application at the network firewall or deploy virtual patches via WAF.",
        "Within 48 h — Isolate the affected app server, run a full EDR scan, and audit web server access logs for anomalous execution threads.",
        "Within 72 h — Upgrade the web framework package to the latest secure release and review server privileges to enforce principal of least privilege.",
    ],
    "remote code execution": [
        "Within 24 h — Block inbound traffic to the vulnerable web application at the network firewall or deploy virtual patches via WAF.",
        "Within 48 h — Isolate the affected app server, run a full EDR scan, and audit web server access logs for anomalous execution threads.",
        "Within 72 h — Upgrade the web framework package to the latest secure release and review server privileges to enforce principal of least privilege.",
    ],
    "authentication bypass": [
        "Within 24 h — Rotate API secret keys and restrict unauthorized access by enforcing rate limits and token verification checks.",
        "Within 48 h — Restrict API access to trusted gateway IPs; apply security patch to resolve the authentication logic flaw.",
        "Within 72 h — Perform audit on the API access logs for anomalous volumes of unauthorized requests and rotate certificates.",
    ],
    "api authentication": [
        "Within 24 h — Rotate all API secrets and enforce OAuth scopes; revoke any tokens issued before the discovery date.",
        "Within 48 h — Apply upstream patch or WAF rule to block unauthenticated requests to the affected resource.",
        "Within 72 h — Enable detailed API access logging and alert on anomalous call volumes or error-rate spikes.",
    ],
    "tls": [
        "Within 24 h — Disable TLS 1.0/1.1 and weak cipher suites at the load balancer or web server level.",
        "Within 48 h — Deploy a valid certificate with a strong cipher suite (TLS 1.3 preferred); validate with an SSL scanner.",
        "Within 72 h — Schedule quarterly TLS configuration reviews; integrate cipher-suite checks into the CI/CD pipeline.",
    ],
    "ssh": [
        "Within 24 h — Apply the OpenSSH patch; restrict SSH access to jump-host/bastion only using firewall rules.",
        "Within 48 h — Rotate all SSH keys on the affected host; audit authorised-keys files for unauthorised entries.",
        "Within 72 h — Enable brute-force detection (fail2ban or equivalent); alert on unauthenticated SSH attempts.",
    ],
    "oauth": [
        "Within 24 h — Invalidate all existing OAuth tokens and force re-authentication for affected users.",
        "Within 48 h — Apply the vendor patch for the redirect-validation flaw; enforce strict redirect-URI whitelisting.",
        "Within 72 h — Add automated scanning of OAuth flows into the QA pipeline; conduct a brief purple-team test.",
    ],
    "http security": [
        "Within 48 h — Add Content-Security-Policy, X-Frame-Options, and HSTS headers to all customer-facing responses.",
        "Within 72 h — Automate header validation in the CI/CD pipeline (e.g., using OWASP ZAP or SecurityHeaders.com).",
        "Within 1 week — Review all API and web responses for information leakage in error bodies and server banners.",
    ],
    "redirect": [
        "Within 24 h — Implement and enforce a strict redirect whitelist; reject any redirect target not in the approved list.",
        "Within 48 h — Apply the vendor fix for the unvalidated redirect; redeploy the affected service.",
        "Within 72 h — Add automated redirect-validation tests to the regression test suite.",
    ],
    "error disclosure": [
        "Within 48 h — Configure all API error responses to return generic messages; suppress stack traces in production.",
        "Within 72 h — Centralise error logging server-side; ensure stack traces are written only to internal logs.",
        "Within 1 week — Conduct a brief security review of all public-facing API endpoints for information leakage.",
    ],
    "vpn": [
        "Within 24 h — Apply the Fortinet/VPN vendor patch; if unavailable, disable the affected feature and re-route traffic.",
        "Within 48 h — Review VPN access logs for signs of successful exploitation (unexpected sessions, new admin accounts).",
        "Within 72 h — Enforce MFA on all VPN sessions; audit remote-access permissions against the principle of least privilege.",
    ],
}

_DEFAULT_ACTIONS = [
    "Within 48 h — Apply the available vendor patch or implement a compensating control (e.g., WAF rule, network segmentation).",
    "Within 72 h — Review host and application logs for indicators of exploitation; escalate to IR team if anomalies are found.",
    "Within 1 week — Verify EDR coverage on the affected asset; conduct a follow-up vulnerability scan to confirm remediation.",
]


def get_immediate_actions(vuln_name: str, local_guidance: str) -> list:
    """
    Return exactly 3 time-tagged action items for a vulnerability.
    Matches keywords in the vulnerability name; falls back to parsing local_guidance,
    then to generic default actions.
    """
    name_lower = vuln_name.lower()
    for keyword, actions in _ACTION_TEMPLATES.items():
        if keyword in name_lower:
            return actions[:3]

    if local_guidance and local_guidance.lower() not in ("n/a", "none", ""):
        parts   = [p.strip() for p in re.split(r"[;\n]", local_guidance) if len(p.strip()) > 15]
        tagged  = []
        times   = ["Within 24 h", "Within 48 h", "Within 72 h"]
        for i, part in enumerate(parts[:3]):
            tagged.append(f"{times[i]} — {part.rstrip('.')}.")
        while len(tagged) < 3:
            tagged.append(_DEFAULT_ACTIONS[len(tagged)])
        return tagged[:3]

    return _DEFAULT_ACTIONS[:3]


# ── Groq LLM wrapper ───────────────────────────────────────────────────────────

class GroqClientWrapper:
    """
    Thin wrapper around the Groq API for executive summary, risk narrative,
    and remediation summarisation. Falls back to deterministic templates when
    no API key is configured.
    """

    def __init__(self):
        from groq import Groq
        api_key = os.getenv("GROQ_API_KEY", "")
        self.client = None
        if api_key and "your_groq_api_key" not in api_key and len(api_key.strip()) > 10:
            try:
                self.client = Groq(api_key=api_key.strip())
                print("Groq client initialized successfully.")
            except Exception as e:
                print(f"Error initializing Groq client: {e}")
        else:
            print("Groq API key not configured. Using deterministic fallback narratives.")

    def generate_executive_summary(self, top_risks_text: str) -> str:
        if not self.client:
            return (
                "RiskLens AI identified critical security exposures across TawasolPay's production "
                "infrastructure, with active threat campaigns from the Middle East region matching "
                "internet-facing payment gateways and authentication interfaces. Several vulnerabilities "
                "are confirmed in the CISA Known Exploited Vulnerabilities catalog, requiring patch "
                "deployment within 24–48 hours. Immediate priorities include isolating affected hosts, "
                "rotating credentials, and verifying EDR and WAF defences across PCI DSS and GDPR-scoped services."
            )
        try:
            resp = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior cyber security analyst writing an executive risk brief. "
                            "Write exactly 3-4 sentences. Focus on the most critical business risk, active "
                            "threat campaigns, and urgency of action. Do NOT invent any CVE IDs, scores, or "
                            "statistics. Do NOT use the phrase 'it is important'. Be direct and board-readable."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Write a concise executive cyber risk summary for TawasolPay based only on "
                            f"the following prioritised risks. Do not add new facts.\n\n{top_risks_text}"
                        ),
                    },
                ],
                max_tokens=220,
                temperature=0.25,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            print(f"Groq exec summary error: {e}")
            return (
                "Active exploitation campaigns are targeting TawasolPay's internet-facing infrastructure. "
                "Prioritise patching, credential rotation, and EDR validation across all PCI-scoped systems."
            )

    def generate_why_this_matters(self, risk: dict) -> str:
        """
        Generate a unique 2-3 sentence business-impact narrative for a risk.
        Uses 4 sentence-opening templates rotated by hash to prevent repetition.
        """
        asset_name       = risk.get("asset_name", "Unknown Asset")
        vuln_name        = risk.get("vuln_name",  "Unknown Vulnerability")
        cvss             = risk.get("cvss", 0.0)
        criticality      = risk.get("asset_criticality_raw", "medium")
        campaign_name    = risk.get("campaign_name") or "None"
        business_service = risk.get("business_service", "N/A")
        rto              = risk.get("rto", "N/A")
        compliance_scope = risk.get("compliance_scope", "N/A")
        exploit_status   = risk.get("exploit_status", "None")
        owner_team       = risk.get("owner_team", "Unassigned")
        is_kev           = "KEV" in str(exploit_status)
        ransomware       = risk.get("ransomware_association", False)
        internet_exposed = risk.get("internet_exposed", "No") == "Yes"
        is_customer_facing = str(risk.get("customer_facing", "No")).lower() == "yes"

        biz_impact = get_business_impact(business_service, is_customer_facing)

        if not self.client:
            exposure       = "an internet-facing production service" if internet_exposed else "accessible via internal lateral movement"
            kev_note       = " This CVE is confirmed in the CISA Known Exploited Vulnerabilities (KEV) catalog, indicating active exploitation in the wild." if is_kev else ""
            ransomware_note = " Ransomware operators have previously used this exploit path in financially-motivated campaigns." if ransomware else ""
            campaign_note  = f" The '{campaign_name}' campaign targets this vector." if campaign_name != "None" else ""
            rto_note       = f" With an RTO of {rto}, any outage directly threatens SLA compliance." if rto != "N/A" else ""
            compliance_note = f" A breach on this asset presents regulatory exposure under {compliance_scope}." if compliance_scope not in ("N/A", "None", "none") else ""

            # 4 templates rotated by hash to ensure variety across the Top 5
            template = hash(asset_name + vuln_name) % 4
            if template == 0:
                return (
                    f"Exploiting '{vuln_name}' on **{asset_name}** poses a direct threat to "
                    f"{business_service} operations, potentially leading to {biz_impact}. "
                    f"Owned by {owner_team}, this {criticality.lower()} asset is {exposure} (CVSS: {cvss})."
                    f"{kev_note}{campaign_note}{ransomware_note}{rto_note}{compliance_note}"
                ).strip()
            elif template == 1:
                return (
                    f"A breach of **{asset_name}** ({criticality.lower()} criticality, owned by {owner_team}) "
                    f"via '{vuln_name}' would result in {biz_impact}. "
                    f"The asset is {exposure} (CVSS: {cvss})."
                    f"{kev_note}{campaign_note}{ransomware_note}{rto_note}{compliance_note}"
                ).strip()
            elif template == 2:
                return (
                    f"Compromise of {business_service} via '{vuln_name}' on **{asset_name}** risks "
                    f"{biz_impact}. {owner_team} owns this {criticality.lower()} asset "
                    f"({exposure}, CVSS: {cvss})."
                    f"{kev_note}{campaign_note}{ransomware_note}{rto_note}{compliance_note}"
                ).strip()
            else:
                return (
                    f"With an RTO of {rto}, {business_service} has little tolerance for downtime — "
                    f"yet '{vuln_name}' on **{asset_name}** creates direct exposure to {biz_impact}. "
                    f"This {criticality.lower()} asset ({owner_team}) is {exposure} with a CVSS of {cvss}."
                    f"{kev_note}{campaign_note}{ransomware_note}{compliance_note}"
                ).strip()

        try:
            prompt = (
                f"Asset: {asset_name} | Criticality: {criticality} | Owner: {owner_team}\n"
                f"Vulnerability: {vuln_name} | CVSS: {cvss}\n"
                f"Internet Exposed: {'Yes' if internet_exposed else 'No'}\n"
                f"CISA KEV: {'Yes — active exploitation confirmed' if is_kev else 'No'}\n"
                f"Active Campaign: {campaign_name}\n"
                f"Ransomware Association: {'Yes' if ransomware else 'No'}\n"
                f"Business Service: {business_service} | RTO: {rto} | Compliance: {compliance_scope}\n"
                f"Business Impact if Exploited: {biz_impact}\n\n"
                f"Write a 2-3 sentence 'Why This Matters' paragraph. "
                f"Lead with the specific business consequence. "
                f"Mention KEV status and campaign if present. "
                f"Do NOT use: 'critical because host is internet exposed', 'it is important', "
                f"'directly reachable from the internet', 'active ransomware capability linked to'. "
                f"Do NOT invent statistics. Be concise and board-readable."
            )
            resp = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cyber security advisor writing risk narratives for a fintech board. "
                            "Each narrative must be unique and lead with the business consequence, not the "
                            "technical detail. Vary sentence openings across risks. Do not invent facts. "
                            "2-3 sentences maximum."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=180,
                temperature=0.35,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            print(f"Groq why_this_matters error: {e}")
            return f"Exploitation of '{vuln_name}' on {asset_name} would result in {biz_impact}."

    def generate_remediation_summary(self, control_id: str, control_title: str,
                                     control_prose: str, local_guidance: str) -> str:
        """
        Combine cleaned NIST prose with local remediation guidance into a short paragraph.
        Never exposes raw OSCAL text.
        """
        cleaned = clean_nist_prose(control_prose, max_sentences=2)

        if not self.client:
            if cleaned and local_guidance and local_guidance.lower() not in ("n/a", "none"):
                return (
                    f"Per NIST SP 800-53 **{control_id} ({control_title})**: {cleaned} "
                    f"Locally, the recommended action is: {local_guidance.rstrip('.')}."
                )
            if cleaned:
                return f"Per NIST SP 800-53 **{control_id} ({control_title})**: {cleaned}"
            if local_guidance and local_guidance.lower() not in ("n/a", "none"):
                return f"*(Non-authoritative)* {local_guidance.rstrip('.')}."
            return f"Apply NIST SP 800-53 {control_id} ({control_title}) controls and follow vendor remediation guidance."

        try:
            prompt = (
                f"NIST Control: {control_id} — {control_title}\n"
                f"Summary of Control: {cleaned}\n"
                f"Local Remediation Action: {local_guidance}\n\n"
                f"Write a single concise paragraph (2-3 sentences, max 80 words) that integrates the "
                f"NIST control with the local action. Do not copy raw NIST text verbatim. Write in plain "
                f"English. Do not invent controls, CVEs, or procedures not mentioned above."
            )
            resp = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cyber compliance expert. Produce a short, human-readable remediation "
                            "paragraph. Avoid bureaucratic NIST boilerplate. Do not exceed 80 words."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=130,
                temperature=0.25,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            print(f"Groq remediation error: {e}")
            return f"Per NIST SP 800-53 {control_id} ({control_title}): {cleaned}"


# ── Score label ────────────────────────────────────────────────────────────────

def _score_label(score: float) -> str:
    if score >= 0.80:
        return "🔴 CRITICAL"
    if score >= 0.65:
        return "🟠 HIGH"
    if score >= 0.45:
        return "🟡 MEDIUM"
    return "🟢 LOW"


# ── Main report formatter ──────────────────────────────────────────────────────

def format_markdown_report(top_risks: list, llm_wrapper: GroqClientWrapper) -> str:
    """
    Generate a board-readable Markdown risk brief from the top-ranked risks.

    Structure per risk: metadata table · threat intelligence · Why This Matters
                        · Remediation Guidance · Immediate Actions
    """
    risks_text = "\n".join(
        f"{i+1}. {r['asset_name']} — {r['vuln_name']} (CVE: {r['cve']}, CVSS: {r['cvss']}, Score: {r['score']:.2f})"
        for i, r in enumerate(top_risks)
    )
    exec_summary = llm_wrapper.generate_executive_summary(risks_text)

    lines = [
        "# 🛡️ Cyber Risk Brief — TawasolPay",
        "",
        f"> **Generated by RiskLens AI** · {len(top_risks)} risks analysed · Scoring: deterministic 6-factor model",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        exec_summary,
        "",
        "---",
        "",
        "## Top Prioritised Risks",
        "",
    ]

    for idx, risk in enumerate(top_risks):
        rank             = idx + 1
        asset_name       = risk.get("asset_name", "Unknown")
        vuln_name        = risk.get("vuln_name",  "Unknown")
        cve              = risk.get("cve") or "N/A"
        score            = risk.get("score", 0.0)
        cvss             = risk.get("cvss", 0.0)
        days_open        = int(risk.get("days_open", 0))
        owner_team       = risk.get("owner_team", "Unassigned")
        exploit_status   = risk.get("exploit_status", "None")
        is_in_kev        = "KEV" in str(exploit_status)
        campaign_name    = risk.get("campaign_name") or None
        confidence       = risk.get("threat_confidence", "None")
        business_service = risk.get("business_service", "N/A")
        rto              = risk.get("rto", "N/A")
        compliance_scope = risk.get("compliance_scope", "N/A")
        revenue_impact   = risk.get("revenue_impact", "N/A")
        internet_exposed = risk.get("internet_exposed", "No")
        ransomware       = risk.get("ransomware_association", False)
        target_region    = risk.get("target_region", None)

        risk["ransomware_association"] = ransomware
        risk["customer_facing"]        = risk.get("customer_facing", "No")

        # Orphan / stale asset warnings
        warnings = []
        if risk.get("is_orphaned"):
            warnings.append("⚠️ Unassigned Owner")
        if risk.get("is_stale"):
            warnings.append(f"⚠️ Stale Asset (last seen {int(risk.get('days_since_seen', 0))} days ago)")

        threat_line = format_threat_metadata(
            campaign_name, confidence, exploit_status,
            is_in_kev=is_in_kev, target_region=target_region, ransomware=ransomware,
        )

        lines += [f"### Risk #{rank} — {asset_name}", ""]
        if warnings:
            lines += ["  \n".join(f"> {w}" for w in warnings), ""]

        lines += [
            "| Field | Detail |",
            "|---|---|",
            f"| **Vulnerability** | {vuln_name} |",
            f"| **CVE** | `{cve}` |",
            f"| **CVSS** | {cvss} |",
            f"| **Risk Score** | **{score:.2f} / 1.00** — {_score_label(score)} |",
            f"| **Days Open** | {days_open} days |",
            f"| **Internet Exposed** | {internet_exposed} |",
            f"| **Owner Team** | {owner_team} |",
            f"| **Business Service** | {business_service} |",
            f"| **Customer-Facing** | {risk.get('customer_facing', 'N/A')} |",
            f"| **Compliance Scope** | {compliance_scope} |",
            f"| **RTO** | {rto} |",
            f"| **Revenue Impact** | {revenue_impact} |",
            "",
        ]

        lines += ["**🔍 Threat Intelligence**", "", threat_line, ""]

        why = llm_wrapper.generate_why_this_matters(risk)
        lines += ["**💼 Why This Matters**", "", why, ""]

        nist_control  = risk.get("nist_control")
        local_guidance = risk.get("local_remediation_guidance", "")

        if nist_control:
            remediation = llm_wrapper.generate_remediation_summary(
                nist_control.get("control_id", "N/A"),
                nist_control.get("title", ""),
                nist_control.get("prose", ""),
                local_guidance,
            )
        elif local_guidance and local_guidance.lower() not in ("n/a", "none", ""):
            remediation = f"*(Non-authoritative)* {local_guidance.rstrip('.')}."
        else:
            remediation = "*(Non-authoritative)* Apply vendor patches promptly; review access controls and monitor host logs."

        remediation = truncate_to_word_limit(remediation, 150)
        lines += ["**🔧 Remediation Guidance**", "", remediation, ""]

        actions = get_immediate_actions(vuln_name, local_guidance)
        lines += ["**⚡ Immediate Actions**", ""]
        lines.extend(f"- {a}" for a in actions)
        lines.append("")

        if rank < len(top_risks):
            lines += ["---", ""]

    lines += [
        "---",
        "",
        "> *Report generated by **RiskLens AI**. "
        "Scoring is 100% deterministic — no LLM hallucination in risk prioritisation. "
        "NIST controls retrieved via semantic search (NIST SP 800-53 Rev 5). "
        "Non-authoritative guidance is clearly labelled.*",
        "",
    ]

    return "\n".join(lines)
