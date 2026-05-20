import pandas as pd


def calculate_business_criticality(asset_row, business_services_df) -> float:
    """
    Score business criticality [0, 1] from asset criticality and service attributes
    (customer-facing status, compliance scope, revenue impact, RTO).
    """
    crit_map = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
    asset_crit = str(asset_row.get("criticality", "medium")).strip().lower()
    asset_val  = crit_map.get(asset_crit, 0.4)

    service_name = asset_row.get("business_service")
    if pd.isna(service_name) or not isinstance(service_name, str) or not service_name.strip():
        return 0.5 * asset_val + 0.5 * 0.3  # no service data — use default service score

    service_rows = business_services_df[
        business_services_df["business_service"].str.strip().str.lower() == service_name.strip().lower()
    ]
    if service_rows.empty:
        return 0.5 * asset_val + 0.5 * 0.3

    svc = service_rows.iloc[0]

    customer_facing_val = 1.0 if str(svc.get("customer_facing", "No")).strip().lower() == "yes" else 0.0

    comp_scope = str(svc.get("compliance_scope", "None")).strip().lower()
    compliance_val = 1.0 if (comp_scope != "none" and any(
        d in comp_scope for d in ["gdpr", "pci", "pdpl", "soc", "ifrs"]
    )) else 0.0

    rev = str(svc.get("revenue_impact", "low")).strip().lower()
    revenue_val = crit_map.get(rev, 0.1)

    # RTO: tighter recovery window → higher criticality
    rto_val = 0.4
    try:
        rto_hours = float(svc.get("rto_hours", 24))
        if rto_hours <= 4:
            rto_val = 1.0
        elif rto_hours <= 12:
            rto_val = 0.7
        elif rto_hours <= 24:
            rto_val = 0.4
        else:
            rto_val = 0.1
    except (ValueError, TypeError):
        pass

    service_val = (
        0.2 * customer_facing_val +
        0.3 * compliance_val +
        0.3 * revenue_val +
        0.2 * rto_val
    )
    return 0.5 * asset_val + 0.5 * service_val


def evaluate_threat_match(cve, asset_location, threat_intel_df):
    """
    Match a CVE against the threat intelligence feed with regional weighting.

    Returns (score, campaign_name, confidence, ransomware, target_region):
      - CVE match + region match  → 1.0
      - CVE match, different region → 0.5
      - No CVE match → 0.0 with None campaign
    """
    if pd.isna(cve) or not cve:
        return 0.0, None, "None", False, "Global"

    cve      = str(cve).strip().upper()
    asset_loc = str(asset_location).strip().lower()

    cve_col = "matched_cve" if "matched_cve" in threat_intel_df.columns else "matched_cve_or_control"
    matches = threat_intel_df[threat_intel_df[cve_col].str.strip().str.upper() == cve]

    if matches.empty:
        return 0.0, None, "None", False, "Global"

    uae_regions    = {"middle east", "gulf", "uae", "global"}
    india_regions  = {"global", "india", "asia"}
    fintech_sectors = {"fintech", "financial", "technology", "all", "retail", "saas", "enterprise", "network", "linux", "web"}

    best_score    = 0.5
    best_campaign = None

    for _, campaign in matches.iterrows():
        sector = str(campaign.get("target_sector", "All")).strip().lower()
        if not any(k in sector for k in fintech_sectors):
            continue

        region = str(campaign.get("target_region", "Global")).strip().lower()
        if asset_loc == "uae":
            region_match = any(r in region for r in uae_regions)
        elif asset_loc == "india":
            region_match = any(r in region for r in india_regions)
        else:
            region_match = "global" in region or asset_loc in region

        if region_match:
            best_score    = 1.0
            best_campaign = campaign
            break
        else:
            best_campaign = campaign  # CVE match without region — keep as fallback

    if best_campaign is None:
        return 0.0, None, "None", False, "Global"

    return (
        best_score,
        str(best_campaign.get("campaign_name", "Unknown")),
        str(best_campaign.get("confidence",    "Medium")).strip(),
        str(best_campaign.get("ransomware_association", "No")).strip().lower() in ("yes", "true", "1"),
        str(best_campaign.get("target_region", "Global")).strip(),
    )


def calculate_risk_score(vuln_row, asset_row, business_services_df, threat_intel_df, kev_cves) -> dict:
    """
    Deterministic 6-factor risk score, normalised to [0, 1].

    Weights:
      CVSS (0.15) · Exploit (0.15) · Threat campaign (0.25) · Internet exposure (0.10)
      Business criticality (0.30) · Days open (0.05) − Security controls (0.10)
    """
    # 1. CVSS
    cvss      = float(vuln_row.get("cvss", 0.0))
    cvss_norm = cvss / 10.0

    # 2. Exploit / KEV
    cve        = vuln_row.get("cve")
    is_in_kev  = bool(cve and str(cve).strip().upper() in kev_cves)
    exploit_ok = str(vuln_row.get("exploit_available", "No")).strip().lower() == "yes"
    exploit_val = 1.0 if (is_in_kev or exploit_ok) else 0.0

    # 3. Threat campaign
    threat_score, campaign_name, confidence, ransomware, target_region = evaluate_threat_match(
        cve, asset_row.get("location", "UAE"), threat_intel_df
    )

    # 4. Internet exposure
    internet_val = 1.0 if str(asset_row.get("internet_exposed", "No")).strip().lower() == "yes" else 0.0

    # 5. Business criticality
    biz_crit = calculate_business_criticality(asset_row, business_services_df)

    # 6. Days open
    days_open     = float(vuln_row.get("days_open", 0))
    days_open_val = min(days_open, 365.0) / 365.0

    # Compensating controls reduce the score (EDR 0.5, WAF 0.3, patch available 0.2)
    controls = (
        (0.5 if str(asset_row.get("edr_installed", "No")).strip().lower() == "yes" else 0.0) +
        (0.3 if str(asset_row.get("has_waf",       "No")).strip().lower() == "yes" else 0.0) +
        (0.2 if str(vuln_row.get("patch_available", "No")).strip().lower() == "yes" else 0.0)
    )

    raw = (
        0.15 * cvss_norm    +
        0.15 * exploit_val  +
        0.25 * threat_score +
        0.10 * internet_val +
        0.30 * biz_crit     +
        0.05 * days_open_val -
        0.10 * controls
    )

    # Normalise: min possible = -0.10 (full controls, no positives); max = 1.0
    score = max(0.0, min(1.0, (raw + 0.10) / 1.10))

    owner_team  = asset_row.get("owner_team")
    is_orphaned = pd.isna(owner_team) or str(owner_team).strip() == ""
    is_stale    = float(asset_row.get("last_seen_days", 0)) > 30.0

    if is_in_kev:
        exploit_status = "Active (KEV)"
    elif exploit_ok:
        exploit_status = "Exploit Available"
    else:
        exploit_status = "None"

    return {
        "score":                score,
        "cvss":                 cvss,
        "days_open":            days_open,
        "exploit_status":       exploit_status,
        "is_in_kev":            is_in_kev,
        "campaign_name":        campaign_name,
        "threat_confidence":    confidence,
        "ransomware_association": ransomware,
        "target_region":        target_region,
        "is_orphaned":          is_orphaned,
        "is_stale":             is_stale,
        "owner_team":           "Unassigned" if is_orphaned else str(owner_team).strip(),
    }
