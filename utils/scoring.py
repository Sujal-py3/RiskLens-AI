import pandas as pd
import numpy as np

def calculate_business_criticality(asset_row, business_services_df):
    """
    Calculates business criticality based on asset criticality and business service attributes:
    customer-facing, PCI/GDPR scope, RTO, and revenue impact.
    """
    # 1. Asset Criticality Mapping
    crit_map = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
    asset_crit = str(asset_row.get("criticality", "medium")).strip().lower()
    asset_criticality_val = crit_map.get(asset_crit, 0.4)
    
    # 2. Service context lookup
    service_name = asset_row.get("business_service")
    if pd.isna(service_name) or not isinstance(service_name, str) or str(service_name).strip() == "":
        # No service mapped, fallback to a default business service context value (0.3)
        service_criticality = 0.3
    else:
        service_name = service_name.strip()
        # Find matching service in df
        service_rows = business_services_df[business_services_df["business_service"].str.strip().str.lower() == service_name.lower()]
        if service_rows.empty:
            service_criticality = 0.3
        else:
            service_row = service_rows.iloc[0]
            
            # customer_facing
            cf = str(service_row.get("customer_facing", "No")).strip().lower()
            customer_facing_val = 1.0 if cf == "yes" else 0.0
            
            # compliance_scope (e.g. GDPR, PCI DSS, UAE PDPL, SOC 2)
            comp_scope = str(service_row.get("compliance_scope", "None")).strip().lower()
            in_scope = any(domain in comp_scope for domain in ["gdpr", "pci", "pdpl", "soc", "ifrs"])
            compliance_val = 1.0 if (comp_scope != "none" and in_scope) else 0.0
            
            # revenue_impact
            rev = str(service_row.get("revenue_impact", "low")).strip().lower()
            revenue_val = crit_map.get(rev, 0.1)
            
            # rto_hours
            rto_val = 0.4  # default if missing or invalid
            try:
                rto_hours = float(service_row.get("rto_hours", 24))
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
                
            service_criticality = (
                0.2 * customer_facing_val +
                0.3 * compliance_val +
                0.3 * revenue_val +
                0.2 * rto_val
            )
            
    # Combine asset criticality and service context (50/50 average)
    business_criticality = 0.5 * asset_criticality_val + 0.5 * service_criticality
    return business_criticality


def evaluate_threat_match(cve, asset_location, threat_intel_df):
    """
    Evaluates threat campaign matching using regional filters:
    - CVE match + Region match = strongest signal (1.0)
    - CVE match but different target region = moderate signal (0.5)
    - No CVE match = (0.0)
    
    Filters out noise from unrelated sectors.
    """
    if pd.isna(cve) or not cve:
        return 0.0, None, "None"
        
    # Standardize inputs
    cve = str(cve).strip().upper()
    asset_loc = str(asset_location).strip().lower()
    
    # Filter threat intelligence to match CVE
    matching_campaigns = threat_intel_df[threat_intel_df["matched_cve"].str.strip().str.upper() == cve]
    
    if matching_campaigns.empty:
        return 0.0, None, "None"
        
    # We have CVE match! Now check region match
    # Regions that are considered a match for UAE and India assets
    uae_matching_regions = ["middle east", "gulf", "uae", "global"]
    india_matching_regions = ["global", "india", "asia"]
    
    best_match_score = 0.5
    best_campaign = None
    max_confidence = "Low"
    
    for _, campaign in matching_campaigns.iterrows():
        # Sector filtering: filter out campaigns targeting unrelated sectors (e.g. Healthcare)
        # TawasolPay is in Fintech / Financial Services / Technology
        target_sector = str(campaign.get("target_sector", "All")).strip().lower()
        unrelated_sectors = ["healthcare", "government", "education", "energy"]
        # If the campaign is specific to healthcare or government and doesn't target Fintech or All Sectors, filter it
        is_fintech_relevant = any(keyword in target_sector for keyword in ["fintech", "financial", "technology", "all", "retail", "saas", "enterprise", "network", "linux", "web"])
        if not is_fintech_relevant:
            continue
            
        region = str(campaign.get("target_region", "Global")).strip().lower()
        
        region_matched = False
        if asset_loc == "uae":
            region_matched = any(r in region for r in uae_matching_regions)
        elif asset_loc == "india":
            region_matched = any(r in region for r in india_matching_regions)
        else:
            region_matched = ("global" in region or asset_loc in region)
            
        if region_matched:
            best_match_score = 1.0
            best_campaign = campaign
            break
        else:
            best_campaign = campaign  # Keep the CVE-matching campaign as fallback
            
    if best_campaign is not None:
        confidence = str(best_campaign.get("confidence", "Medium")).strip()
        campaign_name = str(best_campaign.get("campaign_name", "Unknown"))
        return best_match_score, campaign_name, confidence
        
    return 0.0, None, "None"


def calculate_risk_score(vuln_row, asset_row, business_services_df, threat_intel_df, kev_cves):
    """
    Calculates the deterministic risk score for a single vulnerability on an asset.
    """
    # 1. CVSS Normalization (0-10 to 0-1)
    cvss = float(vuln_row.get("cvss", 0.0))
    cvss_norm = cvss / 10.0
    
    # 2. Active Exploit Status (CISA KEV check + vulnerability exploit availability)
    cve = vuln_row.get("cve")
    is_in_kev = False
    if cve and isinstance(cve, str):
        is_in_kev = str(cve).strip().upper() in kev_cves
        
    exploit_available = str(vuln_row.get("exploit_available", "No")).strip().lower() == "yes"
    
    # KEV validation: CVE must exist in KEV before boosting score for active exploit via KEV
    # Active exploit is 1.0 if in KEV or exploit is available, else 0.0
    exploit_val = 1.0 if (is_in_kev or exploit_available) else 0.0
    
    # 3. Threat Campaign Match (CVE + Region Match)
    asset_location = asset_row.get("location", "UAE")
    threat_match_val, campaign_name, threat_confidence = evaluate_threat_match(cve, asset_location, threat_intel_df)
    
    # 4. Internet Exposure
    ie = str(asset_row.get("internet_exposed", "No")).strip().lower()
    internet_exposed_val = 1.0 if ie == "yes" else 0.0
    
    # 5. Business Criticality
    business_criticality = calculate_business_criticality(asset_row, business_services_df)
    
    # 6. Days Open
    days_open = float(vuln_row.get("days_open", 0))
    days_open_val = min(days_open, 365.0) / 365.0
    
    # 7. Compensating Controls (EDR + WAF + Patch)
    edr_factor = 0.5 if str(asset_row.get("edr_installed", "No")).strip().lower() == "yes" else 0.0
    # WAF: check has_waf == "Yes" explicitly in asset row (do not infer from server type)
    waf_factor = 0.3 if str(asset_row.get("has_waf", "No")).strip().lower() == "yes" else 0.0
    patch_factor = 0.2 if str(vuln_row.get("patch_available", "No")).strip().lower() == "yes" else 0.0
    security_controls = edr_factor + waf_factor + patch_factor
    
    # Raw Score calculation
    raw_score = (
        0.25 * cvss_norm +
        0.20 * exploit_val +
        0.20 * threat_match_val +
        0.15 * internet_exposed_val +
        0.15 * business_criticality +
        0.05 * days_open_val -
        0.05 * security_controls
    )
    
    # Normalize between 0 and 1
    # Minimum score is -0.05 (controls=1.0, all others 0.0)
    # Maximum score is 1.0 (all positive values 1.0, controls=0.0)
    normalized_score = (raw_score + 0.05) / 1.05
    
    # Explicit clipping to [0.0, 1.0]
    normalized_score = max(0.0, min(1.0, normalized_score))
    
    # Stale Asset and Owner validation
    owner_team = asset_row.get("owner_team")
    is_orphaned = pd.isna(owner_team) or str(owner_team).strip() == ""
    last_seen_days = float(asset_row.get("last_seen_days", 0))
    is_stale = last_seen_days > 30.0
    
    # Package results
    return {
        "score": normalized_score,
        "raw_score": raw_score,
        "cvss": cvss,
        "exploit_status": "Active (KEV)" if is_in_kev else ("Exploit Available" if exploit_available else "None"),
        "threat_match_val": threat_match_val,
        "campaign_name": campaign_name,
        "threat_confidence": threat_confidence,
        "business_criticality": business_criticality,
        "security_controls_score": security_controls,
        "days_open": days_open,
        "is_orphaned": is_orphaned,
        "is_stale": is_stale,
        "owner_team": "Unassigned" if is_orphaned else str(owner_team).strip()
    }
