def extract_cvss_score(cve_data):
    metrics = cve_data.get("metrics", {})
    
    v31 = metrics.get("cvssMetricV31", [])
    if v31 and len(v31) > 0:
        cvss_data = v31[0].get("cvssData", {})
        score = cvss_data.get("baseScore", 0.0)
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        return float(score), str(severity)
    
    v30 = metrics.get("cvssMetricV30", [])
    if v30 and len(v30) > 0:
        cvss_data = v30[0].get("cvssData", {})
        score = cvss_data.get("baseScore", 0.0)
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        return float(score), str(severity)
    
    v2 = metrics.get("cvssMetricV2", [])
    if v2 and len(v2) > 0:
        cvss_data = v2[0].get("cvssData", {})
        score = float(cvss_data.get("baseScore", 0.0))
        if score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        return score, severity
    
    return 0.0, "UNKNOWN"


def get_english_description(cve_data):
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "No description available")
    return "No description available"


def process_vulnerability(vuln_entry):
    cve = vuln_entry.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    description = get_english_description(cve)
    score, severity = extract_cvss_score(cve)
    published = str(cve.get("published", ""))[:10]
    last_modified = str(cve.get("lastModified", ""))[:10]
    
    return {
        "cve_id": str(cve_id),
        "description": description[:200] + "..." if len(description) > 200 else description,
        "cvss_score": float(score),
        "severity": str(severity),
        "published": published,
        "last_modified": last_modified
    }


def process_vulnerabilities(raw_vulnerabilities):
    processed = []
    
    for vuln in raw_vulnerabilities:
        try:
            risk = process_vulnerability(vuln)
            processed.append(risk)
        except Exception as e:
            print(f"Warning: Could not process vulnerability - {e}")
            continue
    
    processed.sort(key=lambda x: x["cvss_score"], reverse=True)
    return processed


def get_risk_statistics(processed_risks):
    if not processed_risks:
        return {}
    
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    total_score = 0.0
    
    for risk in processed_risks:
        severity = risk.get("severity", "UNKNOWN")
        if severity in counts:
            counts[severity] += 1
        else:
            counts["UNKNOWN"] += 1
        total_score += risk.get("cvss_score", 0.0)
    
    return {
        "total": len(processed_risks),
        "counts": counts,
        "average_score": round(total_score / len(processed_risks), 2),
        "highest_score": processed_risks[0]["cvss_score"] if processed_risks else 0
    }