ISO_CONTROLS = {
    "5.7":  "Threat intelligence",
    "5.23": "Information security for use of cloud services",
    "8.2":  "Privileged access rights",
    "8.3":  "Information access restriction",
    "8.7":  "Protection against malware",
    "8.8":  "Management of technical vulnerabilities",
    "8.9":  "Configuration management",
    "8.11": "Data masking",
    "8.15": "Logging",
    "8.16": "Monitoring activities",
    "8.19": "Installation of software on operational systems",
    "8.20": "Networks security",
    "8.21": "Security of network services",
    "8.22": "Segregation of networks",
    "8.25": "Secure development life cycle",
    "8.26": "Application security requirements",
    "8.27": "Secure system architecture and engineering principles",
    "8.28": "Secure coding",
    "8.29": "Security testing in development and acceptance",
    "8.32": "Change management",
}

KEYWORD_CONTROL_MAP = {
    "network": ["8.20", "8.21", "8.22", "5.7"],
    "firewall": ["8.20", "8.21", "8.9"],
    "router": ["8.20", "8.22", "8.9"],
    "dns": ["8.20", "8.21"],
    "vpn": ["8.20", "8.21", "8.3"],
    "authentication": ["8.2", "8.3"],
    "privilege": ["8.2", "8.3"],
    "access": ["8.2", "8.3"],
    "password": ["8.2", "8.3"],
    "bypass": ["8.2", "8.3", "8.7"],
    "sql injection": ["8.26", "8.28", "8.29"],
    "xss": ["8.26", "8.28", "8.29"],
    "cross-site": ["8.26", "8.28", "8.29"],
    "injection": ["8.26", "8.28", "8.29"],
    "web": ["8.25", "8.26", "8.27", "8.29"],
    "api": ["8.26", "8.27", "8.29"],
    "malware": ["8.7", "8.16", "5.7"],
    "ransomware": ["8.7", "8.16", "5.7"],
    "trojan": ["8.7", "8.16"],
    "virus": ["8.7", "8.16"],
    "backdoor": ["8.7", "8.16", "8.2"],
    "data": ["8.11", "8.3", "8.15"],
    "encryption": ["8.11", "8.3"],
    "disclosure": ["8.11", "8.15", "8.3"],
    "leak": ["8.11", "8.15"],
    "configuration": ["8.9", "8.19", "8.32"],
    "misconfiguration": ["8.9", "8.19"],
    "software": ["8.19", "8.8", "8.32"],
    "update": ["8.8", "8.19", "8.32"],
    "patch": ["8.8", "8.19"],
    "cloud": ["5.23", "8.9", "8.20"],
    "aws": ["5.23", "8.9", "8.3"],
    "azure": ["5.23", "8.9", "8.3"],
    "log": ["8.15", "8.16"],
    "monitor": ["8.15", "8.16", "5.7"],
    "detection": ["8.16", "5.7"],
    "default": ["8.8", "5.7", "8.16"]
}


def map_to_iso_controls(vulnerability):
    description = vulnerability.get("description", "").lower()
    matched_control_ids = set()
    
    for keyword, control_ids in KEYWORD_CONTROL_MAP.items():
        if keyword in description:
            matched_control_ids.update(control_ids)
    
    if not matched_control_ids:
        matched_control_ids.update(KEYWORD_CONTROL_MAP["default"])
    
    matched_control_ids.add("8.8")
    matched_control_ids.add("5.7")
    
    matched_controls = []
    for control_id in sorted(matched_control_ids):
        if control_id in ISO_CONTROLS:
            matched_controls.append({
                "id": control_id,
                "name": ISO_CONTROLS[control_id]
            })
    
    return matched_controls


def format_controls_for_report(controls):
    return "; ".join([f"{c['id']} - {c['name']}" for c in controls])