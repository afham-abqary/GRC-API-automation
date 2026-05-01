import csv
import os
from datetime import datetime
from colorama import Fore, Style, init
from iso_mapper import format_controls_for_report


def generate_csv_report(processed_risks, keyword, output_dir="."):
    if not processed_risks:
        print("No risks to report.")
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"grc_report_{keyword.replace(' ', '_')}_{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)
    
    fieldnames = [
        "CVE ID",
        "Severity",
        "CVSS Score",
        "Actively Exploited",
        "Description",
        "Published Date",
        "Last Modified",
        "ISO 27001 Controls",
        "Recommended Action",
        "Status"
    ]
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for risk in processed_risks:
            severity = risk.get("severity", "UNKNOWN")
            score = risk.get("cvss_score", 0)
            
            if severity == "CRITICAL" or score >= 9.0:
                action = "Immediate patching required within 24 hours"
            elif severity == "HIGH" or score >= 7.0:
                action = "Patch within 7 days"
            elif severity == "MEDIUM" or score >= 4.0:
                action = "Patch within 30 days"
            else:
                action = "Patch in next maintenance window"
            
            controls = risk.get("iso_controls", [])
            controls_str = format_controls_for_report(controls)
            
            writer.writerow({
                "CVE ID": risk.get("cve_id", ""),
                "Severity": severity,
                "CVSS Score": score,
                "Actively Exploited": risk.get("kev_note", ""),
                "Description": risk.get("description", ""),
                "Published Date": risk.get("published", ""),
                "Last Modified": risk.get("last_modified", ""),
                "ISO 27001 Controls": controls_str,
                "Recommended Action": action,
                "Status": "Open"
            })
    
    print(f"Report saved to: {filepath}")
    return filepath


def print_terminal_dashboard(processed_risks, stats, keyword):
    try:
        init()
        use_color = True
    except ImportError:
        use_color = False

    print("\n")
    print(f"GRC VULNERABILITY REPORT - '{keyword.upper()}'")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if not stats:
        print("No data available.")
        return
    
    print(f"Total Vulnerabilities : {stats['total']}")
    print(f"Average CVSS Score    : {stats['average_score']}")
    print(f"Highest CVSS Score    : {stats['highest_score']}")
    
    print("\nBreakdown by Severity:")
    counts = stats.get("counts", {})
    
    severity_colors = {}
    if use_color:
        severity_colors = {
            "CRITICAL": Fore.RED,
            "HIGH": Fore.YELLOW,
            "MEDIUM": Fore.CYAN,
            "LOW": Fore.GREEN,
            "UNKNOWN": Fore.WHITE
        }
    
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = counts.get(severity, 0)
        if count > 0:
            bar = "#" * count
            label = f"  {severity:<10}: {bar} ({count})"
            if use_color:
                print(severity_colors[severity] + label + Style.RESET_ALL)
            else:
                print(label)
    
    print("\nTop 5 Highest Severity Vulnerabilities:")
    print(f"{'CVE ID':<20} {'Score':<8} {'Severity':<12} Description")
    
    for risk in processed_risks[:5]:
        desc_preview = risk['description'][:35] + "..." if len(risk['description']) > 35 else risk['description']
        print(f"{risk['cve_id']:<20} {risk['cvss_score']:<8} {risk['severity']:<12} {desc_preview}")
    