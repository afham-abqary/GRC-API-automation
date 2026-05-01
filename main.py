from api_client import fetch_vulnerabilities, fetch_recent_critical_vulnerabilities
from risk_processor import process_vulnerabilities, get_risk_statistics
from iso_mapper import map_to_iso_controls
from report_generator import generate_csv_report, print_terminal_dashboard


def run_vulnerability_search(keyword, results=10, severity=None):
    print(f"\nStarting GRC workflow for keyword: '{keyword}'")
    
    raw_vulns = fetch_vulnerabilities(keyword, results_per_page=results, severity=severity)
    
    if not raw_vulns:
        print("No vulnerabilities found. Try a different keyword.")
        return
    
    processed = process_vulnerabilities(raw_vulns)
    
    for risk in processed:
        risk["iso_controls"] = map_to_iso_controls(risk)
    
    stats = get_risk_statistics(processed)
    
    print_terminal_dashboard(processed, stats, keyword)
    
    export = input("\nExport to CSV report? (y/n): ").strip().lower()
    if export == "y":
        generate_csv_report(processed, keyword)
    
    return processed


def main():
    print("GRC WORKFLOW AUTOMATION TOOL")

    while True:
        print("\n--- Main Menu ---")
        print("1. Search vulnerabilities by keyword")
        print("2. Fetch recent critical vulnerabilities (last 30 days)")
        print("3. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == "1":
            keyword = input("Enter search keyword (e.g. 'sql injection', 'ransomware', 'network'): ").strip()
            if not keyword:
                print("Keyword cannot be empty.")
                continue
            
            try:
                results = int(input("Number of results to fetch (1-20, default 10): ").strip() or "10")
                results = max(1, min(20, results))
            except ValueError:
                results = 10
            
            severity_filter = input("Filter by severity? (LOW/MEDIUM/HIGH/CRITICAL or press Enter to skip): ").strip()
            severity_filter = severity_filter if severity_filter else None
            
            run_vulnerability_search(keyword, results, severity_filter)
        
        elif choice == "2":
            print("\nFetching recent critical vulnerabilities...")
            raw_vulns = fetch_recent_critical_vulnerabilities(days=30)
            
            if raw_vulns:
                processed = process_vulnerabilities(raw_vulns)
                for risk in processed:
                    risk["iso_controls"] = map_to_iso_controls(risk)
                stats = get_risk_statistics(processed)
                print_terminal_dashboard(processed, stats, "Recent Critical CVEs")
                
                export = input("\nExport to CSV report? (y/n): ").strip().lower()
                if export == "y":
                    generate_csv_report(processed, "recent_critical")
        
        elif choice == "3":
            print("\nGoodbye!")
            break
        
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()