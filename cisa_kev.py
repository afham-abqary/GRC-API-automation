import requests
import time

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev_list():
    print("Fetching CISA Known Exploited Vulnerabilities catalogue...")
    
    try:
        res = requests.get(CISA_KEV_URL, timeout=30)
        res.raise_for_status()
        data = res.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        kev_ids = {vuln["cveID"] for vuln in vulnerabilities}
        
        print(f"Loaded {len(kev_ids)} known exploited vulnerabilities from CISA.")
        return kev_ids
    
    except requests.exceptions.ConnectionError:
        print("Warning: Could not reach CISA KEV. Skipping KEV check.")
        return set()
    except requests.exceptions.Timeout:
        print("Warning: CISA KEV request timed out. Skipping KEV check.")
        return set()
    except Exception as e:
        print(f"Warning: Could not load CISA KEV - {e}")
        return set()


def flag_kev_vulnerabilities(processed_risks, kev_ids):
    if not kev_ids:
        return processed_risks
    
    flagged = 0
    for risk in processed_risks:
        if risk["cve_id"] in kev_ids:
            risk["actively_exploited"] = True
            risk["kev_note"] = "ACTIVELY EXPLOITED - On CISA KEV list"
            flagged += 1
        else:
            risk["actively_exploited"] = False
            risk["kev_note"] = ""
    
    if flagged > 0:
        print(f"WARNING: {flagged} vulnerabilities are on the CISA Known Exploited Vulnerabilities list!")
    else:
        print("None of the fetched CVEs are on the CISA KEV list.")
    
    return processed_risks