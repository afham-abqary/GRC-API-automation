import requests
import time

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_vulnerabilities(keyword, results_per_page=10, severity=None):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page
    }

    if severity:
        params["cvssV3Severity"] = severity.upper()

    try:
        res = requests.get(NVD_BASE_URL, params=params, timeout=30)
        res.raise_for_status()
        data = res.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)
        print(f'Found {total} total results. Fetched {len(vulnerabilities)} vulnerabilites.')
        time.sleep(1)
        return vulnerabilities
    
    except requests.exceptions.ConnectionError:
        print("Error: Cannot connect to NVD API. Check your internet connection.")
        return []
    except requests.exceptions.Timeout:
        print("Error: API request timed out. Try again.")
        return []
    except requests.exceptions.HTTPError as e:
        print(f'Error: API returned an error - {e}')
        return []
    except Exception as e:
        print(f'Unexpected error: {e}')
        return []
    
def fetch_recent_critical_vulnerabilities(days=30):
    from datetime import datetime, timedelta

    start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
    end_date = datetime.now().strftime("%Y-%m-%dT23:59:59.000")

    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": 20
    }

    print(f'Fetching critical vulnerabilities from the last {days} days...')

    try:
        res = requests.get(NVD_BASE_URL, params=params, timeout=30)
        res.raise_for_status()
        data = res.json()
        vulnerabilities = data.get("vulnerabilities", [])
        print(f'Found {len(vulnerabilities)} critical vulnerabilities.')
        time.sleep(1)
        return vulnerabilities
    except Exception as e:
        print(f'Error fetching recent vulnerabilities: {e}')
        return []