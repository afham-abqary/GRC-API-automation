# GRC Workflow Automation Tool

A Python tool that fetches real CVE vulnerability data from the NIST National 
Vulnerability Database (NVD) API, maps findings to ISO 27001:2022 controls, 
and generates audit-ready compliance reports.

Built as a personal project to learn GRC automation and REST API integration.

## What it does

- Fetches live CVE data from the NIST NVD API by keyword or severity
- Scores vulnerabilities using CVSS v3.1, v3.0, and v2
- Automatically maps each vulnerability to relevant ISO 27001:2022 controls
- Generates a CSV report with remediation timelines based on severity
- Displays a colour-coded terminal dashboard showing risk breakdown

## How to run

```bash
git clone https://github.com/afham-abqary/grc-api-automation
cd grc-api-automation
pip install -r requirements.txt
python main.py
```

## Example output