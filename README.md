# ThreatWeave - Threat Intelligence Aggregator

ThreatWeave is a Python-based, pure rule-based Threat Intelligence Aggregator and Correlation system designed for defensive cybersecurity. The tool fetches malicious Indicators of Compromise (IOCs) from multiple feeds, validates and normalizes them, correlates overlaps across sources to calculate severity, enriches threat metadata via VirusTotal, and exports active blocklists and reports.

This tool is designed to work alongside existing portfolio tools like **SentinelShield** (IDS/SOC dashboard) and **ScanVault** (static malware analysis).

---

## Features

1. **Rule-Based Parsing & Normalization**:
   - Parses AbuseIPDB, URLhaus, and AlienVault OTX feeds.
   - Extracts and validates IPv4/IPv6, domains, URLs, hashes (MD5, SHA-1, SHA-256), and emails.
   - Cleans and refangs indicators (e.g. converting `hxxps://` to `https://` or `[.]` to `.`).
   - Discards duplicates or malformed inputs.
2. **Correlation & Severity Engine**:
   - Assigns severity based on multi-source coverage:
     - **High Severity**: Ingested from 3+ distinct sources.
     - **Medium Severity**: Ingested from 2 distinct sources.
     - **Low Severity**: Ingested from 1 source.
   - Saves all data using parameterized SQL queries in a local SQLite database.
3. **VirusTotal Enrichment (Strict Rate Limits & Cache)**:
   - Queries VirusTotal API for High/Medium severity indicators.
   - Implements a local SQLite cache check to avoid redundant API queries.
   - Enforces a strict 15-second delay between queries to stay under the 4 requests/minute public API threshold.
4. **Defensive Integrations (Blocklists)**:
   - Exports High/Medium severity indicators into production-ready formats:
     - Plain IP text list (`blocklists/ips.txt`) for Firewalls.
     - Malicious Domains and URLs (`blocklists/domains_urls.csv`) for DNS/Web filters.
     - File hashes (`blocklists/hashes.csv`) for EDR and AV systems.
     - Combined JSON export (`blocklists/combined.json`) for SIEM/API integrations.
5. **Modern Dashboard UI**:
   - Renders statistics (unique indicators, feed health, severity cards).
   - Interactive AJAX sync trigger (real-time loader, no page reload).
   - Paginated, filterable, and sortable interactive indicators datatable.
   - Quick "click-to-copy" buttons on all IOC values.
   - Immediate access to download generated blocklists.

---

## Directory Structure

```text
threat-intel-aggregator/
│
├── threat_intel/             # Core Python Package
│   ├── __init__.py
│   ├── config.py             # App & Feed settings, .env configurations
│   ├── utils.py              # Log Setup, HTTP client, and VirusTotal v3 client
│   ├── parser.py             # Feed Fetchers (AbuseIPDB, URLhaus, OTX) with mock fallbacks
│   ├── normalizer.py         # Refanging, validation (regex + ipaddress), classification
│   ├── database.py           # SQLite initialization, parameterized CRUD operations
│   ├── correlator.py         # Cross-source correlation & severity logic
│   ├── blocklist.py          # Exporters (Firewall, DNS, EDR, SIEM formats)
│   └── reporter.py           # Text/JSON summary compiler
│
├── templates/
│   └── dashboard.html        # Glassmorphic, modern dashboard HTML layout
│
├── static/
│   └── style.css             # Glassmorphic Dark UI stylesheets with micro-animations
│
├── docs/
│   └── architecture.md       # Mermaid architecture pipeline diagram
│
├── blocklists/               # Exported firewall/EDR blocklist deliverables
├── reports/                  # Exported TXT/JSON SOC summaries
├── app.py                    # Flask server entrypoint
├── test_aggregator.py        # End-to-end integration test runner
├── .env.example              # Environment variables template
├── .env                      # Local environment settings (gitignored)
├── .gitignore                # Git ignore settings
├── requirements.txt          # Python dependencies
└── PROJECT_REPORT.md         # Academic/Internship Project Report
```

---

## Setup & Installation

### 1. Prerequisites
- Python 3.8 or higher.
- `pip` package manager.

### 2. Clone and Setup Environment
Open your terminal in the project directory:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Setup your .env file
# A default .env is already supplied in this directory. 
# If missing, copy from .env.example:
cp .env.example .env
```

### 3. API Key Setup
If you want live feed ingestion and VirusTotal enrichment, obtain free keys and paste them into `.env`:
- **AbuseIPDB**: Register at [abuseipdb.com](https://www.abuseipdb.com/) to get an API key.
- **AlienVault OTX**: Register at [otx.alienvault.com](https://otx.alienvault.com/) and obtain an API key from your profile settings.
- **VirusTotal**: Register at [virustotal.com](https://www.virustotal.com/) and copy your API key from the user menu.

> [!NOTE]
> **Demo/Mock Mode**: If API keys are left blank in `.env`, the parser will automatically load built-in simulated mock feeds. This makes the project fully runnable and interactive out-of-the-box without needing API credentials.

### 4. Basic Authentication Configuration
To protect the dashboard or download endpoints in production, you can enforce HTTP Basic Authentication:
- By default, basic auth is **OFF** for local/portfolio testing (`REQUIRE_BASIC_AUTH=False` in `.env`).
- To turn basic auth **ON**, set `REQUIRE_BASIC_AUTH=True` in `.env`.
- Modify credentials in `.env` using:
  ```env
  BASIC_AUTH_USERNAME=admin
  BASIC_AUTH_PASSWORD=your-custom-secure-password
  ```

### 5. Debug Mode Configuration
- By default, Flask's debug mode is **disabled** (`FLASK_DEBUG=False` in `.env`).
- > [!WARNING]
  > Flask's debug mode exposes an interactive debugger that allows arbitrary code execution on unhandled exceptions. **Only enable `FLASK_DEBUG=True` for local development. Never enable it when the application is exposed on a public network.**

---

## How to Run

### Run Integration Test
To run a fast verification script that initializes the database, simulates feed sync, runs correlation, generates blocklists, and compiles a text report:

```bash
python test_aggregator.py
```

### Run the Dashboard Web Server
To launch the Flask web interface:

```bash
python app.py
```
After launching, navigate to [http://localhost:5000](http://localhost:5000) in your web browser.

---

## Defensive Outputs Example

1. **Firewall Blocklist (`blocklists/ips.txt`)**:
   ```text
   198.51.100.12
   ```
2. **EDR/AV Hash blocklist (`blocklists/hashes.csv`)**:
   ```csv
   Hash,Type,Severity,Sources,FirstSeen,LastSeen
   85136c79cbf9fe36bb9d05d0639c70c265c18d37,hash_sha1,Medium,"AlienVault OTX",2026-07-20T12:00:00Z,2026-07-20T12:00:00Z
   ```
3. **Summary Report (`reports/summary_report.txt`)**:
   Shows feed statistics, severity counts, and top correlated indicators. Read the generated reports under `/reports`.
