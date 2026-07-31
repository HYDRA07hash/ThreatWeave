# B.Tech Cybersecurity Internship Project Report

**Project Title**: ThreatWeave - Threat Intelligence Aggregator & Correlation System (Non-AI)  
**Focus Area**: Cyber Defense, Threat Intel Ingestion, Vulnerability Correlation, and Automated Blocklist Provisioning  
**Portfolio Scope**: Portfolio-aligned defensive security tool sitting alongside SentinelShield (IDS) and ScanVault (Malware Analyzer).

---

## 1. Executive Summary

In modern Security Operations Centers (SOCs), threat intelligence is essential for proactive defense. Security telemetry relies on feeds consisting of malicious IP addresses, domain names, file hashes, and URLs. However, raw threat feeds are often formatted inconsistently, contain duplicate entries, suffer from transient false positives, and fail to correlate occurrences across distinct sensors.

This project implements **ThreatWeave**, a rule-based Threat Intelligence Aggregator in Python. The system fetches threat indicators from free-tier repositories, validates and parses them using standard libraries, translates them into a single unified schema, correlates overlapping occurrences to determine confidence/severity levels, and automatically exports firewall, DNS filter, and EDR-compatible blocklists. The interface is displayed via a custom glassmorphic Flask web dashboard that offers interactive search, sorting, pagination, and direct downloads.

---

## 2. Core Modules Architecture & Implementation

The architecture operates strictly on a deterministic pipeline designed around six core modules:

```text
Load Feeds ──> Parse & Validate ──> Normalize ──> Correlate & Score ──> Blocklist & Report
```

### 2.1. IOC Feed Parser (`parser.py`)
- **Feeds Integrated**: AbuseIPDB (JSON blacklist API), URLhaus (recent malicious CSV feed), and AlienVault OTX (subscribed pulses JSON endpoint).
- **Graceful Error Handling**: Uses an exponential-backoff wrapper (`requests_with_retry` in `utils.py`) to retry up to 3 times on connection drops or HTTP 429 (rate-limit) status codes.
- **Fail-Safe Operation**: If a feed fails to load, it logs the error and continues sync operations using the remaining sources to prevent system-wide crashes.
- **Mock Feed Support**: Includes offline mock datasets that automatically load if API keys are not supplied.

### 2.2. Normalization Engine (`normalizer.py`)
- **Refanging**: Resolves defanged text values (e.g., converting `hxxps://malicious[.]com` to `https://malicious.com`).
- **Validation**: Filters indicators utilizing standard `ipaddress` validation for IPv4/IPv6 and strict regular expressions for domains, URLs, email addresses, and cryptographic hashes (MD5, SHA-1, SHA-256). Invalid items are discarded.
- **Unified Schema Mapping**: Standardizes entries into a dictionary layout consisting of:
  ```json
  {
    "value": "198.51.100.12",
    "ioc_type": "ip",
    "source": "AbuseIPDB",
    "category": "SSH brute force brute",
    "first_seen": "2026-07-20T12:00:00Z",
    "raw_data": "..."
  }
  ```

### 2.3. Correlation & Severity Engine (`correlator.py` & `database.py`)
- **Overlapping Detections**: Scans the SQLite database for unique indicators reported by multiple separate feeds.
- **Severity Scoring Rules**:
  - **High**: Indicators reported by 3 or more distinct sources.
  - **Medium**: Indicators reported by 2 distinct sources.
  - **Low**: Indicators reported by 1 source.
- **VirusTotal Enrichment Cache**: Queries the VirusTotal API v3 for High and Medium indicators to check detection scores. To stay within public limit rates (4 requests/minute), the engine queries a local SQLite table (`vt_cache`) first. If cache is missed, a live query is initiated with a 15-second delay to guarantee compliance with public limits.

### 2.4. Blocklist Generator (`blocklist.py`)
Extracts High and Medium severity threats from the database and exports them to their respective formats:
1. **Firewalls**: Plain-text list of IP addresses (`blocklists/ips.txt`).
2. **Web Filters**: CSV structure containing malicious domains and URLs (`blocklists/domains_urls.csv`).
3. **EDR/AV Sensors**: CSV file containing MD5, SHA-1, and SHA-256 hashes (`blocklists/hashes.csv`).
4. **Custom Integrations**: A unified JSON export (`blocklists/combined.json`).

### 2.5. Reporting Module (`reporter.py`)
Processes metrics from the database and outputs:
- A human-readable text file summary (`reports/summary_report.txt`).
- A machine-readable JSON structure (`reports/summary_report.json`) tracking feed counts, severity spreads, type distributions, and the top 10 most correlated indicators.

### 2.6. Flask Dashboard Web UI (`app.py` & `templates/dashboard.html`)
- **Metrics Dashboard**: Displays cards for unique indicators, threat severity splits, sync times, and ingestion health.
- **Interactive Control**: Trigger sync queries via AJAX to run normalization and correlation without refreshing the page.
- **Data Table**: Features pagination, instant text search, column sorting, copying, and direct links to VT records.

---

## 3. Security Hardening Controls

As a cybersecurity tool, the aggregator incorporates critical defense-in-depth principles:
- **Zero Secrets Leakage**: Secrets and keys are loaded strictly from the environment (`.env`) using `python-dotenv` and ignored in `.gitignore`.
- **SQL Injection Prevention**: Every SQLite connection executes strictly parameterized queries (e.g. `cursor.execute("SELECT * FROM table WHERE value = ?", (val,))`). String concatenation or formatting is prohibited.
- **Input Sanitization**: Discards malformed data using strict regex filters. Resolves defanged formats before running matches.
- **Basic Authentication**: Supports basic access auth on all dashboard and download routes (`REQUIRE_BASIC_AUTH=True`), which can be disabled on localhost for presentation ease.
- **Activity Auditing**: Logs successes, timeouts, rate limits, and partial failures with timestamps to a persistent file (`threat_intel.log`).

---

## 4. Key Learnings & Outcomes

1. **Rule-Based Threat Correlation**: Developed a solid understanding of logic-driven correlation without ML, relying on feed overlaps to increase reporting confidence.
2. **API Ingestion and Rate Control**: Mastered API limits handling by writing cached SQLite logic and enforcing timed query delays.
3. **Defensive Integration**: Created production-grade export formats that match the requirements of enterprise security gateways like pfSense, DNS filters, and antivirus agents.
4. **Safe Software Practices**: Practiced secure Python engineering, specifically preventing SQL injection and protecting configuration data.
