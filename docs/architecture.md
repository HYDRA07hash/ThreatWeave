# ThreatWeave - Architecture

The system aggregates Indicators of Compromise (IOCs) from multiple feeds, validates and normalizes them, correlates occurrences to determine severity, enriches them with threat intelligence metadata, and generates defensive outputs (blocklists and summaries).

## Pipeline Flow

```mermaid
graph TD
    %% Styling
    classDef feedStyle fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#f8fafc;
    classDef processStyle fill:#0f172a,stroke:#10b981,stroke-width:2px,color:#f8fafc;
    classDef dbStyle fill:#1e1b4b,stroke:#8b5cf6,stroke-width:2px,color:#f8fafc;
    classDef outputStyle fill:#31102f,stroke:#ec4899,stroke-width:2px,color:#f8fafc;

    %% Data Sources / Feeds
    subgraph Feeds ["Threat Intel Feeds (CSV/JSON/API)"]
        F1["AbuseIPDB API<br/>(Malicious IPs)"]:::feedStyle
        F2["URLhaus Feed<br/>(Malicious URLs/Domains)"]:::feedStyle
        F3["AlienVault OTX API<br/>(IPs, Domains, Hashes)"]:::feedStyle
        Mock["Mock Feeds<br/>(Fallback Offline Mode)"]:::feedStyle
    end

    %% Pipeline Steps
    Step1["1. Load Feeds<br/>(HTTP requests with exponential backoff)"]:::processStyle
    Step2["2. Parse & Validate<br/>(CSV/JSON parsers + regex/ipaddress checks)"]:::processStyle
    Step3["3. Normalize<br/>(Map to unified schema structure)"]:::processStyle
    Step4["4. Correlate & Score<br/>(Track cross-feed matches & set severity)"]:::processStyle
    
    %% Enrichment & Database
    VT["VirusTotal API<br/>(Enrichment with 15s delay & caching)"]:::feedStyle
    DB[("Local SQLite Database<br/>(Parameterized SQL)")]:::dbStyle

    %% Outputs
    subgraph Outputs ["Defensive Outputs"]
        B1["Firewall IP Blocklist<br/>(.txt)"]:::outputStyle
        B2["DNS/Web Filter list<br/>(.csv)"]:::outputStyle
        B3["EDR/AV Hash list<br/>(.csv)"]:::outputStyle
        B4["Unified JSON blocklist<br/>(.json)"]:::outputStyle
        Rep["Summary Report<br/>(TXT/JSON)"]:::outputStyle
    end

    Dash["Flask Dashboard<br/>(Web UI Metrics, Sorting, & Downloads)"]:::processStyle

    %% Connections
    Feeds --> Step1
    Step1 --> Step2
    Step2 --> Step3
    Step3 --> Step4
    Step4 <--> DB
    Step4 <--> VT
    Step4 --> Outputs
    DB <--> Dash
    Outputs --> Dash
```

## Description of Pipeline Components

1. **Load Feeds**: Triggers HTTP requests to active feeds. Built-in retry logic executes up to 3 times with exponential backoff on network failures or 429 status codes. If a feed is offline, the pipeline proceeds with other active feeds and marks the status as partially successful.
2. **Parse & Validate**: Checks syntax (e.g. valid IP addresses using the `ipaddress` module, hash formats, URLs) and discards duplicate or malformed items to prevent database pollution.
3. **Normalize**: Maps data from diverse sources into a standard format containing: `value`, `ioc_type`, `source`, `category`, `first_seen`, and `raw_data`.
4. **Correlate & Score**: Aggregates normalized entries. Calculates severity based on feed overlap:
   - **High**: Found in 3+ sources.
   - **Medium**: Found in 2 sources.
   - **Low**: Found in 1 source.
5. **VirusTotal Enrichment**: Queries VT to enrich hashes, IPs, or URLs. Enforces a 15-second delay between queries and checks a local SQLite cache first to avoid hitting public API limits (500 requests/day).
6. **SQLite Database**: Stores raw records, cached VT lookups, and correlated metrics safely using parameterized SQL queries.
7. **Blocklist Generator**: Extracts High and Medium severity IOCs, splitting them into format-specific outputs for ingestion by security controls (Firewalls, Proxies, EDR).
8. **Flask Dashboard**: Renders key SOC metrics, displays a sortable table of threats, and hosts blocklist download controls.
