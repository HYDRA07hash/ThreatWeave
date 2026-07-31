import csv
import json
from threat_intel.config import (
    ABUSEIPDB_API_KEY, OTX_API_KEY, ABUSEIPDB_FEED_URL, URLHAUS_FEED_URL, OTX_FEED_URL
)
from threat_intel.utils import requests_with_retry, logger

# Mock data for fallback / local demo mode
MOCK_ABUSEIPDB = [
    {"ipAddress": "198.51.100.12", "abuseConfidenceScore": 95, "countryCode": "US", "comment": "SSH brute force brute"},
    {"ipAddress": "203.0.113.45", "abuseConfidenceScore": 88, "countryCode": "CN", "comment": "Botnet command & control"},
    {"ipAddress": "198.51.100.55", "abuseConfidenceScore": 100, "countryCode": "RU", "comment": "Port scanning activity"},
    {"ipAddress": "45.227.254.10", "abuseConfidenceScore": 92, "countryCode": "BR", "comment": "Malicious spam sender"},
    {"ipAddress": "185.220.101.5", "abuseConfidenceScore": 85, "countryCode": "DE", "comment": "Tor exit node running scans"},
    # Bug 5 overlap: IP with CIDR in one, without CIDR in another
    {"ipAddress": "198.51.100.20/32", "abuseConfidenceScore": 99, "countryCode": "US", "comment": "Active SSH Brute Forcer"},
    # Bug 8 overlap: Hash reported by all three mock sources (64 chars)
    {"ipAddress": "d03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85", "abuseConfidenceScore": 99, "countryCode": "US", "comment": "Emotet Crypt Dropper Hash"}
]

MOCK_URLHAUS = """# URLhaus CSV Feed
# Generated on: 2026-07-20
# Columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
1,2026-07-20 12:00:00,http://phishing-login-update.com/signin,online,2026-07-20,phishing,phishing,https://urlhaus.abuse.ch/url/1/,reporter1
2,2026-07-20 12:10:00,http://203.0.113.45/malware/dropper.exe,online,2026-07-20,malware_download,exe,https://urlhaus.abuse.ch/url/2/,reporter2
3,2026-07-20 12:20:00,http://super-malicious-domain.xyz/payload.bin,online,2026-07-20,malware_download,bin,https://urlhaus.abuse.ch/url/3/,reporter1
4,2026-07-20 12:30:00,https://compromised-site.org/wp-content/themes/shell.php,online,2026-07-20,backdoor,webshell,https://urlhaus.abuse.ch/url/4/,reporter3
5,2026-07-20 12:40:00,http://198.51.100.12/scan.sh,online,2026-07-20,malware_download,sh,https://urlhaus.abuse.ch/url/5/,reporter2
6,2026-07-20 12:50:00,http://Phish-Site.com/path/,online,2026-07-20,phishing,phish,https://urlhaus.abuse.ch/url/6/,reporter1
7,2026-07-20 12:55:00,d03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85,online,2026-07-20,malware,emotet,https://urlhaus.abuse.ch/url/7/,reporter1
"""

MOCK_OTX = {
    "results": [
        {
            "name": "Cobalt Strike C2 Campaign",
            "indicators": [
                {"indicator": "198.51.100.12", "type": "IPv4", "description": "Cobalt Strike beacon host"},
                {"indicator": "super-malicious-domain.xyz", "type": "domain", "description": "C2 domain"},
                {"indicator": "5e883f82d168d8393e837f8f9024f923c59a6866", "type": "FileHash-SHA1", "description": "Malicious DLL payload"},
                {"indicator": "85136c79cbf9fe36bb9d05d0639c70c265c18d37", "type": "FileHash-SHA1", "description": "Cobalt Strike loader"},
                {"indicator": "d03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85", "type": "FileHash-SHA256", "description": "Emotet dropper bin"},
                {"indicator": "phishing-login-update.com", "type": "domain", "description": "Phishing landing domain"},
                # Bug 5 overlap: IP without CIDR
                {"indicator": "198.51.100.20", "type": "IPv4", "description": "Known SSH Scanner"},
                # Bug 6 overlap: URL with casing / fragment / trailing slash variation
                {"indicator": "HTTP://PHISH-SITE.COM/path", "type": "URL", "description": "C2 landing URL"}
            ]
        }
    ]
}

def parse_abuseipdb(force_mock=False):
    """
    Fetches and parses AbuseIPDB JSON feed. Falls back to mock data if key is missing or API errors.
    Returns: (list of raw records, status_message)
    """
    if force_mock or not ABUSEIPDB_API_KEY:
        logger.info("AbuseIPDB API key missing or forced mock. Using simulated local feed.")
        records = []
        for item in MOCK_ABUSEIPDB:
            records.append({
                "value": item["ipAddress"],
                "source": "AbuseIPDB",
                "category": item["comment"],
                "raw": json.dumps(item)
            })
        return records, "Success (Mock Data)"
        
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "limit": 100
    }
    
    logger.info("Fetching AbuseIPDB feed...")
    response = requests_with_retry(ABUSEIPDB_FEED_URL, headers=headers, params=params, method="GET")
    
    if not response or response.status_code != 200:
        logger.error("Failed to fetch AbuseIPDB live feed. Falling back to mock data.")
        # Fallback
        records = []
        for item in MOCK_ABUSEIPDB:
            records.append({
                "value": item["ipAddress"],
                "source": "AbuseIPDB (Fallback)",
                "category": item["comment"],
                "raw": json.dumps(item)
            })
        return records, "Partial Success (Fallback to Mock due to API Failure)"
        
    try:
        data = response.json()
        ip_list = data.get("data", [])
        records = []
        for item in ip_list:
            records.append({
                "value": item.get("ipAddress"),
                "source": "AbuseIPDB",
                "category": f"Abuse Score: {item.get('abuseConfidenceScore', 0)}% | Country: {item.get('countryCode', 'Unknown')}",
                "raw": json.dumps(item)
            })
        return records, "Success"
    except Exception as e:
        logger.error(f"Error parsing AbuseIPDB JSON response: {e}")
        return [], f"Failed (Parse Error: {e})"

def parse_urlhaus(force_mock=False):
    """
    Fetches and parses URLhaus CSV recent feed (no key required). Falls back to mock data if API errors.
    Returns: (list of raw records, status_message)
    """
    if force_mock:
        logger.info("Forced mock mode. Using simulated URLhaus feed.")
        csv_text = MOCK_URLHAUS
        status = "Success (Mock Data)"
        source_name = "URLhaus"
    else:
        logger.info("Fetching URLhaus feed...")
        response = requests_with_retry(URLHAUS_FEED_URL, method="GET")
        
        if not response or response.status_code != 200:
            logger.error("Failed to fetch URLhaus live feed. Falling back to mock data.")
            csv_text = MOCK_URLHAUS
            status = "Partial Success (Fallback to Mock due to API Failure)"
            source_name = "URLhaus (Fallback)"
        else:
            csv_text = response.text
            status = "Success"
            source_name = "URLhaus"
        
    records = []
    try:
        lines = csv_text.splitlines()
        # Parse CSV lines, skipping comments
        reader = csv.reader([line for line in lines if not line.strip().startswith("#")])
        for row in reader:
            if not row or len(row) < 6:
                continue
            # Column mapping based on URLhaus headers:
            # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            url_val = row[2]
            threat_cat = row[5]
            tags = row[6]
            records.append({
                "value": url_val,
                "source": source_name,
                "category": f"Threat: {threat_cat} | Tags: {tags}",
                "raw": ",".join(row)
            })
            
            # Also extract domain from URL to increase cross-feed correlation
            # URL format is like http://domain.com/path
            from urllib.parse import urlparse
            parsed_url = urlparse(url_val)
            domain_val = parsed_url.netloc.split(":")[0]  # remove port if any
            if domain_val:
                # Do not treat hashes or raw IPs as domains
                from threat_intel.normalizer import classify_ioc
                ioc_type, _ = classify_ioc(domain_val)
                if domain_val and ioc_type == "domain":
                    records.append({
                        "value": domain_val,
                        "source": source_name,
                        "category": f"Domain of URLhaus URL ({threat_cat})",
                        "raw": f"URLhaus parent: {url_val}"
                    })
        return records, status
    except Exception as e:
        logger.error(f"Error parsing URLhaus CSV response: {e}")
        return [], f"Failed (Parse Error: {e})"

def parse_otx(force_mock=False):
    """
    Fetches and parses AlienVault OTX. Falls back to mock data if key is missing or API errors.
    Returns: (list of raw records, status_message)
    """
    if force_mock or not OTX_API_KEY:
        logger.info("AlienVault OTX API key missing or forced mock. Using simulated local feed.")
        records = []
        for pulse in MOCK_OTX["results"]:
            for ind in pulse["indicators"]:
                records.append({
                    "value": ind["indicator"],
                    "source": "AlienVault OTX",
                    "category": f"Pulse: {pulse['name']} | Type: {ind['type']} | Desc: {ind['description']}",
                    "raw": json.dumps(ind)
                })
        return records, "Success (Mock Data)"
        
    # Endpoint: Subscribed pulses
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }
    
    logger.info("Fetching AlienVault OTX subscribed pulses...")
    response = requests_with_retry(url, headers=headers, method="GET")
    
    # Try public active pulses if subscribed pulses returns empty or fails
    if not response or response.status_code != 200:
        logger.warning("OTX Subscribed pulses lookup failed. Retrying with active public pulses feed...")
        url = "https://otx.alienvault.com/api/v1/pulses/activity"
        response = requests_with_retry(url, headers=headers, method="GET")
        
    if not response or response.status_code != 200:
        logger.error("Failed to fetch AlienVault OTX live feed. Falling back to mock data.")
        records = []
        for pulse in MOCK_OTX["results"]:
            for ind in pulse["indicators"]:
                records.append({
                    "value": ind["indicator"],
                    "source": "AlienVault OTX (Fallback)",
                    "category": f"Pulse: {pulse['name']} | Type: {ind['type']}",
                    "raw": json.dumps(ind)
                })
        return records, "Partial Success (Fallback to Mock due to API Failure)"
        
    try:
        data = response.json()
        pulses = data.get("results", [])
        records = []
        for pulse in pulses:
            pulse_name = pulse.get("name", "Unknown Pulse")
            indicators = pulse.get("indicators", [])
            for ind in indicators:
                records.append({
                    "value": ind.get("indicator"),
                    "source": "AlienVault OTX",
                    "category": f"Pulse: {pulse_name} | Type: {ind.get('type')} | Desc: {ind.get('description', '')}",
                    "raw": json.dumps(ind)
                })
        return records, "Success"
    except Exception as e:
        logger.error(f"Error parsing AlienVault OTX response: {e}")
        return [], f"Failed (Parse Error: {e})"

def fetch_all_feeds(force_mock=False):
    """
    Fetches indicators from all active sources.
    Returns:
        dict: A summary status mapping feed name to its status (succeeded/failed) and item counts.
        list: All raw parsed records collected from all feeds.
    """
    records = []
    sync_status = {}
    
    # 1. AbuseIPDB
    logger.info("Parsing AbuseIPDB Feed...")
    abuse_records, abuse_status = parse_abuseipdb(force_mock=force_mock)
    records.extend(abuse_records)
    sync_status["AbuseIPDB"] = {"status": abuse_status, "count": len(abuse_records)}
    
    # 2. URLhaus
    logger.info("Parsing URLhaus Feed...")
    urlhaus_records, urlhaus_status = parse_urlhaus(force_mock=force_mock)
    records.extend(urlhaus_records)
    sync_status["URLhaus"] = {"status": urlhaus_status, "count": len(urlhaus_records)}
    
    # 3. AlienVault OTX
    logger.info("Parsing AlienVault OTX Feed...")
    otx_records, otx_status = parse_otx(force_mock=force_mock)
    records.extend(otx_records)
    sync_status["AlienVault OTX"] = {"status": otx_status, "count": len(otx_records)}
    
    return sync_status, records
