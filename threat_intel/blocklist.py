import csv
import json
from threat_intel.config import BLOCKLIST_DIR
from threat_intel.database import get_correlated_iocs
from threat_intel.utils import logger

def generate_blocklists():
    """
    Fetches High and Medium severity correlated IOCs from the database and
    exports them into target-specific blocklist files:
    1. plain IP list (.txt) for firewalls
    2. malicious domain/URL list (.csv) for web filters
    3. hash list (.csv) for EDR/AV tools
    4. combined list (.json) for other integrations
    
    Returns:
        dict: A dictionary containing export statistics and paths.
    """
    logger.info("Generating defensive blocklists...")
    
    # 1. Fetch High/Medium severity IOCs
    high_iocs = get_correlated_iocs(severity_filter="High")
    med_iocs = get_correlated_iocs(severity_filter="Medium")
    target_iocs = high_iocs + med_iocs
    
    ips = []
    domains_urls = []
    hashes = []
    combined = []
    
    for ioc in target_iocs:
        val = ioc["value"]
        itype = ioc["ioc_type"]
        sev = ioc["overall_severity"]
        sources = ioc["sources"]
        
        entry = {
            "value": val,
            "type": itype,
            "severity": sev,
            "sources": sources,
            "first_seen": ioc["first_seen"],
            "last_seen": ioc["last_seen"]
        }
        combined.append(entry)
        
        if itype == "ip":
            ips.append(val)
        elif itype in ("domain", "url"):
            domains_urls.append(entry)
        elif itype in ("hash_md5", "hash_sha1", "hash_sha256"):
            hashes.append(entry)
            
    # Create export file paths
    ip_file = BLOCKLIST_DIR / "ips.txt"
    domain_url_file = BLOCKLIST_DIR / "domains_urls.csv"
    hash_file = BLOCKLIST_DIR / "hashes.csv"
    combined_file = BLOCKLIST_DIR / "combined.json"
    
    # Write plain IP list (.txt)
    try:
        with open(ip_file, "w", encoding="utf-8") as f:
            for ip in sorted(ips):
                f.write(f"{ip}\n")
        logger.info(f"Generated IP blocklist: {ip_file} ({len(ips)} IPs)")
    except Exception as e:
        logger.error(f"Error writing IP blocklist: {e}")
        
    # Write domains & URLs (.csv)
    try:
        with open(domain_url_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Value", "Type", "Severity", "Sources", "FirstSeen", "LastSeen"])
            for entry in domains_urls:
                writer.writerow([
                    entry["value"],
                    entry["type"],
                    entry["severity"],
                    entry["sources"],
                    entry["first_seen"],
                    entry["last_seen"]
                ])
        logger.info(f"Generated Domain/URL blocklist: {domain_url_file} ({len(domains_urls)} entries)")
    except Exception as e:
        logger.error(f"Error writing Domain/URL blocklist: {e}")
        
    # Write hashes (.csv)
    try:
        with open(hash_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Hash", "Type", "Severity", "Sources", "FirstSeen", "LastSeen"])
            for entry in hashes:
                writer.writerow([
                    entry["value"],
                    entry["type"],
                    entry["severity"],
                    entry["sources"],
                    entry["first_seen"],
                    entry["last_seen"]
                ])
        logger.info(f"Generated Hash blocklist: {hash_file} ({len(hashes)} hashes)")
    except Exception as e:
        logger.error(f"Error writing Hash blocklist: {e}")
        
    # Write combined JSON (.json)
    try:
        with open(combined_file, "w", encoding="utf-8") as f:
            json.dump({
                "meta": {
                    "total_count": len(combined),
                    "generator": "ThreatWeave",
                    "exported_at": combined_file.stat().st_mtime
                },
                "indicators": combined
            }, f, indent=4)
        logger.info(f"Generated Combined JSON blocklist: {combined_file} ({len(combined)} indicators)")
    except Exception as e:
        logger.error(f"Error writing Combined JSON blocklist: {e}")
        
    return {
        "ips_count": len(ips),
        "domains_urls_count": len(domains_urls),
        "hashes_count": len(hashes),
        "combined_count": len(combined),
        "files": {
            "ips": str(ip_file),
            "domains_urls": str(domain_url_file),
            "hashes": str(hash_file),
            "combined": str(combined_file)
        }
    }
