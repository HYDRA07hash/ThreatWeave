import sys
from pathlib import Path

# Add project root to python path to import threat_intel
project_root = Path(__file__).resolve().parent
sys.path.append(str(project_root))

from threat_intel.database import init_db, get_db_connection, get_all_raw_iocs, get_correlated_iocs
from threat_intel.parser import fetch_all_feeds
from threat_intel.normalizer import normalize_ioc
from threat_intel.database import save_raw_iocs, log_sync_history
from threat_intel.correlator import correlate_and_score
from threat_intel.blocklist import generate_blocklists
from threat_intel.reporter import generate_report

def main():
    print("====================================================")
    print("                 ThreatWeave - Test Run             ")
    print("====================================================")
    
    # 1. Initialize database
    print("\n1. Initializing SQLite Database...")
    init_db()
    
    # Clear tables for clean test run
    conn = get_db_connection()
    conn.execute("DELETE FROM raw_iocs")
    conn.execute("DELETE FROM correlated_iocs")
    conn.commit()
    conn.close()
    
    # 2. Fetch Feeds
    print("\n2. Fetching feeds (forcing mock mode to test correlation overlaps)...")
    sync_status, raw_feed_items = fetch_all_feeds(force_mock=True)
    print(f"Fetch completed. Status details: {sync_status}")
    print(f"Collected {len(raw_feed_items)} raw feed records.")
    
    # 3. Normalize parsed records
    print("\n3. Normalizing and validating parsed IOCs...")
    normalized_records = []
    malformed_count = 0
    for item in raw_feed_items:
        norm = normalize_ioc(item["value"], item["source"], item["category"])
        if norm:
            normalized_records.append(norm)
        else:
            malformed_count += 1
            
    print(f"Normalization complete: {len(normalized_records)} succeeded, {malformed_count} discarded as malformed.")
    
    # 4. Save normalized raw IOCs to database
    print("\n4. Saving normalized raw IOCs to raw_iocs database table...")
    save_raw_iocs(normalized_records)
    log_sync_history("Success", sync_status)
    
    # Verify raw records in database
    db_raw = get_all_raw_iocs()
    print(f"DB raw_iocs table now contains {len(db_raw)} entries.")
    
    # 5. Correlate and score severity
    print("\n5. Running Correlation Engine...")
    # Note: we disable live VT enrichment in test to avoid delay / errors if VT key not set.
    # Set enrich_high_medium=False to bypass live VT lookup.
    correlated_items = correlate_and_score(enrich_high_medium=False)
    print(f"Correlation complete: Computed {len(correlated_items)} unique indicators.")
    
    # Print out severity stats
    high_count = sum(1 for c in correlated_items if c["overall_severity"] == "High")
    med_count = sum(1 for c in correlated_items if c["overall_severity"] == "Medium")
    low_count = sum(1 for c in correlated_items if c["overall_severity"] == "Low")
    print(f"Severity Breakdown: High={high_count}, Medium={med_count}, Low={low_count}")
    
    # 6. Generate defensive blocklists
    print("\n6. Exporting blocklists...")
    stats = generate_blocklists()
    print(f"Blocklists exported:")
    print(f"- Firewall IP list: {stats['ips_count']} entries")
    print(f"- DNS/Web filter list: {stats['domains_urls_count']} entries")
    print(f"- AV/EDR hash list: {stats['hashes_count']} entries")
    print(f"- Combined JSON: {stats['combined_count']} entries")
    
    # 7. Generate Reporting Summary
    print("\n7. Generating SOC Intelligence report...")
    report = generate_report()
    print(f"Reports saved to reports/ folder.")
    print("Report Top Indicators:")
    for ind in report["top_correlated_indicators"]:
        print(f"  - {ind['value']} ({ind['type']}): Severity={ind['severity']}, Sources Count={ind['source_count']} ({ind['sources']})")
        
    print("\n====================================================")
    print("              Test Execution Completed!             ")
    print("====================================================")

if __name__ == "__main__":
    main()
