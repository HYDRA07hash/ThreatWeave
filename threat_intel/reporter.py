import json
from datetime import datetime
from threat_intel.config import REPORTS_DIR
from threat_intel.database import get_correlated_iocs, get_latest_sync_status
from threat_intel.utils import logger

def generate_report():
    """
    Analyzes the database contents and sync logs to generate a summary report.
    Saves the report as:
    1. A human-readable text file: reports/summary_report.txt
    2. A structured JSON file: reports/summary_report.json
    
    Returns:
        dict: The report data structure.
    """
    logger.info("Generating threat intelligence report...")
    
    # 1. Fetch latest sync status
    sync_status = get_latest_sync_status()
    feeds_processed = {}
    last_sync_time = "Never"
    if sync_status:
        feeds_processed = sync_status.get("details", {})
        last_sync_time = sync_status.get("sync_time", "Unknown")
        
    # 2. Fetch correlated indicators
    iocs = get_correlated_iocs()
    total_unique = len(iocs)
    
    # 3. Calculate metrics
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    type_counts = {"ip": 0, "domain": 0, "url": 0, "hash_md5": 0, "hash_sha1": 0, "hash_sha256": 0, "email": 0}
    
    for ioc in iocs:
        sev = ioc["overall_severity"]
        itype = ioc["ioc_type"]
        
        if sev in severity_counts:
            severity_counts[sev] += 1
        if itype in type_counts:
            type_counts[itype] += 1
            
    # 4. Top 10 correlated indicators
    top_10 = iocs[:10]
    
    report_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "last_sync_time": last_sync_time,
        "feeds_processed": feeds_processed,
        "metrics": {
            "total_unique_iocs": total_unique,
            "severity_distribution": severity_counts,
            "type_distribution": type_counts
        },
        "top_correlated_indicators": [
            {
                "value": item["value"],
                "type": item["ioc_type"],
                "severity": item["overall_severity"],
                "source_count": item["source_count"],
                "sources": item["sources"],
                "positives": item["positives"],
                "total": item["total"]
            }
            for item in top_10
        ]
    }
    
    # Write JSON report
    json_path = REPORTS_DIR / "summary_report.json"
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        logger.info(f"Generated JSON report: {json_path}")
    except Exception as e:
        logger.error(f"Error writing JSON report: {e}")
        
    # Write text report
    txt_path = REPORTS_DIR / "summary_report.txt"
    try:
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("==================================================\n")
            f.write("             THREATWEAVE SUMMARY REPORT           \n")
            f.write("==================================================\n")
            f.write(f"Generated At:       {report_data['generated_at']}\n")
            f.write(f"Last Sync Time:     {report_data['last_sync_time']}\n")
            f.write(f"Total Unique IOCs:  {total_unique}\n\n")
            
            f.write("--- FEED INGESTION STATUS ---\n")
            for feed, details in feeds_processed.items():
                f.write(f"- {feed}: {details.get('status')} | Ingested Count: {details.get('count', 0)}\n")
            f.write("\n")
            
            f.write("--- SEVERITY DISTRIBUTION ---\n")
            for sev, count in severity_counts.items():
                f.write(f"- {sev}: {count}\n")
            f.write("\n")
            
            f.write("--- IOC TYPE DISTRIBUTION ---\n")
            for itype, count in type_counts.items():
                f.write(f"- {itype.upper()}: {count}\n")
            f.write("\n")
            
            f.write("--- TOP 10 CORRELATED INDICATORS ---\n")
            f.write(f"{'Indicator':<40} | {'Type':<12} | {'Sources':<3} | {'Severity':<6} | {'VT Detections':<12}\n")
            f.write("-" * 85 + "\n")
            for item in report_data["top_correlated_indicators"]:
                vt_det = "N/A"
                if item["positives"] != -1:
                    vt_det = f"{item['positives']}/{item['total']}"
                f.write(f"{item['value']:<40} | {item['type']:<12} | {item['source_count']:<7} | {item['severity']:<8} | {vt_det:<12}\n")
                
        logger.info(f"Generated TXT report: {txt_path}")
    except Exception as e:
        logger.error(f"Error writing TXT report: {e}")
        
    return report_data
