import json
from collections import defaultdict
from datetime import datetime
from threat_intel.database import get_all_raw_iocs, save_correlated_iocs
from threat_intel.utils import VirusTotalClient, logger

def correlate_and_score(enrich_high_medium=True):
    """
    Retrieves all raw IOCs from the database, group them by value,
    calculates their severity based on the number of distinct sources reporting them,
    enriches them with VirusTotal if configured, and saves the correlated records.
    Returns the list of correlated records.
    """
    logger.info("Starting correlation and scoring process...")
    
    # 1. Fetch raw items
    raw_records = get_all_raw_iocs()
    if not raw_records:
        logger.info("No raw IOCs found in the database. Correlation skipped.")
        return []
        
    # 2. Group raw records by IOC value
    grouped_iocs = defaultdict(list)
    for record in raw_records:
        grouped_iocs[record["value"]].append(record)
        
    # Initialize VT Client
    vt_client = VirusTotalClient()
    correlated_list = []
    
    # 3. Correlate details for each unique IOC value
    for value, records in grouped_iocs.items():
        # Get distinct sources
        sources = list(set(r["source"] for r in records))
        source_count = len(sources)
        
        # Calculate overall severity
        if source_count >= 3:
            severity = "High"
        elif source_count == 2:
            severity = "Medium"
        else:
            severity = "Low"
            
        # Classify the type (take the first records' type, they should be consistent)
        ioc_type = records[0]["ioc_type"]
        
        # Determine timestamps
        first_seens = []
        last_seens = []
        for r in records:
            # Parse ISO timestamps
            ts_str = r["first_seen"]
            try:
                # Strip 'Z' if present, parse, or keep string
                first_seens.append(ts_str)
                last_seens.append(ts_str)
            except Exception:
                pass
                
        first_seen = min(first_seens) if first_seens else datetime.utcnow().isoformat() + "Z"
        last_seen = max(last_seens) if last_seens else datetime.utcnow().isoformat() + "Z"
        
        # Combine categories / descriptions
        cats = [f"[{r['source']}] {r['category']}" for r in records if r.get("category")]
        description = " | ".join(cats)
        
        correlated_item = {
            "value": value,
            "ioc_type": ioc_type,
            "overall_severity": severity,
            "source_count": source_count,
            "sources": ", ".join(sources),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "description": description,
            "positives": -1,
            "total": -1,
            "vt_link": None
        }
        
        # 4. Enrich High and Medium severity IOCs with VirusTotal
        if enrich_high_medium and severity in ("High", "Medium"):
            logger.info(f"Enriching {severity} severity IOC: {value}")
            # Get cached or query VT
            vt_report = vt_client.query_ioc(value, ioc_type)
            if vt_report:
                correlated_item["positives"] = vt_report["positives"]
                correlated_item["total"] = vt_report["total"]
                correlated_item["vt_link"] = vt_report["permalink"]
                
                # Append VirusTotal data to description
                vt_desc = f" [VirusTotal Detections: {vt_report['positives']}/{vt_report['total']}]"
                correlated_item["description"] += vt_desc
                
        correlated_list.append(correlated_item)
        
    # 5. Save correlated list to the database
    save_correlated_iocs(correlated_list)
    logger.info(f"Correlation complete. Computed {len(correlated_list)} unique indicators.")
    return correlated_list
