import sys
import json
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file, Response

# Add current folder to path
sys.path.append(str(Path(__file__).resolve().parent))

from threat_intel.config import (
    PORT, FLASK_SECRET_KEY, REQUIRE_BASIC_AUTH, BASIC_AUTH_USERNAME, BASIC_AUTH_PASSWORD,
    BLOCKLIST_DIR, REPORTS_DIR, FLASK_DEBUG
)
from threat_intel.database import (
    init_db, get_db_connection, get_latest_sync_status, log_sync_history, get_correlated_iocs
)
from threat_intel.parser import fetch_all_feeds
from threat_intel.normalizer import normalize_ioc
from threat_intel.database import save_raw_iocs
from threat_intel.correlator import correlate_and_score
from threat_intel.blocklist import generate_blocklists
from threat_intel.reporter import generate_report
from threat_intel.utils import logger

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# Basic Auth Decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not REQUIRE_BASIC_AUTH:
            return f(*args, **kwargs)
            
        auth = request.authorization
        if not auth or not (auth.username == BASIC_AUTH_USERNAME and auth.password == BASIC_AUTH_PASSWORD):
            return Response(
                'Could not verify your access level for this URL.\n'
                'You have to login with proper credentials', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated

@app.before_request
def initialize_system():
    # Make sure DB is ready
    init_db()

@app.route("/")
@requires_auth
def index():
    """Renders the main dashboard page."""
    return render_template("dashboard.html", active_page="dashboard")

@app.route("/indicators")
@requires_auth
def indicators_page():
    """Renders the correlated indicators page."""
    return render_template("indicators.html", active_page="indicators")

@app.route("/blocklists")
@requires_auth
def blocklists_page():
    """Renders the blocklists integrations page."""
    return render_template("blocklists.html", active_page="blocklists")

@app.route("/reports")
@requires_auth
def reports_page():
    """Renders the reports page."""
    return render_template("reports.html", active_page="reports")

@app.route("/api/metrics", methods=["GET"])
@requires_auth
def get_metrics():
    """Returns JSON summary metrics for dashboard cards."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Unique counts
        cursor.execute("SELECT COUNT(*) FROM correlated_iocs")
        total_iocs = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM correlated_iocs WHERE overall_severity = 'High'")
        high_risk = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM correlated_iocs WHERE overall_severity = 'Medium'")
        medium_risk = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM correlated_iocs WHERE overall_severity = 'Low'")
        low_risk = cursor.fetchone()[0]
        
        conn.close()
        
        # Latest sync details
        latest_sync = get_latest_sync_status()
        feeds_count = 0
        last_sync_time = "Never"
        feed_details = {}
        
        if latest_sync:
            last_sync_time = latest_sync["sync_time"]
            feed_details = latest_sync["details"]
            feeds_count = len(feed_details)
            
        return jsonify({
            "success": True,
            "total_iocs": total_iocs,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "last_sync": last_sync_time,
            "feeds_count": feeds_count,
            "feed_details": feed_details
        })
    except Exception as e:
        logger.error(f"Error fetching metrics API: {e}", exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred while fetching metrics."}), 500

@app.route("/api/indicators", methods=["GET"])
@requires_auth
def get_indicators():
    """
    Returns a paginated list of correlated indicators,
    supporting search filter, severity filter, and sorting.
    """
    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 50))
        search = request.args.get("search", "").strip()
        severity = request.args.get("severity", "all").strip()
        ioc_type = request.args.get("type", "all").strip()
        sort_by = request.args.get("sort_by", "source_count").strip()
        sort_order = request.args.get("sort_order", "desc").strip()
        
        # Validate sorting inputs to prevent injection
        allowed_sorts = ["value", "ioc_type", "overall_severity", "source_count", "last_seen", "positives"]
        if sort_by not in allowed_sorts:
            sort_by = "source_count"
        if sort_order.lower() not in ["asc", "desc"]:
            sort_order = "desc"
            
        offset = (page - 1) * limit
        
        # Build SQL Query
        query_parts = ["SELECT * FROM correlated_iocs WHERE 1=1"]
        count_parts = ["SELECT COUNT(*) FROM correlated_iocs WHERE 1=1"]
        params = []
        
        if search:
            query_parts.append("AND (value LIKE ? OR description LIKE ? OR sources LIKE ?)")
            count_parts.append("AND (value LIKE ? OR description LIKE ? OR sources LIKE ?)")
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
            
        if severity != "all":
            query_parts.append("AND overall_severity = ?")
            count_parts.append("AND overall_severity = ?")
            params.append(severity)
            
        if ioc_type != "all":
            query_parts.append("AND ioc_type = ?")
            count_parts.append("AND ioc_type = ?")
            params.append(ioc_type)
            
        # Add sorting
        query_parts.append(f"ORDER BY {sort_by} {sort_order.upper()}")
        
        # Add pagination
        query_parts.append("LIMIT ? OFFSET ?")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch count
        cursor.execute(" ".join(count_parts), params)
        total_items = cursor.fetchone()[0]
        
        # Fetch items
        cursor.execute(" ".join(query_parts), params + [limit, offset])
        rows = cursor.fetchall()
        conn.close()
        
        indicators = [dict(r) for r in rows]
        total_pages = (total_items + limit - 1) // limit if total_items > 0 else 1
        
        return jsonify({
            "success": True,
            "data": indicators,
            "pagination": {
                "page": page,
                "limit": limit,
                "total_items": total_items,
                "total_pages": total_pages
            }
        })
    except Exception as e:
        logger.error(f"Error fetching indicators API: {e}", exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred while fetching indicators."}), 500

@app.route("/sync", methods=["POST"])
@requires_auth
def trigger_sync():
    """Triggers feed ingestion, normalization, correlation, blocklisting, and reporting."""
    try:
        logger.info("Sync triggered via web API dashboard.")
        
        # 1. Fetch feeds
        sync_status, raw_feed_items = fetch_all_feeds()
        
        # 2. Normalize and validate
        normalized_records = []
        for item in raw_feed_items:
            norm = normalize_ioc(item["value"], item["source"], item["category"])
            if norm:
                normalized_records.append(norm)
                
        # 3. Save raw iocs
        save_raw_iocs(normalized_records)
        
        # Log status in DB
        # Determine if overall sync succeeded or partially failed
        overall_status = "Success"
        for feed, details in sync_status.items():
            if "Failed" in details["status"]:
                overall_status = "Partial Failure"
                
        log_sync_history(overall_status, sync_status)
        
        # 4. Correlate and score severity (perform live VirusTotal enrichment)
        # Note: live VT enrichment is set to True to enrich High/Medium severity.
        # utils.py has rate limits and cache checks.
        correlate_and_score(enrich_high_medium=True)
        
        # 5. Generate blocklists
        blocklist_stats = generate_blocklists()
        
        # 6. Generate report
        report_data = generate_report()
        
        return jsonify({
            "success": True,
            "status": overall_status,
            "feeds": sync_status,
            "blocklist_stats": blocklist_stats,
            "unique_iocs": report_data["metrics"]["total_unique_iocs"]
        })
    except Exception as e:
        logger.error(f"Sync failed during execution: {e}", exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred during synchronization."}), 500

@app.route("/download/<file_type>", methods=["GET"])
@requires_auth
def download_blocklist(file_type):
    """Protected routes to download the generated blocklists."""
    file_map = {
        "ips": (BLOCKLIST_DIR / "ips.txt", "text/plain", "ips.txt"),
        "domains_urls": (BLOCKLIST_DIR / "domains_urls.csv", "text/csv", "domains_urls.csv"),
        "hashes": (BLOCKLIST_DIR / "hashes.csv", "text/csv", "hashes.csv"),
        "combined": (BLOCKLIST_DIR / "combined.json", "application/json", "combined.json")
    }
    
    if file_type not in file_map:
        return jsonify({"success": False, "error": "Invalid blocklist type"}), 400
        
    file_path, mime_type, download_name = file_map[file_type]
    
    if not file_path.exists():
        # Auto trigger blocklist generation if file doesn't exist
        try:
            generate_blocklists()
        except Exception as e:
            logger.error(f"Blocklist file generation failed: {e}", exc_info=True)
            return jsonify({"success": False, "error": "Failed to generate blocklist file."}), 500
            
    if not file_path.exists():
        return jsonify({"success": False, "error": "Blocklist file not found. Please sync feeds first."}), 404
        
    return send_file(
        str(file_path),
        mimetype=mime_type,
        as_attachment=True,
        download_name=download_name
    )

@app.route("/api/report", methods=["GET"])
@requires_auth
def get_report():
    """Returns the JSON summary report data."""
    try:
        generate_report()
    except Exception as e:
        logger.error(f"Failed to generate fresh report: {e}", exc_info=True)
        
    json_path = REPORTS_DIR / "summary_report.json"
            
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify({"success": True, "report": data})
    except Exception as e:
        logger.error(f"Error reading report: {e}", exc_info=True)
        return jsonify({"success": False, "error": "An internal error occurred while reading the report."}), 500

if __name__ == "__main__":
    print(f"Starting ThreatWeave on port {PORT}...")
    app.run(host="0.0.0.0", port=PORT, debug=FLASK_DEBUG)
