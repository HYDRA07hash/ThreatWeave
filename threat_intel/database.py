import sqlite3
import json
from threat_intel.config import DB_PATH
from threat_intel.utils import logger

def get_db_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if tables do not exist."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Raw IOCs Table (Normalized parsed entries)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT,
                first_seen TIMESTAMP NOT NULL,
                raw_data TEXT,
                UNIQUE(value, source) ON CONFLICT REPLACE
            )
        """)
        
        # Correlated IOCs Table (Aggregated unique IOCs with computed metrics)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS correlated_iocs (
                value TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                overall_severity TEXT NOT NULL,
                source_count INTEGER NOT NULL,
                sources TEXT NOT NULL, -- Comma-separated list of sources
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                description TEXT,
                positives INTEGER DEFAULT -1, -- VT positive detections (-1 means no VT scan done)
                total INTEGER DEFAULT -1,     -- VT total scan count
                vt_link TEXT                  -- Link to VirusTotal report
            )
        """)
        
        # VirusTotal Cache Table (VT reports)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                ioc_value TEXT PRIMARY KEY,
                positives INTEGER NOT NULL,
                total INTEGER NOT NULL,
                permalink TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Sync History Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                details TEXT NOT NULL
            )
        """)
        
        # Indexes for search optimization
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_raw_value ON raw_iocs(value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_corr_severity ON correlated_iocs(overall_severity)")
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

def save_raw_iocs(normalized_records):
    """
    Inserts a list of normalized IOCs into the raw_iocs table.
    Uses parameterized queries to prevent SQL Injection.
    """
    if not normalized_records:
        return
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            INSERT INTO raw_iocs (value, ioc_type, source, category, first_seen, raw_data)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(value, source) DO UPDATE SET
                category = excluded.category,
                raw_data = excluded.raw_data
        """
        
        # Convert records to tuple format for executemany
        data_tuples = [
            (
                r["value"],
                r["ioc_type"],
                r["source"],
                r.get("category", "malware"),
                r["first_seen"],
                r.get("raw_data", "")
            )
            for r in normalized_records
        ]
        
        cursor.executemany(query, data_tuples)
        conn.commit()
        conn.close()
        logger.info(f"Successfully saved {len(normalized_records)} raw IOCs to database.")
    except Exception as e:
        logger.error(f"Error saving raw IOCs: {e}")

def get_all_raw_iocs():
    """Retrieves all raw IOCs from the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM raw_iocs")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error fetching raw IOCs: {e}")
        return []

def save_correlated_iocs(correlated_list):
    """
    Saves or updates correlated unique IOCs.
    Each item in correlated_list must be a dictionary matching correlated_iocs schema.
    """
    if not correlated_list:
        return
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            INSERT INTO correlated_iocs (
                value, ioc_type, overall_severity, source_count, sources, 
                first_seen, last_seen, description, positives, total, vt_link
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(value) DO UPDATE SET
                overall_severity = excluded.overall_severity,
                source_count = excluded.source_count,
                sources = excluded.sources,
                last_seen = excluded.last_seen,
                description = excluded.description,
                positives = CASE WHEN excluded.positives != -1 THEN excluded.positives ELSE positives END,
                total = CASE WHEN excluded.total != -1 THEN excluded.total ELSE total END,
                vt_link = CASE WHEN excluded.vt_link IS NOT NULL THEN excluded.vt_link ELSE vt_link END
        """
        
        data_tuples = [
            (
                c["value"],
                c["ioc_type"],
                c["overall_severity"],
                c["source_count"],
                c["sources"],
                c["first_seen"],
                c["last_seen"],
                c.get("description", ""),
                c.get("positives", -1),
                c.get("total", -1),
                c.get("vt_link", None)
            )
            for c in correlated_list
        ]
        
        cursor.executemany(query, data_tuples)
        conn.commit()
        conn.close()
        logger.info(f"Successfully saved {len(correlated_list)} correlated IOCs.")
    except Exception as e:
        logger.error(f"Error saving correlated IOCs: {e}")

def get_correlated_iocs(severity_filter=None):
    """
    Retrieves correlated IOCs. Optionally filters by overall_severity (High/Medium/Low).
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if severity_filter:
            cursor.execute(
                "SELECT * FROM correlated_iocs WHERE overall_severity = ? ORDER BY source_count DESC, value ASC",
                (severity_filter,)
            )
        else:
            cursor.execute("SELECT * FROM correlated_iocs ORDER BY source_count DESC, value ASC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Error fetching correlated IOCs: {e}")
        return []

def log_sync_history(status, details_dict):
    """Logs sync history with timestamp and JSON serialized detail logs."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sync_history (status, details) VALUES (?, ?)",
            (status, json.dumps(details_dict))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error logging sync history: {e}")

def get_latest_sync_status():
    """Retrieves the details of the most recent synchronization run."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sync_history ORDER BY sync_time DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        if row:
            res = dict(row)
            res["details"] = json.loads(res["details"])
            return res
    except Exception as e:
        logger.error(f"Error reading latest sync status: {e}")
    return None
