import time
import logging
import sqlite3
import requests
from threat_intel.config import LOG_FILE, DB_PATH, VIRUSTOTAL_API_KEY, VT_REQUEST_DELAY

# Setup Logging
logger = logging.getLogger("ThreatIntelAggregator")
logger.setLevel(logging.INFO)

# Create file handler and console handler
if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    console_handler = logging.StreamHandler()
    
    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def requests_with_retry(url, headers=None, params=None, data=None, method="GET", timeout=15):
    """
    Executes an HTTP request with exponential backoff on connection errors or HTTP 429 status codes.
    Retries up to 3 times (delays: 2s, 4s, 8s) before logging the failure and returning None.
    """
    max_retries = 3
    backoff = 2  # initial delay in seconds
    
    for attempt in range(1, max_retries + 1):
        try:
            logger.debug(f"HTTP {method} request to {url} (Attempt {attempt}/{max_retries})")
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, params=params, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, params=params, json=data, timeout=timeout)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
                
            # If rate limited, trigger retry
            if response.status_code == 429:
                logger.warning(f"Rate limited (429) by {url}. Retrying in {backoff}s...")
                time.sleep(backoff)
                backoff *= 2
                continue
                
            # If server error, retry
            if 500 <= response.status_code < 600:
                logger.warning(f"Server error ({response.status_code}) from {url}. Retrying in {backoff}s...")
                time.sleep(backoff)
                backoff *= 2
                continue
                
            # Raise exception for bad codes (4xx except 429)
            response.raise_for_status()
            logger.debug(f"HTTP request to {url} succeeded.")
            return response
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request attempt {attempt} to {url} failed: {e}")
            if attempt < max_retries:
                logger.info(f"Retrying in {backoff}s...")
                time.sleep(backoff)
                backoff *= 2
            else:
                logger.error(f"Failed to fetch {url} after {max_retries} attempts.")
                
    return None

class VirusTotalClient:
    """
    VirusTotal API v3 Client with rate limiting (15s delay between requests)
    and SQLite caching of scan results.
    """
    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.last_request_time = 0
        
    def _wait_for_rate_limit(self):
        """Enforces a 15-second delay between VirusTotal API queries to avoid 429s."""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < VT_REQUEST_DELAY:
            sleep_time = VT_REQUEST_DELAY - elapsed
            logger.info(f"Rate limiting VT request: sleeping for {sleep_time:.2f} seconds...")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def get_cached_report(self, ioc_value):
        """Checks if a VirusTotal report for this IOC exists in the SQLite cache."""
        try:
            conn = sqlite3.connect(str(DB_PATH))
            cursor = conn.cursor()
            # Ensure table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vt_cache (
                    ioc_value TEXT PRIMARY KEY,
                    positives INTEGER,
                    total INTEGER,
                    permalink TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            
            cursor.execute("SELECT positives, total, permalink FROM vt_cache WHERE ioc_value = ?", (ioc_value,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                logger.info(f"VT Cache Hit for {ioc_value}: {row[0]}/{row[1]}")
                return {"positives": row[0], "total": row[1], "permalink": row[2], "source": "cache"}
        except Exception as e:
            logger.error(f"Error checking VirusTotal cache: {e}")
            
        return None

    def save_to_cache(self, ioc_value, positives, total, permalink):
        """Saves a VirusTotal lookup result to the local SQLite cache."""
        try:
            conn = sqlite3.connect(str(DB_PATH))
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO vt_cache (ioc_value, positives, total, permalink, last_updated)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (ioc_value, positives, total, permalink))
            conn.commit()
            conn.close()
            logger.debug(f"Saved VT result to cache for {ioc_value}")
        except Exception as e:
            logger.error(f"Error saving VirusTotal cache: {e}")

    def query_ioc(self, ioc_value, ioc_type):
        """
        Enriches an IOC by checking the VT cache first, then the live API if needed.
        Supports ip, domain, url, hash.
        """
        # 1. Check local cache
        cached = self.get_cached_report(ioc_value)
        if cached:
            return cached
            
        # 2. Check if API key is configured
        if not self.api_key:
            logger.debug(f"VirusTotal API key not configured, skipping live enrichment for {ioc_value}")
            return None
            
        # 3. Map ioc_type to VT API v3 endpoint
        endpoint = None
        if ioc_type == "ip":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        elif ioc_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
        elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256", "hash"):
            endpoint = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        elif ioc_type == "url":
            # For URLs, we need to hash the URL in SHA-256 or base64 (without padding) according to VT v3 docs
            # Base64 without padding of the URL
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
        if not endpoint:
            logger.warning(f"VT Enrichment not supported for type '{ioc_type}' (value: {ioc_value})")
            return None
            
        # Enforce rate limiting delay
        self._wait_for_rate_limit()
        
        headers = {"x-apikey": self.api_key}
        logger.info(f"Querying VirusTotal API for {ioc_value} ({ioc_type})...")
        response = requests_with_retry(endpoint, headers=headers, method="GET")
        
        if not response or response.status_code != 200:
            logger.warning(f"Failed to query VirusTotal for {ioc_value}")
            return None
            
        try:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            # Sum up detections
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            
            # Permalink
            permalink = data.get("data", {}).get("links", {}).get("self", "")
            # VT self links are sometimes API links; replace with GUI link if possible
            # File URL: https://www.virustotal.com/gui/file/<hash>
            # IP URL: https://www.virustotal.com/gui/ip-address/<ip>
            # Domain URL: https://www.virustotal.com/gui/domain/<domain>
            # URL URL: https://www.virustotal.com/gui/url/<base64_id>
            gui_link = permalink
            if ioc_type == "ip":
                gui_link = f"https://www.virustotal.com/gui/ip-address/{ioc_value}"
            elif ioc_type == "domain":
                gui_link = f"https://www.virustotal.com/gui/domain/{ioc_value}"
            elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256", "hash"):
                gui_link = f"https://www.virustotal.com/gui/file/{ioc_value}"
            elif ioc_type == "url":
                import base64
                url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
                gui_link = f"https://www.virustotal.com/gui/url/{url_id}"
            
            self.save_to_cache(ioc_value, positives, total, gui_link)
            return {"positives": positives, "total": total, "permalink": gui_link, "source": "virustotal"}
            
        except Exception as e:
            logger.error(f"Error parsing VirusTotal response for {ioc_value}: {e}")
            return None
