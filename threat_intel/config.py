import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env
load_dotenv(dotenv_path=BASE_DIR / ".env")

# API Keys (defaults to empty string)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

# Security Settings
REQUIRE_BASIC_AUTH = os.getenv("REQUIRE_BASIC_AUTH", "False").lower() in ("true", "1", "yes")
BASIC_AUTH_USERNAME = os.getenv("BASIC_AUTH_USERNAME", "admin").strip()
BASIC_AUTH_PASSWORD = os.getenv("BASIC_AUTH_PASSWORD", "cybersecurity-portfolio-2026").strip()

# Flask configuration
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "threat-intel-aggregator-session-secret-change-me")
PORT = int(os.getenv("PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")

# File paths
DB_PATH = BASE_DIR / "threat_intel.db"
LOG_FILE = BASE_DIR / "threat_intel.log"
BLOCKLIST_DIR = BASE_DIR / "blocklists"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure directories exist
BLOCKLIST_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# URL feeds
URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
ABUSEIPDB_FEED_URL = "https://api.abuseipdb.com/api/v2/blacklist"
OTX_FEED_URL = "https://otx.alienvault.com/api/v1/indicators/export" # Note: we will query the OTX API endpoints or provide fallbacks

# Rate Limiting configuration
VT_REQUEST_DELAY = 15  # seconds
VT_DAILY_LIMIT = 500
