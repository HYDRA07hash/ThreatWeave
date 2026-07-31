import re
import ipaddress
from datetime import datetime
from urllib.parse import urlparse, urlunparse

# Regex patterns for IOC validation
# Hashes
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

# Domain: matches valid domains (e.g. malwaredomain.com, sub.domain.co.uk)
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# URL: matches http, https, ftp followed by domain/IP and paths
URL_REGEX = re.compile(
    r"^(https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE
)

# Email validation
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)

def validate_ip(value):
    """Returns True if value is a valid IPv4 or IPv6 address, False otherwise."""
    try:
        # Strip CIDR subnet suffix if present (e.g., /32, /24)
        ip_part = value.split("/")[0].strip()
        ipaddress.ip_address(ip_part)
        return True
    except ValueError:
        return False

def clean_value(value):
    """Cleans whitespace and basic defanging symbols like [.] or (dot)."""
    if not isinstance(value, str):
        return ""
    val = value.strip()
    # Refang defanged indicators (e.g. hxxp://, 1.1.1[.]1, google(dot)com)
    val = re.sub(r"\[\.\]", ".", val)
    val = re.sub(r"\(\.\)", ".", val)
    val = re.sub(r"\(dot\)", ".", val, flags=re.IGNORECASE)
    val = re.sub(r"\[dot\]", ".", val, flags=re.IGNORECASE)
    val = re.sub(r"^hxxps?://", "http://", val, flags=re.IGNORECASE) # Default defanged HTTP
    val = re.sub(r"^hxxp", "http", val, flags=re.IGNORECASE)
    return val

def classify_ioc(value):
    """
    Classifies an IOC string. Returns a tuple (ioc_type, cleaned_value) if valid,
    or (None, None) if the IOC is malformed.
    """
    cleaned = clean_value(value)
    if not cleaned:
        return None, None
        
    # Check IP
    # Strip CIDR suffix for IP classification
    ip_candidate = cleaned
    if "/" in cleaned:
        parts = cleaned.split("/")
        if len(parts) == 2 and parts[1].isdigit():
            ip_candidate = parts[0]
            
    if validate_ip(ip_candidate):
        return "ip", ip_candidate
        
    # Check hashes (MD5, SHA1, SHA256)
    if MD5_REGEX.match(cleaned):
        return "hash_md5", cleaned.lower()
    if SHA1_REGEX.match(cleaned):
        return "hash_sha1", cleaned.lower()
    if SHA256_REGEX.match(cleaned):
        return "hash_sha256", cleaned.lower()
        
    # Check URL (URLs usually start with http/https/ftp)
    if URL_REGEX.match(cleaned):
        # URL normalization: lowercase scheme and netloc, strip trailing slash, drop fragment
        try:
            parsed = urlparse(cleaned)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path
            if path:
                if path.endswith('/') and path != '/':
                    path = path.rstrip('/')
            else:
                path = '/'
            normalized_url = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
            return "url", normalized_url
        except Exception:
            return "url", cleaned
        
    # Check Email
    if EMAIL_REGEX.match(cleaned):
        return "email", cleaned.lower()
        
    # Check Domain (Domains must match DOMAIN_REGEX and NOT be a URL/email/IP)
    domain_candidate = cleaned.lower()
    if domain_candidate.startswith("www."):
        domain_candidate = domain_candidate[4:]
        
    if DOMAIN_REGEX.match(domain_candidate):
        return "domain", domain_candidate
        
    return None, None

def normalize_ioc(raw_value, source, category=None):
    """
    Validates and normalizes an IOC into a standard internal dictionary schema.
    Returns:
        dict: Normalized IOC data with keys: value, ioc_type, source, category, first_seen, raw_data.
        None: If the IOC is invalid or malformed.
    """
    ioc_type, cleaned_val = classify_ioc(raw_value)
    if not ioc_type:
        return None
        
    # Standardize category defaults if not specified
    if not category:
        category = "malware"
    category = category.lower().strip()
    
    return {
        "value": cleaned_val,
        "ioc_type": ioc_type,
        "source": source.strip(),
        "category": category,
        "first_seen": datetime.utcnow().isoformat() + "Z",
        "raw_data": f"Source: {source} | Category: {category} | Parsed: {datetime.utcnow().isoformat()}Z"
    }
