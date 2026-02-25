"""
Core constants and enumerations for VulnX_Pro
"""
from enum import Enum

# ==================== VULNERABILITY TYPES ====================
class VulnerabilityType(Enum):
    """Enumeration of supported vulnerability types"""
    SQL_INJECTION = "SQL Injection"
    BLIND_SQL_INJECTION = "Blind SQL Injection"
    REFLECTED_XSS = "Reflected XSS"
    STORED_XSS = "Stored XSS"

# ==================== SQL INJECTION PAYLOADS ====================
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' UNION SELECT NULL--"
]

# ==================== XSS PAYLOADS ====================
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]

# ==================== SQL ERROR PATTERNS ====================
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ORA-"
]

# ==================== HTTP CONFIGURATIONS ====================
DEFAULT_HEADERS = {
    "User-Agent": "VulnX_Pro-Scanner/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# ==================== REGEX PATTERNS ====================
URL_PATTERN = r"^https?://[^\s]+$"
EMAIL_PATTERN = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# ==================== LOGGING MESSAGES ====================
LOG_MESSAGES = {
    "SCAN_START": "Starting scan on target: {}",
    "SCAN_COMPLETE": "Scan completed. Found {} vulnerabilities",
    "CRAWL_START": "Starting web crawl",
    "CRAWL_COMPLETE": "Web crawl completed. Discovered {} URLs",
    "FORM_EXTRACTED": "Extracted {} forms from: {}",
    "PAYLOAD_INJECTED": "Injected payload: {}",
    "VULN_FOUND": "Vulnerability found: {} at {}",
    "ERROR": "Error occurred: {}",
    "TIMEOUT": "Request timeout for: {}",
}

