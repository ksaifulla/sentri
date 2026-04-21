"""Centralized configuration constants for Sentri."""

from pathlib import Path
from sentri.models import Severity

# OSV API configuration
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_API_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# HTTP client configuration
DEFAULT_TIMEOUT = 10.0  # seconds
DEFAULT_USER_AGENT = "Sentri/0.1.0 Security Scanner"

# Rate limit testing configuration
DEFAULT_BURST_COUNT = 20  # Number of rapid requests to send
RATE_LIMIT_DELAY = 0.05  # Delay between requests in seconds (50ms)
RATE_LIMIT_RESPONSE_TIME_THRESHOLD = 2.0  # seconds 

# Security headers to check
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "required": True,
        "valid_values": None,
        "severity_missing": Severity.HIGH,
        "severity_misconfigured": Severity.MEDIUM,
    },
    "Strict-Transport-Security": {
        "required": True,
        "valid_values": "max-age",
        "min_max_age": 31536000,
        "severity_missing": Severity.HIGH,
        "severity_misconfigured": Severity.MEDIUM,
    },
    "X-Frame-Options": {
        "required": True,
        "valid_values": ["DENY", "SAMEORIGIN"],
        "severity_missing": Severity.HIGH,
        "severity_misconfigured": Severity.MEDIUM,
    },
    "X-Content-Type-Options": {
        "required": True,
        "valid_values": ["nosniff"],
        "severity_missing": Severity.MEDIUM,
        "severity_misconfigured": Severity.MEDIUM,
    },
    "Referrer-Policy": {
        "required": False,
        "valid_values": [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ],
        "severity_missing": Severity.LOW,
        "severity_misconfigured": Severity.MEDIUM,
    },
    "Permissions-Policy": {
        "required": False,
        "valid_values": None,
        "severity_missing": Severity.LOW,
        "severity_misconfigured": Severity.MEDIUM,
    },
}

# CORS testing configuration
CORS_SPOOFED_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "https://malicious-site.com",
    "null",
    "https://sentri-test.attacker.com",
]

# CORS header values that indicate issues
CORS_WILDCARD = "*"

# JWT configuration
JWT_ALGORITHMS_INSECURE = ["none", "None", "NONE"]
JWT_HMAC_ALGORITHMS = ["HS256", "HS384", "HS512"]

# Wordlist configuration
DEFAULT_WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "common-secrets.txt"


def get_wordlist_path(custom_path: str | None = None) -> Path:
    """Get the path to the secrets wordlist."""
    if custom_path:
        return Path(custom_path)
    return DEFAULT_WORDLIST_PATH