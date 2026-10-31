"""
CyberForge Core Configuration and Guardrails.
Enforces Target Safety Lock (PRD Page 2 & 4 Rules).
"""

import ipaddress
import re
from typing import List, Set
from urllib.parse import urlparse

# Loopback / local test app scope guard
# Disqualification Guard (PRD Page 4 Rule 1):
# Point the DAST scanner ONLY at the organisers' app running on your own machine.
ALLOWED_HOSTS: Set[str] = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "testserver",
    "host.docker.internal",
}

# Supported CWE IDs in this flagship challenge
SUPPORTED_CWES = [
    "CWE-89",   # SQL Injection
    "CWE-79",   # Cross-Site Scripting (XSS)
    "CWE-78",   # Command Injection
    "CWE-22",   # Path Traversal
    "CWE-601",  # Open Redirect
    "CWE-798",  # Hard-coded Secrets
]

# CWE Human-Readable Names
CWE_NAMES = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-601": "Open Redirect",
    "CWE-798": "Hard-coded Secret",
    # Supplementary runtime-only & code-only CWEs
    "CWE-693": "Protection Mechanism Failure (Missing Security Headers)",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains (CORS)",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-489": "Active Debug Code",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
}

# Base Risk Scores (0-100) before exploitability weighting
CWE_BASE_SEVERITY = {
    "CWE-89": ("Critical", 90.0),
    "CWE-78": ("Critical", 95.0),
    "CWE-79": ("High", 75.0),
    "CWE-22": ("High", 75.0),
    "CWE-601": ("Medium", 50.0),
    "CWE-798": ("High", 70.0),
    "CWE-693": ("Medium", 45.0),
    "CWE-614": ("Medium", 45.0),
    "CWE-1004": ("Medium", 45.0),
    "CWE-942": ("Medium", 55.0),
    "CWE-327": ("Medium", 55.0),
    "CWE-489": ("Medium", 50.0),
    "CWE-200": ("Medium", 50.0),
}


def is_safe_target_url(url: str) -> bool:
    """
    Validate that target URL belongs strictly to localhost/loopback or local Docker network.
    Refuses scanning public internet domains or public IPs to protect against disqualification.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
            return False
        hostname = (parsed.hostname or "").lower().strip(".")
        if not hostname:
            return False
        if hostname in ALLOWED_HOSTS:
            return True
        if hostname.endswith((".localhost", ".local", ".internal", ".docker")):
            return True
        # Check IP address (allow loopback, private RFC1918/Docker bridge, unspecified; block public IPs)
        try:
            ip = ipaddress.ip_address(hostname)
            return bool(ip.is_loopback or ip.is_private or ip.is_unspecified)
        except ValueError:
            pass
        # Allow single-label local Docker Compose service names (e.g. "test-app", "shop", "web")
        # which have no dots and therefore cannot resolve to public internet FQDNs.
        if "." not in hostname and re.match(r"^[a-z0-9][a-z0-9_-]*$", hostname):
            return True
        return False
    except Exception:
        return False


def assert_safe_target(url: str) -> None:
    """
    Raises ValueError if `url` is not a permitted localhost/loopback/local-container target.
    """
    if not is_safe_target_url(url):
        raise ValueError(
            f"Disqualification Guard: Target URL '{url}' is outside allowed local/loopback scope."
        )

