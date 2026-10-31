"""
CyberForge Core Configuration and Guardrails.
Enforces Target Safety Lock (PRD Page 2 & 4 Rules).
"""

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
    Validate that target URL belongs strictly to localhost/loopback or docker network.
    Refuses scanning public internet domains to protect against disqualification.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        if hostname in ALLOWED_HOSTS:
            return True
        # Allow internal docker network hostnames or private ips if needed
        if hostname.startswith("127.") or hostname.endswith(".localhost"):
            return True
        return False
    except Exception:
        return False
