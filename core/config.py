"""
core/config.py — Localhost & Test-App Scope Guard and CWE Configuration (PRD Page 2 & 4 Rules).

Verbatim PRD Rule:
  "Scan only the test app. Point the DAST scanner only at the organisers' app running
   on your own machine. Scanning any other site or system is not allowed and leads to
   disqualification."

Enforces:
  1. Strict hostname/IP allowlist: only `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`,
     and approved local Docker Compose test-app container hostnames (or private Docker
     bridge IPs when explicitly enabled for local container-to-container networking).
  2. Strict `follow_redirects=False` on all `httpx.AsyncClient` instances so an Open
     Redirect (`CWE-601`) test never follows a `Location` header out to the internet.
  3. An `httpx` request event hook (`_enforce_request_scope_hook`) that inspects every
     outbound HTTP request URL right before transmission and aborts immediately if the
     host is not on the local allowlist.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore


class TargetScopeViolationError(PermissionError):
    """Raised when DAST or Auto-Verify is pointed at a non-local / external target."""


# Explicitly allowed local & Docker Compose service hostnames for the test web shop
DEFAULT_ALLOWED_HOSTS: FrozenSet[str] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "[::1]",
        "0.0.0.0",
        "host.docker.internal",
        "testserver",  # FastAPI / Starlette / httpx ASGI in-process test client
        # Local Docker Compose service names for the kickoff & unseen test apps
        "test-app",
        "test_app",
        "testapp",
        "web-shop",
        "web_shop",
        "webshop",
        "mock-shop",
        "mock_shop",
        "shop-app",
        "shop",
        "app",
        "web",
        "target-app",
        "target",
        "unseen-app",
        "unseen_app",
        "second-app",
    }
)

ALLOWED_HOSTS: Set[str] = set(DEFAULT_ALLOWED_HOSTS)

# Canary redirect target used for CWE-601 Open Redirect checks (RFC 2606 reserved .invalid TLD)
SAFE_OPEN_REDIRECT_CANARY_URL: str = "https://cyberforge-redirect-canary.invalid/verify"

# Supported CWE IDs in this flagship challenge
SUPPORTED_CWES: List[str] = [
    "CWE-89",   # SQL Injection
    "CWE-79",   # Cross-Site Scripting (XSS)
    "CWE-78",   # Command Injection
    "CWE-22",   # Path Traversal
    "CWE-601",  # Open Redirect
    "CWE-798",  # Hard-coded Secrets
]

# CWE Human-Readable Names
CWE_NAMES: Dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-601": "Open Redirect",
    "CWE-798": "Hard-coded Secret",
    # Supplementary runtime-only & code-only CWEs
    "CWE-693": "Protection Mechanism Failure (Missing Security Headers)",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains (CORS)",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-489": "Active Debug Code",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-16": "Security Misconfiguration",
}

# Base Risk Scores (0-100) before exploitability weighting
CWE_BASE_SEVERITY: Dict[str, Tuple[str, float]] = {
    "CWE-89": ("Critical", 90.0),
    "CWE-78": ("Critical", 95.0),
    "CWE-79": ("High", 75.0),
    "CWE-22": ("High", 75.0),
    "CWE-601": ("Medium", 50.0),
    "CWE-798": ("High", 70.0),
    "CWE-693": ("Medium", 45.0),
    "CWE-1021": ("Medium", 45.0),
    "CWE-614": ("Medium", 45.0),
    "CWE-1004": ("Medium", 45.0),
    "CWE-942": ("Medium", 55.0),
    "CWE-327": ("Medium", 55.0),
    "CWE-489": ("Medium", 50.0),
    "CWE-200": ("Medium", 50.0),
    "CWE-16": ("Medium", 45.0),
}


def get_allowed_hosts() -> FrozenSet[str]:
    """Return the set of allowed target hostnames, optionally extended via CYBERFORGE_ALLOWED_HOSTS."""
    extra_raw = os.getenv("CYBERFORGE_ALLOWED_HOSTS", "")
    if not extra_raw.strip():
        return DEFAULT_ALLOWED_HOSTS
    extra = {h.strip().lower() for h in extra_raw.split(",") if h.strip()}
    return DEFAULT_ALLOWED_HOSTS | extra


def is_local_or_docker_host(hostname: Optional[str]) -> bool:
    """
    Verify that `hostname` is strictly a loopback address or an approved local
    Docker Compose container hostname (never an external domain or public IP).
    """
    if not hostname:
        return False

    clean_host = hostname.strip().lower().strip("[]")
    if clean_host in get_allowed_hosts():
        return True

    # Check if hostname is a literal IP address
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if ip_obj.is_loopback:
            return True
        # Allow RFC1918 172.16.0.0/12 Docker bridge networks only when running inside Docker
        if os.getenv("CYBERFORGE_IN_DOCKER", "").lower() in ("1", "true", "yes"):
            if ip_obj in ipaddress.ip_network("172.16.0.0/12"):
                return True
        return False
    except ValueError:
        pass

    # Reject any hostname containing a public TLD dot unless it ends with `.local` or `.internal`
    if "." in clean_host:
        if clean_host.endswith(".docker.internal") or clean_host.endswith(".local"):
            return True
        return False

    return False


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
        if is_local_or_docker_host(hostname):
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


def validate_target_url(target_url: str) -> str:
    """
    Validate that `target_url` uses http/https and points strictly to an approved
    local host. Returns the normalized base URL (without trailing slash) or raises
    `TargetScopeViolationError`.
    """
    if not target_url or not isinstance(target_url, str):
        raise TargetScopeViolationError("Target URL must be a non-empty string.")

    cleaned = target_url.strip()
    parsed = urlparse(cleaned)

    if parsed.scheme not in ("http", "https"):
        raise TargetScopeViolationError(
            f"Disallowed URL scheme '{parsed.scheme}' in '{target_url}'. Only http:// or https:// on localhost is permitted."
        )

    hostname = parsed.hostname
    if not is_local_or_docker_host(hostname):
        raise TargetScopeViolationError(
            f"SAFETY LOCK BLOCKED TARGET '{target_url}' (host='{hostname}'). "
            "Per PRD Page 4 Rule 1, DAST scanning is strictly locked to localhost / 127.0.0.1 / local test-app containers."
        )

    # Reconstruct clean normalized URL
    return cleaned.rstrip("/") if parsed.path in ("", "/") and not parsed.query else cleaned


async def _enforce_request_scope_hook(request: httpx.Request) -> None:
    """
    httpx async event hook executed before every HTTP request is sent over the wire.
    Guarantees no request can ever escape the localhost/test-app boundary.
    """
    host = request.url.host
    if not is_local_or_docker_host(host):
        raise TargetScopeViolationError(
            f"Outbound HTTP request to '{request.url}' blocked by CYBERFORGE Target Safety Lock (host='{host}')."
        )


def create_safe_async_client(
    timeout_seconds: float = 6.0,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    **extra_kwargs: Any,
) -> httpx.AsyncClient:
    """
    Factory for creating an `httpx.AsyncClient` with non-negotiable safety locks:
      1. `follow_redirects=False` (ALWAYS enforced; ignores any caller attempt to set True)
      2. Request event hook `_enforce_request_scope_hook` verifying every request URL
      3. Fast connection/read timeouts for `< 35s` full-scan execution
    """
    # Force follow_redirects=False regardless of extra_kwargs
    extra_kwargs.pop("follow_redirects", None)
    default_headers = {
        "User-Agent": "CyberForgeCorrelate-LocalVerifier/1.0 (Mitigata-CyberForge-SafeScope)",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }
    if headers:
        default_headers.update(headers)

    client_kwargs: Dict[str, Any] = {
        "follow_redirects": False,
        "timeout": httpx.Timeout(timeout_seconds, connect=3.0),
        "headers": default_headers,
        "cookies": cookies,
        "event_hooks": {"request": [_enforce_request_scope_hook]},
        **extra_kwargs,
    }
    if transport is not None:
        client_kwargs["transport"] = transport

    return httpx.AsyncClient(**client_kwargs)
