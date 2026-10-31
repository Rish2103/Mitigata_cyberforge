"""
core/config.py — Localhost & Test-App Scope Guard (PRD Page 4 Rule 1 Disqualification Lock).

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
from typing import Any, Dict, FrozenSet, Optional
from urllib.parse import urlparse

import httpx


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

# Canary redirect target used for CWE-601 Open Redirect checks (RFC 2606 reserved .invalid TLD)
SAFE_OPEN_REDIRECT_CANARY_URL: str = "https://gordon-redirect-canary.invalid/verify"


def get_allowed_hosts() -> FrozenSet[str]:
    """Return the set of allowed target hostnames, optionally extended via GORDON_ALLOWED_HOSTS."""
    extra_raw = os.getenv("GORDON_ALLOWED_HOSTS", "")
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
        if os.getenv("GORDON_IN_DOCKER", "").lower() in ("1", "true", "yes"):
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
            f"Outbound HTTP request to '{request.url}' blocked by GORDON Target Safety Lock (host='{host}')."
        )


def create_safe_async_client(
    timeout_seconds: float = 6.0,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    transport: Optional[ httpx.AsyncBaseTransport ] = None,
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
        "User-Agent": "GordonCorrelate-LocalVerifier/1.0 (Mitigata-CyberForge-SafeScope)",
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
