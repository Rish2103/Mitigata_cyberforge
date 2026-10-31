"""
api/main.py — FastAPI Control Plane for CYBERFORGE CORRELATE (FR-8, FR-9, FR-10, B-3, B-4, B-5).

Endpoints:
  - GET  /health                   -> Liveness & target-safety-lock status
  - POST /scans                    -> Trigger full SAST + DAST + Correlation scan (FR-10)
  - GET  /scans                    -> List executed scans & summary counters
  - GET  /issues                   -> Prioritised issue list: Confirmed first, then by risk_score (FR-9)
  - GET  /issues/{issue_id}        -> Unified issue detail view (FR-8)
  - GET  /routes                   -> Discovered AST Route Map (FR-4)
  - GET  /decoys                   -> Safe decoys suppressed (B-2)
  - GET  /scans/compare            -> Differential scan comparison: NEW, FIXED, STILL-OPEN (B-5)
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import re
import socket
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from api.db import DatabaseStore
from api.sarif_exporter import build_sarif_report, evaluate_ci_gate
from core.config import TargetScopeViolationError, get_allowed_hosts, validate_target_url
from core.schemas import (
    CanonicalFinding,
    CorrelatedIssue,
    RouteEntry,
    SCAFinding,
    ScanRequest,
    ScanSummary,
    ScopeReductionReport,
)
from engine.dast_scanner import DASTScanner, run_dast_scan

app = FastAPI(
    title="CYBERFORGE CORRELATE - SAST & DAST Correlation Engine",
    description=(
        "Enterprise AppSec Correlation Engine (PROBLEM 06): "
        "Deterministic AST Route-to-Sink Mapper + 2-Phase Scope-Locked DAST + "
        "Zero-Wrong-Link Correlator + Idempotent SQLite Store."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_default_store: Optional[DatabaseStore] = None

FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36" fill="none">'
    '<rect width="36" height="36" rx="6" fill="#111625"/>'
    '<path d="M18 5.5L28.5 10.2V18.4C28.5 24.9 24.0 29.7 18 31.5C12.0 29.7 7.5 24.9 7.5 18.4V10.2L18 5.5Z" '
    'fill="#1A2138" stroke="#3D52D5" stroke-width="1.8"/>'
    '<path d="M13.5 14.5L18 19L22.5 14.5M18 19V25" stroke="#EAEEFF" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>'
    '<circle cx="13.5" cy="14.5" r="2.1" fill="#3D52D5" stroke="#FFFFFF" stroke-width="1.1"/>'
    '<circle cx="22.5" cy="14.5" r="2.1" fill="#3D52D5" stroke="#FFFFFF" stroke-width="1.1"/>'
    '<circle cx="18" cy="25" r="2.3" fill="#10B981" stroke="#FFFFFF" stroke-width="1.1"/>'
    '</svg>'
)


class _AsyncWSGITransport(httpx.AsyncBaseTransport):
    """Async adapter around httpx.WSGITransport for in-process Flask/WSGI target verification."""

    def __init__(self, wsgi_app: Any) -> None:
        self._sync_transport = httpx.WSGITransport(app=wsgi_app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        sync_resp = await asyncio.to_thread(self._sync_transport.handle_request, request)
        body = sync_resp.read()
        return httpx.Response(
            status_code=sync_resp.status_code,
            headers=sync_resp.headers,
            content=body,
            request=request,
        )


def _is_tcp_port_reachable(url: str, timeout: float = 0.15) -> bool:
    """Return True if a live TCP server is listening at the URL's host:port."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _resolve_reachable_target_url(url: str) -> str:
    """
    If `url` points to `127.0.0.1:5000` or `127.0.0.1:5001` from the browser UI while
    running inside Docker Compose, transparently route to the sibling container hostname
    (`http://web-shop:5000` or `http://unseen-app:5001`) when reachable on `cyberforge-net`.
    """
    if _is_tcp_port_reachable(url):
        return url
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        if host in ("127.0.0.1", "localhost", "0.0.0.0"):
            docker_Fallbacks = {
                5000: "http://web-shop:5000",
                5001: "http://unseen-app:5001",
            }
            candidate = docker_Fallbacks.get(port)
            if candidate and _is_tcp_port_reachable(candidate):
                return candidate
    except Exception:
        pass
    return url


def _load_local_wsgi_transport(source_dir: Optional[str]) -> Optional[_AsyncWSGITransport]:
    """
    When `run_live_dast=True` is requested against a local Flask app (such as `tests/mock_shop_app`)
    and no standalone server process is listening on the target port, load the WSGI `app`
    in-process so live DAST probes execute against the real route handlers out of the box.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidate_dirs: List[str] = []
    if source_dir:
        candidate_dirs.append(os.path.abspath(source_dir))
    default_mock_dir = os.path.join(repo_root, "tests", "mock_shop_app")
    if os.path.isdir(default_mock_dir) and default_mock_dir not in candidate_dirs:
        candidate_dirs.append(default_mock_dir)

    for folder in candidate_dirs:
        app_py = os.path.join(folder, "app.py")
        if not os.path.isfile(app_py):
            continue
        try:
            if folder in sys.path:
                sys.path.remove(folder)
            sys.path.insert(0, folder)
            for mod_name in list(sys.modules.keys()):
                if mod_name in ("routes", "services", "models") or mod_name.startswith(
                    ("routes.", "services.", "models.")
                ):
                    sys.modules.pop(mod_name, None)
            spec = importlib.util.spec_from_file_location("cyberforge_local_target_app", app_py)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                wsgi_app = getattr(mod, "app", None)
                if wsgi_app is not None:
                    return _AsyncWSGITransport(wsgi_app)
        except Exception:
            continue
    return None


def get_store() -> DatabaseStore:
    """Return singleton `DatabaseStore` instance (or custom path via `CYBERFORGE_DB_PATH` / `GORDON_DB_PATH`)."""
    global _default_store
    current_path = os.getenv("CYBERFORGE_DB_PATH", os.getenv("GORDON_DB_PATH"))
    if _default_store is None or (current_path and _default_store.db_path != current_path):
        _default_store = DatabaseStore(db_path=current_path)
    return _default_store


# ---------------------------------------------------------------------------
# Built-in Plain-English Remediation Generator (Bonus B-4) & Fallback Correlator
# ---------------------------------------------------------------------------

DEFAULT_FIX_SUGGESTIONS: Dict[str, str] = {
    "CWE-89": (
        "Use parameterized queries / prepared statements instead of string concatenation or f-strings. "
        "Example: `cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))`."
    ),
    "CWE-79": (
        "Contextually HTML-encode all user-supplied input before rendering (`html.escape(val)` or Jinja2 autoescaping) "
        "and deploy a strict `Content-Security-Policy` header."
    ),
    "CWE-78": (
        "Avoid `os.system()` and `subprocess.run(..., shell=True)`. Pass arguments as a list "
        "`subprocess.run(['ping', '-c', '1', host], shell=False)` and validate against an allowlist."
    ),
    "CWE-22": (
        "Resolve the canonical path via `os.path.realpath()` and verify it starts with the intended base directory "
        "before opening or sending files."
    ),
    "CWE-601": (
        "Validate redirect targets against a strict relative-path or host allowlist (`urlparse(next_url).netloc == ''`) "
        "before issuing a `302 Redirect`."
    ),
    "CWE-798": (
        "Remove hard-coded API keys/passwords from source code and load them from environment variables or a secrets manager."
    ),
    "CWE-693": (
        "Configure security response headers in middleware (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`)."
    ),
    "CWE-1021": (
        "Add `X-Frame-Options: DENY` (or `SAMEORIGIN`) and `Content-Security-Policy: frame-ancestors 'self'`."
    ),
    "CWE-614": (
        "Set `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict`) on all session cookies."
    ),
    "CWE-942": (
        "Replace wildcard `Access-Control-Allow-Origin: *` with an explicit origin allowlist."
    ),
}


def _sink_param_affinity(sf: CanonicalFinding, dast_param: Optional[str]) -> int:
    """
    Score how strongly a SAST finding `sf` matches a DAST parameter `dast_param`:
      - +2: explicit `sf.param` matches `dast_param`
      - +1: `dast_param` appears as an identifier token in `sf.snippet`
      -  0: no explicit parameter or snippet token match
    """
    if not dast_param:
        return 0
    if sf.param and sf.param.lower() == dast_param.lower():
        return 2
    if sf.snippet and re.search(rf"\b{re.escape(dast_param)}\b", sf.snippet, re.IGNORECASE):
        return 1
    return 0


def fallback_correlate_findings(
    routes: List[RouteEntry],
    sast_findings: List[CanonicalFinding],
    dast_findings: List[CanonicalFinding],
    route_mapper: Optional[Any] = None,
) -> List[CorrelatedIssue]:
    """
    Deterministic correlation entry point that delegates to `engine.correlator.correlate_findings`
    when available, with an internal fallback implementation.
    """
    try:
        from engine import correlator  # type: ignore

        if hasattr(correlator, "correlate_findings"):
            issues = correlator.correlate_findings(
                routes=routes,
                sast_findings=sast_findings,
                dast_findings=dast_findings,
                route_mapper=route_mapper,
            )
            for issue in issues:
                if not issue.fix_suggestion:
                    issue.fix_suggestion = DEFAULT_FIX_SUGGESTIONS.get(
                        issue.cwe, "Apply input validation and safe API patterns."
                    )
            return issues
    except ImportError:
        pass

    active_sast = [f for f in sast_findings if not f.is_protected_decoy]
    matched_sast_fps: set[str] = set()
    matched_dast_fps: set[str] = set()
    bound_param_by_sink: Dict[Tuple[str, Optional[str], Optional[int]], str] = {}
    issues_by_fp: Dict[str, CorrelatedIssue] = {}

    for df in dast_findings:
        candidate_pairs: List[Tuple[int, CanonicalFinding, RouteEntry]] = []
        for sf in active_sast:
            if df.cwe != sf.cwe:
                continue

            # Hard Veto 1: If both specify a parameter name and they differ, never join!
            if df.param and sf.param and df.param.lower() != sf.param.lower():
                continue

            # Hard Veto 2: Never bind the same (cwe, file, line) sink to two different parameter names
            sink_key = (sf.cwe, sf.file, sf.line)
            existing_bound_param = bound_param_by_sink.get(sink_key)
            if existing_bound_param and df.param and existing_bound_param != df.param.lower():
                continue

            # Find a route entry that connects DAST URL + method to SAST file:line
            connecting_route: Optional[RouteEntry] = None
            for r in routes:
                if r.matches_url(df.url or df.canonical_path or "/", df.method) and r.covers_location(sf.file, sf.line):
                    connecting_route = r
                    break

            if connecting_route is not None:
                affinity = _sink_param_affinity(sf, df.param)
                candidate_pairs.append((affinity, sf, connecting_route))

        if not candidate_pairs:
            continue

        max_affinity = max(score for score, _, _ in candidate_pairs)
        best_choices = [
            (score, sf, r) for score, sf, r in candidate_pairs if score == max_affinity
        ]
        _, best_sf, connecting_route = best_choices[0]

        sink_key = (best_sf.cwe, best_sf.file, best_sf.line)
        effective_param = df.param or best_sf.param
        if effective_param:
            bound_param_by_sink[sink_key] = effective_param.lower()

        peer_sast_findings: List[CanonicalFinding] = []
        for sf_peer in active_sast:
            if (sf_peer.cwe, sf_peer.file, sf_peer.line) == sink_key:
                if df.param and sf_peer.param and df.param.lower() != sf_peer.param.lower():
                    continue
                peer_sast_findings.append(sf_peer)
                matched_sast_fps.add(sf_peer.fingerprint)

        matched_dast_fps.add(df.fingerprint)
        route_desc = (
            f"{connecting_route.method} {connecting_route.path_pattern} -> "
            f"{connecting_route.func_name}(), {connecting_route.file}:{connecting_route.start_line}-{connecting_route.end_line}"
        )
        param_desc = effective_param or "n/a"
        link_reason = (
            f"Same {df.cwe} + Route `{connecting_route.method} {connecting_route.canonical_path}` "
            f"handled by `{connecting_route.func_name}()` ({connecting_route.file}:{connecting_route.start_line}-{connecting_route.end_line}) "
            f"covering sink at line {best_sf.line} + Parameter `{param_desc}`."
        )
        candidate = CorrelatedIssue(
            status="Confirmed",
            cwe=df.cwe,
            severity=df.severity if df.severity == "Critical" else best_sf.severity,
            url=df.url,
            canonical_path=connecting_route.canonical_path,
            method=df.method or connecting_route.method,
            param=effective_param,
            payload=df.payload,
            evidence=df.evidence,
            file=best_sf.file,
            line=best_sf.line,
            func_name=best_sf.func_name or connecting_route.func_name,
            snippet=best_sf.snippet,
            sast_evidence=peer_sast_findings,
            dast_evidence=[df],
            matched_route=route_desc,
            link_reason=link_reason,
            fix_suggestion=DEFAULT_FIX_SUGGESTIONS.get(df.cwe, "Apply input validation and safe API patterns."),
        )
        if candidate.fingerprint not in issues_by_fp:
            issues_by_fp[candidate.fingerprint] = candidate
        else:
            existing = issues_by_fp[candidate.fingerprint]
            for sf_peer in peer_sast_findings:
                if all(x.fingerprint != sf_peer.fingerprint for x in existing.sast_evidence):
                    existing.sast_evidence.append(sf_peer)
            if all(x.fingerprint != df.fingerprint for x in existing.dast_evidence):
                existing.dast_evidence.append(df)
            existing.finding_count = len(existing.sast_evidence) + len(existing.dast_evidence)

    # Remaining unmatched SAST findings -> "Code only"
    for sf in active_sast:
        if sf.fingerprint in matched_sast_fps:
            continue
        code_issue = CorrelatedIssue(
            status="Code only",
            cwe=sf.cwe,
            title=sf.title,
            severity=sf.severity,
            file=sf.file,
            line=sf.line,
            func_name=sf.func_name,
            param=sf.param,
            snippet=sf.snippet,
            sast_evidence=[sf],
            dast_evidence=[],
            fix_suggestion=DEFAULT_FIX_SUGGESTIONS.get(sf.cwe, "Remediate static code vulnerability."),
        )
        if code_issue.fingerprint not in issues_by_fp:
            issues_by_fp[code_issue.fingerprint] = code_issue
        else:
            existing = issues_by_fp[code_issue.fingerprint]
            if all(x.fingerprint != sf.fingerprint for x in existing.sast_evidence):
                existing.sast_evidence.append(sf)
            existing.finding_count = len(existing.sast_evidence) + len(existing.dast_evidence)

    # Remaining unmatched DAST findings -> "Runtime only"
    for df in dast_findings:
        if df.fingerprint in matched_dast_fps:
            continue
        resolved_canonical = df.canonical_path
        for r in routes:
            if r.matches_url(df.url or df.canonical_path or "/", df.method):
                resolved_canonical = r.canonical_path
                break
        runtime_issue = CorrelatedIssue(
            status="Runtime only",
            cwe=df.cwe,
            title=df.title,
            severity=df.severity,
            url=df.url,
            canonical_path=resolved_canonical,
            method=df.method,
            param=df.param,
            payload=df.payload,
            evidence=df.evidence,
            sast_evidence=[],
            dast_evidence=[df],
            fix_suggestion=DEFAULT_FIX_SUGGESTIONS.get(df.cwe, "Harden runtime configuration and security headers."),
        )
        if runtime_issue.fingerprint not in issues_by_fp:
            issues_by_fp[runtime_issue.fingerprint] = runtime_issue
        else:
            existing = issues_by_fp[runtime_issue.fingerprint]
            if all(x.fingerprint != df.fingerprint for x in existing.dast_evidence):
                existing.dast_evidence.append(df)
            existing.finding_count = len(existing.sast_evidence) + len(existing.dast_evidence)

    return list(issues_by_fp.values())


# ---------------------------------------------------------------------------
# FastAPI Routes (FR-10) & UI Dashboard Server (FR-8, FR-9)
# ---------------------------------------------------------------------------


def _build_checkpoint1_reference_slice() -> Tuple[List[RouteEntry], List[CanonicalFinding], List[CanonicalFinding]]:
    """
    Reference vertical slice for Checkpoint 1 (4:00 PM Mentor Demo) used when the UI
    triggers a scan before the standalone target web-shop process is booted.
    """
    demo_routes = [
        RouteEntry(
            method="GET",
            path_pattern="/api/orders",
            file="orders.py",
            func_name="get_orders",
            start_line=80,
            end_line=95,
            params=["id", "sort"],
            called_funcs=["query_orders_db"],
        ),
        RouteEntry(
            method="GET",
            path_pattern="/search",
            file="views.py",
            func_name="search_catalog",
            start_line=35,
            end_line=52,
            params=["q"],
            called_funcs=["render_search_results"],
        ),
        RouteEntry(
            method="GET",
            path_pattern="/api/orders/safe",
            file="orders.py",
            func_name="get_orders_safe",
            start_line=105,
            end_line=120,
            params=["id"],
            called_funcs=[],
        ),
    ]
    demo_sast = [
        CanonicalFinding(
            source="SAST",
            scanner_name="core-sast",
            cwe="CWE-89",
            severity="Critical",
            file="orders.py",
            line=88,
            func_name="get_orders",
            param="id",
            snippet="cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")",
            evidence="Unparameterized f-string SQL query in get_orders()",
        ),
        CanonicalFinding(
            source="SAST",
            scanner_name="core-sast",
            cwe="CWE-79",
            severity="High",
            file="views.py",
            line=42,
            func_name="search_catalog",
            param="q",
            snippet="return HTMLResponse(f\"<h2>Results for {q}</h2>\")",
            evidence="Unescaped user query parameter 'q' rendered directly into HTMLResponse",
        ),
        CanonicalFinding(
            source="SAST",
            scanner_name="core-sast",
            cwe="CWE-798",
            severity="High",
            file="config.py",
            line=19,
            func_name="load_payment_gateway",
            snippet="API_SECRET_KEY = os.getenv('API_SECRET_KEY', 'REDACTED')",
            evidence="Hard-coded API secret identifier detected in config.py:19",
        ),
        CanonicalFinding(
            source="SAST",
            scanner_name="core-sast",
            cwe="CWE-89",
            severity="Info",
            file="orders.py",
            line=114,
            func_name="get_orders_safe",
            param="id",
            snippet="cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))",
            is_protected_decoy=True,
            decoy_reason="B-2 Safe Decoy: Parameterized 2-argument cursor.execute(sql, (order_id,)) prevents SQL injection",
        ),
        CanonicalFinding(
            source="SAST",
            scanner_name="core-sast",
            cwe="CWE-79",
            severity="Info",
            file="views.py",
            line=64,
            func_name="search_catalog_safe",
            param="q",
            snippet="return HTMLResponse(f\"<h2>Results for {html.escape(q)}</h2>\")",
            is_protected_decoy=True,
            decoy_reason="B-2 Safe Decoy: Explicit html.escape(q) neutralizes reflected XSS",
        ),
    ]
    demo_dast = [
        CanonicalFinding(
            source="DAST",
            scanner_name="core-dast",
            cwe="CWE-89",
            severity="Critical",
            url="http://localhost:5000/api/orders?id=1%27",
            method="GET",
            param="id",
            payload="1' OR '1'='1",
            evidence="SQLite syntax error / boolean tautology differential (HTTP 500 -> 200, +412 bytes)",
            phase="Phase-A-Active",
        ),
        CanonicalFinding(
            source="DAST",
            scanner_name="core-dast",
            cwe="CWE-79",
            severity="High",
            url="http://localhost:5000/search?q=%3Cscript%3Ecanary_probe_79%3C/script%3E",
            method="GET",
            param="q",
            payload="<script>canary_probe_79</script>",
            evidence="Raw unescaped '<script>canary_probe_79</script>' reflected in text/html body",
            phase="Phase-A-Active",
        ),
        CanonicalFinding(
            source="DAST",
            scanner_name="core-dast",
            cwe="CWE-693",
            severity="Medium",
            url="http://localhost:5000/api/orders",
            method="GET",
            payload="GET /api/orders (Passive Header Audit)",
            evidence="Missing Content-Security-Policy and X-Content-Type-Options headers on HTTP 200 response",
            phase="Phase-B-Passive",
        ),
        CanonicalFinding(
            source="DAST",
            scanner_name="core-dast",
            cwe="CWE-614",
            severity="Medium",
            url="http://localhost:5000/api/orders",
            method="GET",
            param="session_id",
            payload="Set-Cookie: session_id=...",
            evidence="Session cookie 'session_id' issued without HttpOnly and Secure attributes",
            phase="Phase-B-Passive",
        ),
    ]
    return demo_routes, demo_sast, demo_dast


def _load_ui_html(status_code: int = 200) -> HTMLResponse:
    """Read and return `ui/index.html` with the specified HTTP status code."""
    ui_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "index.html")
    if not os.path.exists(ui_path):
        return HTMLResponse("<h1>ui/index.html not found</h1>", status_code=404)
    with open(ui_path, "r", encoding="utf-8") as fh:
        return HTMLResponse(content=fh.read(), status_code=status_code)


def _wants_html_document(request: Request) -> bool:
    """Return True when the client explicitly requests an HTML document (browser navigation)."""
    accept = request.headers.get("accept", "").lower()
    return "text/html" in accept and "application/json" not in accept


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    """FR-8 / FR-9: Serve the single-page correlation dashboard (`ui/index.html`)."""
    return _load_ui_html(status_code=200)


@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon() -> Response:
    """Serve crisp SVG site icon for browser tabs and bookmarks."""
    return Response(content=FAVICON_SVG, media_type="image/svg+xml")


@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
@app.get("/terms", response_class=HTMLResponse, include_in_schema=False)
@app.get("/diff", response_class=HTMLResponse, include_in_schema=False)
@app.get("/onboarding", response_class=HTMLResponse, include_in_schema=False)
async def serve_spa_client_views() -> HTMLResponse:
    """Serve SPA shell for client-side routes (`/privacy`, `/terms`, `/diff`, `/onboarding`)."""
    return _load_ui_html(status_code=200)


@app.get("/404", response_class=HTMLResponse, include_in_schema=False)
async def serve_custom_404_page() -> HTMLResponse:
    """Serve dedicated custom 404 page with HTTP 404 status."""
    return _load_ui_html(status_code=404)


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Return engine status, Target Safety Lock hosts, and server-managed credential isolation state."""
    return {
        "status": "ok",
        "engine": "CYBERFORGE CORRELATE v1.0",
        "target_safety_lock": {
            "enforced": True,
            "follow_redirects": False,
            "allowed_hosts": sorted(get_allowed_hosts()),
        },
        "credential_isolation": {
            "frontend_api_keys": False,
            "mode": "server-managed-env",
        },
    }


@app.post("/scans", response_model=ScanSummary)
async def create_and_run_scan(
    request: ScanRequest,
    store: DatabaseStore = Depends(get_store),
) -> ScanSummary:
    """
    FR-10: Execute an end-to-end scan (`route_mapper` -> `sast_scanner` -> `decoy_filter`
    -> `dast_scanner` -> `correlator`), persist idempotently to SQLite (`FR-6`), and
    return the `ScanSummary`.
    """
    t0 = time.perf_counter()

    # Validate target_url immediately against PRD Page 4 Rule 1 safety lock
    validated_url: Optional[str] = None
    if request.target_url:
        try:
            validated_url = validate_target_url(request.target_url)
        except TargetScopeViolationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    scan_id = store.create_scan(
        app_name=request.app_name,
        source_dir=request.source_dir,
        target_url=validated_url,
    )

    routes: List[RouteEntry] = list(request.seeded_routes)
    sast_findings: List[CanonicalFinding] = list(request.seeded_sast_findings)
    dast_findings: List[CanonicalFinding] = list(request.seeded_dast_findings)
    sca_findings: List[SCAFinding] = []
    mapper_instance: Optional[Any] = None

    # 1. Person A Route Mapper, SAST Scanner & Reachability SCA (graceful dynamic import)
    if request.source_dir and os.path.exists(request.source_dir):
        try:
            from engine import route_mapper  # type: ignore

            if hasattr(route_mapper, "RouteMapper"):
                mapper_instance = route_mapper.RouteMapper(request.source_dir)
                routes.extend(mapper_instance.scan())
            elif hasattr(route_mapper, "build_route_map"):
                routes.extend(route_mapper.build_route_map(request.source_dir))
            elif hasattr(route_mapper, "map_routes"):
                routes.extend(route_mapper.map_routes(request.source_dir))
        except ImportError:
            pass

        try:
            from engine import sast_scanner  # type: ignore

            if hasattr(sast_scanner, "run_sast_scan"):
                sast_findings.extend(
                    sast_scanner.run_sast_scan(
                        request.source_dir,
                        routes=routes,
                        route_mapper=mapper_instance,
                    )
                )
            elif hasattr(sast_scanner, "scan_source"):
                sast_findings.extend(sast_scanner.scan_source(request.source_dir))
            elif hasattr(sast_scanner, "SASTScanner"):
                scanner_instance = sast_scanner.SASTScanner(
                    request.source_dir, route_mapper=mapper_instance
                )
                reachable_files = (
                    mapper_instance.get_reachable_files() if mapper_instance is not None else None
                )
                sast_findings.extend(
                    scanner_instance.scan(
                        reachable_files=reachable_files,
                        route_mapper=mapper_instance,
                    )
                )
        except ImportError:
            pass

        try:
            from engine import decoy_filter  # type: ignore

            if hasattr(decoy_filter, "filter_decoys"):
                sast_findings = decoy_filter.filter_decoys(
                    sast_findings,
                    routes=routes,
                    route_mapper=mapper_instance,
                )
        except ImportError:
            pass

        if getattr(request, "enable_sca", True):
            try:
                from engine import sca_reachability  # type: ignore

                if hasattr(sca_reachability, "run_sca_reachability"):
                    sca_findings.extend(
                        sca_reachability.run_sca_reachability(
                            request.source_dir,
                            routes=routes,
                            route_mapper=mapper_instance,
                        )
                    )
                elif hasattr(sca_reachability, "SCAReachabilityEngine"):
                    sca_engine = sca_reachability.SCAReachabilityEngine(
                        request.source_dir, route_mapper=mapper_instance
                    )
                    sca_report = sca_engine.analyze_reachability()
                    alert_flags_by_pkg: Dict[str, List[str]] = {}
                    for alert in sca_report.supply_chain_alerts:
                        alert_flags_by_pkg.setdefault(alert.package, []).append(alert.alert_type)
                    for rf in sca_report.findings:
                        sca_findings.append(
                            SCAFinding(
                                id=rf.id,
                                package_name=rf.package,
                                installed_version=rf.installed_version,
                                ecosystem=rf.ecosystem,
                                is_direct=len(rf.transitive_path) <= 1,
                                dependency_path=rf.transitive_path,
                                advisory_id=rf.advisory_id,
                                cve_id=rf.cve_id,
                                original_severity=rf.original_severity,
                                effective_severity=rf.effective_severity,
                                cvss_score=rf.cvss_score,
                                epss_score=rf.epss_score,
                                in_cisa_kev=rf.is_kev,
                                fixed_version=rf.fixed_version,
                                vulnerable_functions=rf.vulnerable_functions,
                                reachability_status=rf.status,
                                call_chain=rf.call_chain,
                                supply_chain_flags=alert_flags_by_pkg.get(rf.package, []),
                            )
                        )
            except ImportError:
                pass

    # 2. Person B 2-Phase Async DAST Scanner (FR-2) with Adaptive Scope Reduction (Task B2.1)
    wsgi_transport: Optional[httpx.AsyncBaseTransport] = None
    scope_reduction_report: Optional[ScopeReductionReport] = None
    effective_target_url = _resolve_reachable_target_url(validated_url) if validated_url else None
    if effective_target_url and request.run_live_dast:
        if not _is_tcp_port_reachable(effective_target_url):
            wsgi_transport = _load_local_wsgi_transport(request.source_dir)
        dast_scanner_instance = DASTScanner(
            base_url=effective_target_url,
            auth_headers=request.auth_headers,
            auth_cookies=request.auth_cookies,
            transport=wsgi_transport,
        )
        live_dast = await dast_scanner_instance.scan(
            routes=routes,
            sast_findings=sast_findings,
            route_mapper=mapper_instance,
        )
        scope_reduction_report = dast_scanner_instance.last_scope_reduction
        dast_findings.extend(live_dast)

    # 2b. Optional Checkpoint 1 Demo Slice Fallback when standalone target app is not running yet
    if getattr(request, "seed_checkpoint_slice_if_empty", False) and not (
        routes or sast_findings or dast_findings
    ):
        demo_routes, demo_sast, demo_dast = _build_checkpoint1_reference_slice()
        routes.extend(demo_routes)
        sast_findings.extend(demo_sast)
        dast_findings.extend(demo_dast)

    # 2c. Ensure ScopeReductionReport telemetry is always computed for Task B2.3
    if scope_reduction_report is None:
        try:
            from engine import scope_reducer  # type: ignore

            if hasattr(scope_reducer, "compute_scope_reduction"):
                scope_reduction_report = DatabaseStore._enrich_scope_reduction(
                    scope_reducer.compute_scope_reduction(
                        routes=routes,
                        sast_findings=sast_findings,
                        route_mapper=mapper_instance,
                    )
                )
        except ImportError:
            pass

    # 3. Correlate SAST + DAST Findings (FR-5, FR-6, FR-7, FR-9)
    correlated_issues: Optional[List[CorrelatedIssue]] = None
    try:
        from engine import correlator  # type: ignore

        if hasattr(correlator, "correlate_findings"):
            correlated_issues = correlator.correlate_findings(
                routes,
                sast_findings,
                dast_findings,
                route_mapper=mapper_instance,
                source_dir=request.source_dir,
            )
    except ImportError:
        pass

    if correlated_issues is None:
        correlated_issues = fallback_correlate_findings(
            routes,
            sast_findings,
            dast_findings,
            route_mapper=mapper_instance,
        )
    else:
        for issue in correlated_issues:
            if not issue.fix_suggestion:
                issue.fix_suggestion = DEFAULT_FIX_SUGGESTIONS.get(
                    issue.cwe, "Apply input validation and safe API patterns."
                )

    # 3b. Optional B-1 Auto-Verification Loop
    if effective_target_url and getattr(request, "enable_auto_verify", True):
        try:
            from engine import auto_verify  # type: ignore

            if hasattr(auto_verify, "auto_verify_code_only_issues"):
                if wsgi_transport is None and not _is_tcp_port_reachable(effective_target_url):
                    wsgi_transport = _load_local_wsgi_transport(request.source_dir)
                correlated_issues = await auto_verify.auto_verify_code_only_issues(
                    base_url=effective_target_url,
                    routes=routes,
                    issues=correlated_issues,
                    auth_headers=request.auth_headers,
                    auth_cookies=request.auth_cookies,
                    transport=wsgi_transport,
                )
        except ImportError:
            pass

    # 4. Persist to SQLite with FR-6 Idempotent Fingerprint Upserts
    store.save_routes(scan_id, routes, app_name=request.app_name)
    all_raw = sast_findings + dast_findings
    _, decoys_suppressed = store.save_findings(scan_id, all_raw, app_name=request.app_name)
    if sca_findings:
        store.save_sca_findings(scan_id, sca_findings, app_name=request.app_name)
    persisted_issues = store.upsert_issues(
        scan_id, correlated_issues, app_name=request.app_name
    )

    elapsed = time.perf_counter() - t0
    active_sast_count = sum(1 for f in sast_findings if not f.is_protected_decoy)
    return store.finalize_scan(
        scan_id=scan_id,
        duration_seconds=elapsed,
        routes_discovered=len(routes),
        raw_sast_findings=active_sast_count,
        raw_dast_findings=len(dast_findings),
        safe_decoys_suppressed=decoys_suppressed,
        issues=persisted_issues,
        sca_findings_count=len(sca_findings),
        scope_reduction=scope_reduction_report,
    )


@app.get("/scans", response_model=List[ScanSummary])
async def list_scans(store: DatabaseStore = Depends(get_store)) -> List[ScanSummary]:
    """Return all scan runs ordered most-recent first."""
    return store.get_scans()


@app.get("/scans/compare")
async def compare_two_scans(
    base: Optional[int] = Query(default=None, description="Base scan ID"),
    target: Optional[int] = Query(default=None, description="Target scan ID"),
    app_name: Optional[str] = Query(default=None, description="Optional app_name to compare latest two scans"),
    store: DatabaseStore = Depends(get_store),
) -> Dict[str, Any]:
    """Bonus B-5: Compare two scans and return `NEW`, `FIXED`, and `STILL-OPEN` issues."""
    if base is None or target is None:
        scans = store.get_scans()
        if app_name:
            scans = [s for s in scans if s.app_name == app_name]
        if len(scans) < 2:
            raise HTTPException(
                status_code=400,
                detail="At least two scans are required for comparison when base/target are not specified.",
            )
        target = target or scans[0].scan_id
        base = base or scans[1].scan_id
    return store.compare_scans(base_scan_id=base, target_scan_id=target)


@app.get("/scans/{scan_id}/sarif")
async def export_scan_sarif(
    scan_id: int,
    store: DatabaseStore = Depends(get_store),
) -> JSONResponse:
    """Task B3.1 (B-6): Export a specific scan's correlated issues and SCA findings as OASIS SARIF v2.1.0."""
    scan = store.get_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found.")
    issues = store.get_issues(scan_id=scan_id, only_open=False)
    sca_findings = store.get_sca_findings(app_name=scan.app_name)
    sarif_doc = build_sarif_report(issues=issues, sca_findings=sca_findings, scan_summary=scan)
    return JSONResponse(
        content=sarif_doc,
        headers={
            "Content-Disposition": f'attachment; filename="cyberforge-scan-{scan_id}.sarif.json"'
        },
    )


@app.get("/export/sarif")
async def export_latest_sarif(
    scan_id: Optional[int] = Query(default=None, description="Optional scan_id (defaults to latest scan)"),
    app_name: Optional[str] = Query(default=None, description="Optional app_name filter"),
    store: DatabaseStore = Depends(get_store),
) -> JSONResponse:
    """Task B3.1 (B-6): Export the latest scan (or specified scan_id) in OASIS SARIF v2.1.0 format."""
    scan: Optional[ScanSummary] = None
    if scan_id is not None:
        scan = store.get_scan_by_id(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found.")
    else:
        scans = store.get_scans()
        if app_name:
            scans = [s for s in scans if s.app_name == app_name]
        if scans:
            scan = scans[0]

    effective_scan_id = scan.scan_id if scan is not None else None
    effective_app = app_name or (scan.app_name if scan is not None else None)
    issues = store.get_issues(
        app_name=effective_app,
        scan_id=effective_scan_id,
        only_open=(effective_scan_id is None),
    )
    sca_findings = store.get_sca_findings(app_name=effective_app)
    sarif_doc = build_sarif_report(issues=issues, sca_findings=sca_findings, scan_summary=scan)
    fname = f"cyberforge-scan-{effective_scan_id or 'latest'}.sarif.json"
    return JSONResponse(
        content=sarif_doc,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/scans/{scan_id}/ci-gate")
async def get_scan_ci_gate(
    scan_id: int,
    store: DatabaseStore = Depends(get_store),
) -> Dict[str, Any]:
    """
    Task B3.1: Evaluate CI/CD security gate for `scan_id`.
    Returns `status: "FAIL"`, `exit_code: 1` if any `Confirmed` Critical/High issue
    or `Reachable` CISA KEV SCA CVE exists, else `status: "PASS"`, `exit_code: 0`.
    """
    scan = store.get_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found.")
    issues = store.get_issues(scan_id=scan_id, only_open=False)
    sca_findings = store.get_sca_findings(app_name=scan.app_name)
    return evaluate_ci_gate(issues=issues, sca_findings=sca_findings, scan_summary=scan)


@app.get("/ci-gate")
async def get_latest_ci_gate(
    scan_id: Optional[int] = Query(default=None, description="Optional scan_id (defaults to latest scan)"),
    app_name: Optional[str] = Query(default=None, description="Optional app_name filter"),
    store: DatabaseStore = Depends(get_store),
) -> Dict[str, Any]:
    """Task B3.1: Evaluate CI/CD security gate for the latest scan (or specified `scan_id`)."""
    scan: Optional[ScanSummary] = None
    if scan_id is not None:
        scan = store.get_scan_by_id(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found.")
    else:
        scans = store.get_scans()
        if app_name:
            scans = [s for s in scans if s.app_name == app_name]
        if scans:
            scan = scans[0]

    effective_scan_id = scan.scan_id if scan is not None else None
    effective_app = app_name or (scan.app_name if scan is not None else None)
    issues = store.get_issues(
        app_name=effective_app,
        scan_id=effective_scan_id,
        only_open=(effective_scan_id is None),
    )
    sca_findings = store.get_sca_findings(app_name=effective_app)
    return evaluate_ci_gate(issues=issues, sca_findings=sca_findings, scan_summary=scan)


@app.get("/scans/{scan_id}", response_model=ScanSummary)
async def get_scan_detail(
    scan_id: int,
    store: DatabaseStore = Depends(get_store),
) -> ScanSummary:
    """Task B2.3: Return a single ScanSummary (including `scope_reduction` telemetry) by `scan_id`."""
    scan = store.get_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found.")
    return scan


@app.get("/issues", response_model=List[CorrelatedIssue])
async def list_issues(
    request: Request,
    status: Optional[str] = Query(default=None, description="Filter by 'Confirmed', 'Code only', 'Runtime only'"),
    cwe: Optional[str] = Query(default=None, description="Filter by CWE, e.g. 'CWE-89'"),
    app_name: Optional[str] = Query(default=None, description="Filter by app_name"),
    scan_id: Optional[int] = Query(default=None, description="Filter by specific scan_id"),
    store: DatabaseStore = Depends(get_store),
) -> Any:
    """
    FR-9 / FR-10: Return correlated issues ranked with `Confirmed` first,
    then by composite `risk_score` descending. Serves SPA HTML when navigated directly in browser.
    """
    if _wants_html_document(request):
        return _load_ui_html(status_code=200)
    return store.get_issues(status=status, cwe=cwe, app_name=app_name, scan_id=scan_id)


@app.get("/issues/{issue_id}", response_model=CorrelatedIssue)
async def get_issue_detail(
    request: Request,
    issue_id: str,
    store: DatabaseStore = Depends(get_store),
) -> Any:
    """
    FR-8 / FR-10: Return unified detail view for a single issue (`GET /issues/7`),
    including URL, parameter, payload, file, line, code snippet, CWE, severity,
    `B-3` link explanation, and `B-4` plain-English fix suggestion.
    """
    if _wants_html_document(request):
        return _load_ui_html(status_code=200)
    issue: Optional[CorrelatedIssue] = None
    if issue_id.isdigit():
        issue = store.get_issue_by_id(int(issue_id))
    else:
        for candidate in store.get_issues(only_open=False):
            if str(candidate.id) == issue_id or candidate.fingerprint == issue_id:
                issue = candidate
                break
    if issue is None:
        raise HTTPException(status_code=404, detail=f"Issue #{issue_id} not found.")
    return issue


@app.get("/routes", response_model=List[RouteEntry])
async def list_discovered_routes(
    request: Request,
    app_name: Optional[str] = Query(default=None),
    store: DatabaseStore = Depends(get_store),
) -> Any:
    """FR-4: Return the AST Route Map (`URL -> function, file, start_line..end_line`)."""
    if _wants_html_document(request):
        return _load_ui_html(status_code=200)
    return store.get_routes(app_name=app_name)


@app.get("/decoys", response_model=List[CanonicalFinding])
async def list_suppressed_decoys(
    request: Request,
    app_name: Optional[str] = Query(default=None),
    store: DatabaseStore = Depends(get_store),
) -> Any:
    """Bonus B-2: Return safe decoys suppressed during static analysis."""
    if _wants_html_document(request):
        return _load_ui_html(status_code=200)
    return store.get_suppressed_decoys(app_name=app_name)


@app.get("/sca", response_model=List[SCAFinding])
async def list_sca_findings(
    request: Request,
    app_name: Optional[str] = Query(default=None),
    store: DatabaseStore = Depends(get_store),
) -> Any:
    """Page 4 Bonus: Return Reachability-Aware SCA findings."""
    if _wants_html_document(request):
        return _load_ui_html(status_code=200)
    return store.get_sca_findings(app_name=app_name)


@app.get("/{unmatched_path:path}", include_in_schema=False)
async def catch_all_custom_404(request: Request, unmatched_path: str) -> Response:
    """
    Serve custom 404 SPA view for browser navigation to unknown routes,
    or structured JSON 404 for API requests.
    """
    if _wants_html_document(request):
        return _load_ui_html(status_code=404)
    return JSONResponse(
        status_code=404,
        content={
            "detail": f"Route '/{unmatched_path}' not found on CyberForge Correlate API.",
            "code": "ROUTE_NOT_FOUND",
            "path": f"/{unmatched_path}",
        },
    )

