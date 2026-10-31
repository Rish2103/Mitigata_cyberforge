"""
tests/test_subblock1_dast_and_db.py — Deep Verification Suite for Phase 1 Sub-block 1.

Tests:
  1. Target Safety Lock (`core/config.py`): blocks external domains/IPs, allows localhost &
     Docker test-app containers, enforces `follow_redirects=False` and outbound request hook.
  2. Shared Schemas (`core/schemas.py`): `RouteEntry` normalization across Flask/FastAPI/Express,
     multi-hop helper call-graph coverage, `SCAFinding` "Never downgrade Unknown" rule.
  3. 2-Phase DAST Scanner (`engine/dast_scanner.py`):
     - Phase A: CWE-89 (SQL error + Boolean differential), CWE-79 (unescaped canary reflection),
       CWE-601 (Open redirect via follow_redirects=False), plus HTML form discovery.
     - Zero False Alarms on HTML-escaped XSS decoys and pages with static "sql error" text.
     - Phase B: All 6 `Runtime only` passive checks (CSP, X-Frame-Options, X-Content-Type-Options,
       HSTS, insecure Cookie flags, wildcard CORS / verbose Server banner).
  4. SQLite Persistence & FastAPI Control Plane (`api/db.py`, `api/main.py`):
     - FR-6 Idempotency: running a scan twice produces 0 duplicate issues; 3 scanner findings
       on the same bug merge into 1 issue.
     - FR-5 Hard Vetoes: 0% wrong links across different routes/parameters.
     - FR-9 Priority Ranking & B-5 Scan Comparison (`NEW`, `FIXED`, `STILL-OPEN`).
"""

from __future__ import annotations

import asyncio
import html
import os
import tempfile
from typing import Optional

import httpx
import pytest
from fastapi import FastAPI, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.testclient import TestClient

from api.db import DatabaseStore
from api.main import app as gordon_api_app, fallback_correlate_findings
from core.config import (
    TargetScopeViolationError,
    create_safe_async_client,
    is_local_or_docker_host,
    validate_target_url,
)
from core.schemas import (
    CalledFunction,
    CanonicalFinding,
    CorrelatedIssue,
    RouteEntry,
    SCAFinding,
)
from engine.dast_scanner import run_dast_scan


# ---------------------------------------------------------------------------
# Mock Local Vulnerable Web Shop (In-Process ASGI App for Real HTTP Probing)
# ---------------------------------------------------------------------------


def build_mock_shop_asgi_app() -> FastAPI:
    shop = FastAPI()

    @shop.get("/")
    async def home() -> HTMLResponse:
        # Sets insecure cookie, wildcard CORS, verbose X-Powered-By, and omits CSP/XFO/HSTS/nosniff
        # Also contains an unlinked HTML form to /api/search so crawler discovery is tested
        body = """
        <html>
          <body>
            <h1>Mitigata Benchmark Web Shop</h1>
            <a href="/api/orders?id=1">My Orders</a>
            <form action="/api/search" method="GET">
              <input type="text" name="q" />
              <button type="submit">Search</button>
            </form>
          </body>
        </html>
        """
        resp = HTMLResponse(content=body, status_code=200)
        resp.headers["Set-Cookie"] = "session_id=unsafecookie123; Path=/"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["X-Powered-By"] = "Flask-Werkzeug/3.0.1"
        return resp

    @shop.get("/api/orders")
    async def get_orders(id: str = Query(default="1")) -> Response:
        # Vulnerable to CWE-89 (SQL error based)
        if "'" in id:
            return HTMLResponse(
                content=(
                    f"sqlite3.OperationalError: near \"'{id}'\": syntax error "
                    f"in SELECT * FROM orders WHERE id = '{id}'"
                ),
                status_code=500,
            )
        return JSONResponse({"order_id": id, "item": "Cyber Insurance Policy", "amount": 5000})

    @shop.get("/api/products")
    async def list_products(category: str = Query(default="all")) -> Response:
        # Vulnerable to CWE-89 (Blind Boolean Differential — no SQL error text returned!)
        if "' OR '1'='1" in category:
            return JSONResponse(
                {
                    "products": [
                        {"id": 1, "name": "Gordon AI SOC"},
                        {"id": 2, "name": "Gordon VAPT"},
                        {"id": 3, "name": "Smart Cyber Insurance"},
                    ]
                }
            )
        if "' AND '1'='2" in category:
            return JSONResponse({"products": []})
        if "'" in category:
            return JSONResponse({"products": []}, status_code=500)
        return JSONResponse({"products": [{"id": 1, "name": "Gordon AI SOC"}]})

    @shop.get("/api/search")
    async def search_items(q: str = Query(default="")) -> HTMLResponse:
        # Vulnerable to CWE-79 Reflected XSS (unescaped reflection)
        return HTMLResponse(content=f"<html><body>Results for: {q}</body></html>")

    @shop.get("/api/safe-search")
    async def safe_search_decoy(q: str = Query(default="")) -> HTMLResponse:
        # SAFE DECOY (B-2): Properly HTML-escapes user input AND contains static text mentioning
        # "sql syntax error" in baseline so baseline diffing is verified!
        escaped_q = html.escape(q, quote=True)
        return HTMLResponse(
            content=(
                f"<html><body>Safe results for: {escaped_q}"
                f"<footer>Note: sql syntax error reporting is disabled.</footer></body></html>"
            )
        )

    @shop.get("/api/redirect")
    async def login_redirect(next: str = Query(default="/dashboard")) -> RedirectResponse:
        # Vulnerable to CWE-601 Open Redirect
        return RedirectResponse(url=next, status_code=302)

    return shop


# ---------------------------------------------------------------------------
# 1. Target Safety Lock Tests (`core/config.py`)
# ---------------------------------------------------------------------------


def test_target_safety_lock_allows_local_and_blocks_external() -> None:
    # Approved local & Docker test-app targets must pass
    assert validate_target_url("http://localhost:5000") == "http://localhost:5000"
    assert validate_target_url("http://127.0.0.1:8080/api") == "http://127.0.0.1:8080/api"
    assert validate_target_url("http://test-app:3000/") == "http://test-app:3000"
    assert validate_target_url("http://web-shop:5000") == "http://web-shop:5000"
    assert is_local_or_docker_host("::1") is True

    # Any external domain, public IP, or non-http scheme must be hard-blocked
    for forbidden_url in [
        "https://example.com",
        "http://mitigata.com/api",
        "http://8.8.8.8:8080",
        "http://192.168.1.50:5000",
        "ftp://localhost:21",
        "",
    ]:
        with pytest.raises(TargetScopeViolationError):
            validate_target_url(forbidden_url)


def test_safe_async_client_enforces_no_redirects_and_request_hook() -> None:
    async def _run() -> None:
        async with create_safe_async_client(follow_redirects=True) as client:
            # Caller attempted follow_redirects=True, but safety factory MUST force False
            assert client.follow_redirects is False

            # Outbound request hook must block any attempt to request an external URL directly
            with pytest.raises(TargetScopeViolationError):
                await client.get("https://example.com/malicious-redirect")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. Schema & Route Normalization Tests (`core/schemas.py`)
# ---------------------------------------------------------------------------


def test_route_entry_normalizes_flask_fastapi_express_and_call_graph() -> None:
    r_flask = RouteEntry(
        method="get",
        path_pattern="/api/orders/<int:order_id>",
        file="routes\\orders.py",
        func_name="get_order",
        start_line=80,
        end_line=95,
        called_func_details=[
            CalledFunction(
                name="fetch_order_from_db",
                file="db/repo.py",
                start_line=30,
                end_line=50,
            )
        ],
    )
    r_express = RouteEntry(
        method="GET",
        path_pattern="/api/orders/:order_id/",
        file="routes/orders.js",
        func_name="getOrder",
        start_line=10,
        end_line=25,
    )
    assert r_flask.canonical_path == "/api/orders/{order_id}"
    assert r_express.canonical_path == "/api/orders/{order_id}"
    assert "order_id" in r_flask.params
    assert r_flask.matches_url("http://localhost:5000/api/orders/42?foo=bar", "GET") is True
    assert r_flask.matches_url("http://localhost:5000/api/orders/42", "POST") is False
    assert r_flask.concrete_path() == "/api/orders/1"

    # Direct handler line coverage AND 1-hop helper coverage across files
    assert r_flask.covers_location("routes/orders.py", 88) is True
    assert r_flask.covers_location("db/repo.py", 42) is True
    assert r_flask.covers_location("db/repo.py", 99) is False


def test_sca_finding_never_downgrades_unknown_status() -> None:
    sca = SCAFinding(
        package_name="cryptography",
        installed_version="39.0.0",
        advisory_id="GHSA-xxxx-yyyy-zzzz",
        original_severity="Critical",
        effective_severity="Low",  # Attempt to downgrade Unknown
        reachability_status="Unknown",
    )
    # Validator must restore original_severity for Unknown!
    assert sca.effective_severity == "Critical"


# ---------------------------------------------------------------------------
# 3. 2-Phase DAST Scanner Tests (`engine/dast_scanner.py`)
# ---------------------------------------------------------------------------


def test_2_phase_dast_scanner_detects_active_and_passive_with_zero_false_alarms() -> None:
    async def _run() -> None:
        shop_app = build_mock_shop_asgi_app()
        transport = httpx.ASGITransport(app=shop_app)

        seeded_routes = [
            RouteEntry(
                method="GET",
                path_pattern="/api/orders",
                file="orders.py",
                func_name="get_orders",
                start_line=80,
                end_line=95,
                params=["id"],
            ),
            RouteEntry(
                method="GET",
                path_pattern="/api/products",
                file="products.py",
                func_name="list_products",
                start_line=20,
                end_line=45,
                params=["category"],
            ),
            RouteEntry(
                method="GET",
                path_pattern="/api/safe-search",
                file="search.py",
                func_name="safe_search_decoy",
                start_line=50,
                end_line=70,
                params=["q"],
            ),
            RouteEntry(
                method="GET",
                path_pattern="/api/redirect",
                file="auth.py",
                func_name="login_redirect",
                start_line=10,
                end_line=25,
                params=["next"],
            ),
            # Note: /api/search is intentionally NOT in seeded_routes to prove HTML form crawler discovery works!
        ]

        findings = await run_dast_scan(
            base_url="http://localhost:5000",
            routes=seeded_routes,
            transport=transport,
        )

        active_findings = [f for f in findings if f.phase == "Phase-A-Active"]
        passive_findings = [f for f in findings if f.phase == "Phase-B-Passive"]

        # Check Phase A active detections:
        active_by_path_cwe = {(f.canonical_path, f.cwe, f.param) for f in active_findings}
        # 1. SQLi error-based on /api/orders?id=
        assert ("/api/orders", "CWE-89", "id") in active_by_path_cwe
        # 2. SQLi boolean-differential on /api/products?category=
        assert ("/api/products", "CWE-89", "category") in active_by_path_cwe
        # 3. Reflected XSS on /api/search?q= (discovered via HTML form crawl on /)
        assert ("/api/search", "CWE-79", "q") in active_by_path_cwe
        # 4. Open Redirect on /api/redirect?next= (captured safely with follow_redirects=False)
        assert ("/api/redirect", "CWE-601", "next") in active_by_path_cwe

        # 5. ZERO False Alarms on /api/safe-search (escaped HTML + baseline SQL error text ignored)
        safe_search_hits = [f for f in active_findings if f.canonical_path == "/api/safe-search"]
        assert safe_search_hits == []

        # Check Phase B passive detections (all 6 Runtime-only bugs captured!):
        passive_cwes = {f.cwe for f in passive_findings}
        assert len(passive_findings) >= 6
        assert "CWE-693" in passive_cwes  # CSP, HSTS, X-Content-Type-Options
        assert "CWE-1021" in passive_cwes  # X-Frame-Options
        assert "CWE-614" in passive_cwes  # Insecure Set-Cookie
        assert "CWE-942" in passive_cwes  # Wildcard CORS
        assert "CWE-200" in passive_cwes  # Verbose X-Powered-By

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. FR-5 Correlation, FR-6 Idempotency & B-5 Scan Comparison Tests (`api/db.py`)
# ---------------------------------------------------------------------------


def test_correlator_vetoes_and_sqlite_idempotency_and_scan_diff() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_gordon.db")
        store = DatabaseStore(db_path=db_path)

        routes = [
            RouteEntry(
                method="GET",
                path_pattern="/api/orders",
                file="orders.py",
                func_name="get_orders",
                start_line=80,
                end_line=95,
                params=["id"],
            ),
            RouteEntry(
                method="GET",
                path_pattern="/api/products",
                file="products.py",
                func_name="list_products",
                start_line=10,
                end_line=35,
                params=["category"],
            ),
        ]

        sast_findings = [
            # Real SAST SQLi on /api/orders (orders.py:88)
            CanonicalFinding(
                source="SAST",
                scanner_name="gordon-sast",
                cwe="CWE-89",
                severity="Critical",
                file="orders.py",
                line=88,
                func_name="get_orders",
                param="id",
                snippet="cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")",
            ),
            # Code-only hard-coded secret (CWE-798)
            CanonicalFinding(
                source="SAST",
                scanner_name="gordon-sast",
                cwe="CWE-798",
                severity="High",
                file="config.py",
                line=14,
                func_name="init_app",
                snippet="STRIPE_SECRET_KEY = 'sk_live_999999999'",
            ),
            # Protected safe decoy (B-2): must be ignored by correlator
            CanonicalFinding(
                source="SAST",
                scanner_name="gordon-sast",
                cwe="CWE-89",
                severity="High",
                file="orders.py",
                line=120,
                func_name="get_orders_safe",
                snippet="cursor.execute('SELECT * FROM orders WHERE id = ?', (id,))",
                is_protected_decoy=True,
                decoy_reason="Parameterized query with bound tuple parameters",
            ),
        ]

        dast_findings = [
            # Matches SAST CWE-89 on /api/orders?id= -> Confirmed!
            CanonicalFinding(
                source="DAST",
                scanner_name="gordon-dast",
                cwe="CWE-89",
                severity="Critical",
                url="http://localhost:5000/api/orders?id=1%27",
                canonical_path="/api/orders",
                method="GET",
                param="id",
                payload="1'",
                evidence="sqlite3.OperationalError: near \"'\": syntax error",
            ),
            # Second DAST scanner hit on the EXACT SAME /api/orders?id= bug -> must merge into 1 issue (FR-6)!
            CanonicalFinding(
                source="DAST",
                scanner_name="zap-importer",
                cwe="CWE-89",
                severity="Critical",
                url="http://localhost:5000/api/orders?id=1%27%20OR%20%271%27%3D%271",
                canonical_path="/api/orders",
                method="GET",
                param="id",
                payload="1' OR '1'='1",
                evidence="Boolean tautology differential response",
            ),
            # Runtime-only missing CSP header (CWE-693)
            CanonicalFinding(
                source="DAST",
                scanner_name="gordon-dast-phase-b",
                cwe="CWE-693",
                severity="Medium",
                url="http://localhost:5000/",
                canonical_path="/",
                method="GET",
                param="header:Content-Security-Policy",
                payload="Passive HTTP Header Audit",
                evidence="Missing Content-Security-Policy header",
            ),
        ]

        # Run Scan #1
        scan1_id = store.create_scan(app_name="shop", target_url="http://localhost:5000")
        issues_scan1 = fallback_correlate_findings(routes, sast_findings, dast_findings)
        persisted_1 = store.upsert_issues(scan1_id, issues_scan1, app_name="shop")

        # Expect strictly 3 issues:
        #   1. Confirmed CWE-89 on /api/orders (orders.py:88)
        #   2. Runtime only CWE-693 on /
        #   3. Code only CWE-798 on config.py:14
        # (The B-2 decoy is suppressed, and the 2nd DAST SQLi on /api/orders merged into Issue #1!)
        assert len(persisted_1) == 3
        assert persisted_1[0].status == "Confirmed"
        assert persisted_1[0].cwe == "CWE-89"
        assert persisted_1[0].file == "orders.py"
        assert persisted_1[0].line == 88
        assert persisted_1[0].param == "id"
        assert persisted_1[0].finding_count == 3  # 1 SAST + 2 DAST findings merged into 1 issue!

        # Verify FR-9 ranking: Confirmed (score ~99) > Runtime only > Code only
        statuses_in_order = [i.status for i in persisted_1]
        assert statuses_in_order[0] == "Confirmed"

        # Run Scan #2 with the EXACT SAME inputs to verify FR-6 idempotency ("running a scan twice does not create copies")
        scan2_id = store.create_scan(app_name="shop", target_url="http://localhost:5000")
        issues_scan2 = fallback_correlate_findings(routes, sast_findings, dast_findings)
        persisted_2 = store.upsert_issues(scan2_id, issues_scan2, app_name="shop")

        all_open_issues = store.get_issues(app_name="shop")
        assert len(all_open_issues) == 3
        assert [i.id for i in persisted_1] == [i.id for i in persisted_2]

        # Run Scan #3 after developer fixes CWE-89 in orders.py -> verify Bonus B-5 Scan Comparison!
        scan3_id = store.create_scan(app_name="shop", target_url="http://localhost:5000")
        issues_scan3 = fallback_correlate_findings(
            routes,
            [f for f in sast_findings if f.cwe != "CWE-89"],
            [f for f in dast_findings if f.cwe != "CWE-89"],
        )
        store.upsert_issues(scan3_id, issues_scan3, app_name="shop")

        diff = store.compare_scans(base_scan_id=scan2_id, target_scan_id=scan3_id)
        assert diff["summary"]["fixed_count"] == 1
        assert diff["summary"]["still_open_count"] == 2
        assert diff["summary"]["new_count"] == 0
        assert diff["fixed_issues"][0].cwe == "CWE-89"
        assert diff["fixed_issues"][0].diff_status == "FIXED"


def test_fastapi_endpoints_and_scope_guard_http_403() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["GORDON_DB_PATH"] = os.path.join(tmpdir, "api_test.db")
        client = TestClient(gordon_api_app)

        # 1. GET /health
        r_health = client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["target_safety_lock"]["follow_redirects"] is False

        # 2. POST /scans with external URL must return HTTP 403 Forbidden (PRD Page 4 Rule 1)
        r_blocked = client.post(
            "/scans",
            json={"app_name": "ext", "target_url": "https://example.com"},
        )
        assert r_blocked.status_code == 403
        assert "SAFETY LOCK BLOCKED TARGET" in r_blocked.json()["detail"]

        # 3. POST /scans with pre-seeded routes + SAST + DAST findings (no live DAST network needed)
        scan_payload = {
            "app_name": "shop",
            "target_url": "http://localhost:5000",
            "run_live_dast": False,
            "seeded_routes": [
                {
                    "method": "GET",
                    "path_pattern": "/api/orders",
                    "file": "orders.py",
                    "func_name": "get_orders",
                    "start_line": 80,
                    "end_line": 95,
                    "params": ["id"],
                }
            ],
            "seeded_sast_findings": [
                {
                    "source": "SAST",
                    "scanner_name": "gordon-sast",
                    "cwe": "CWE-89",
                    "severity": "Critical",
                    "file": "orders.py",
                    "line": 88,
                    "func_name": "get_orders",
                    "param": "id",
                    "snippet": "cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")",
                }
            ],
            "seeded_dast_findings": [
                {
                    "source": "DAST",
                    "scanner_name": "gordon-dast",
                    "cwe": "CWE-89",
                    "severity": "Critical",
                    "url": "http://localhost:5000/api/orders?id=1%27",
                    "canonical_path": "/api/orders",
                    "method": "GET",
                    "param": "id",
                    "payload": "1'",
                    "evidence": "sqlite3.OperationalError: syntax error",
                }
            ],
        }
        r_scan1 = client.post("/scans", json=scan_payload)
        assert r_scan1.status_code == 200
        scan1_data = r_scan1.json()
        assert scan1_data["confirmed_count"] == 1
        assert scan1_data["total_issues"] == 1

        # 4. GET /issues and GET /issues/{id}
        r_issues = client.get("/issues?app_name=shop")
        assert r_issues.status_code == 200
        issues_list = r_issues.json()
        assert len(issues_list) == 1
        issue_id = issues_list[0]["id"]

        r_detail = client.get(f"/issues/{issue_id}")
        assert r_detail.status_code == 200
        assert r_detail.json()["status"] == "Confirmed"
        assert r_detail.json()["cwe"] == "CWE-89"

        # 5. Run 2nd scan & test GET /scans/compare
        r_scan2 = client.post("/scans", json=scan_payload)
        assert r_scan2.status_code == 200
        r_cmp = client.get("/scans/compare?app_name=shop")
        assert r_cmp.status_code == 200
        assert r_cmp.json()["summary"]["still_open_count"] == 1


# ---------------------------------------------------------------------------
# 5. Regression Tests for Reviewer Hardening (Bugs 1–6)
# ---------------------------------------------------------------------------


def test_fastapi_typed_route_normalization_and_fr8_serialized_fields() -> None:
    """Bug 1 & Bug 2 regression test: FastAPI {param:type} route normalization and FR-8 JSON keys."""
    r_typed = RouteEntry(
        method="GET",
        path_pattern="/api/v1/orgs/{org_id:str}/orders/{order_id:int}",
        file="orders.py",
        func_name="get_org_order",
        start_line=10,
        end_line=30,
    )
    assert r_typed.canonical_path == "/api/v1/orgs/{org_id}/orders/{order_id}"
    assert r_typed.params == ["org_id", "order_id"]
    assert r_typed.matches_url("http://localhost:5000/api/v1/orgs/mitigata/orders/42", "GET") is True

    issue = CorrelatedIssue(
        status="Confirmed",
        cwe="CWE-89",
        severity="Critical",
        url="http://localhost:5000/api/orders?id=1'",
        param="id",
        payload="1'",
        file="orders.py",
        line=88,
        snippet="cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")",
    )
    dumped = issue.model_dump()
    assert dumped["param"] == "id"
    assert dumped["parameter"] == "id"
    assert dumped["snippet"] == "cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")"
    assert dumped["code_snippet"] == "cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")"


def test_fetchone_blind_boolean_sqli_and_relative_form_crawler() -> None:
    """Bug 6 regression test: .fetchone() single-row boolean SQLi & relative <form> action resolution."""
    from fastapi import Form

    app = FastAPI()

    @app.get("/")
    async def home() -> HTMLResponse:
        return HTMLResponse('<a href="/feedback">Leave Feedback</a><a href="/api/item?id=1">Item</a>')

    @app.get("/feedback")
    async def feedback_form() -> HTMLResponse:
        # Omitted/empty action attribute must resolve to /feedback, not /
        return HTMLResponse(
            """
            <html><body>
              <form method="POST">
                <input type="text" name="comment" value="hello" />
              </form>
            </body></html>
            """
        )

    @app.post("/feedback")
    async def feedback_submit(comment: str = Form(default="hello")) -> HTMLResponse:
        return HTMLResponse(f"<html><body><div>Posted: {comment}</div></body></html>")

    @app.get("/api/item")
    async def get_single_item(id: str = Query(default="1")) -> JSONResponse:
        # Simulate .fetchone() where baseline ('1') and tautology ("1' OR '1'='1") both return 1 row,
        # while contradiction ("1' AND '1'='2") returns 0 rows (empty object).
        if "AND '1'='2" in id or 'AND "1"="2' in id:
            return JSONResponse({"item": None})
        return JSONResponse(
            {
                "item": {
                    "id": 1,
                    "name": "CyberForge Enterprise Sensor",
                    "category": "Appliance",
                }
            }
        )

    transport = httpx.ASGITransport(app=app)
    findings = asyncio.run(
        run_dast_scan(
            base_url="http://localhost:5000",
            routes=[],
            transport=transport,
        )
    )

    by_cwe_path = {(f.cwe, f.canonical_path, f.method) for f in findings}
    assert ("CWE-89", "/api/item", "GET") in by_cwe_path
    assert ("CWE-79", "/feedback", "POST") in by_cwe_path


def test_multi_sast_scanner_dedup_and_same_route_multi_param_disambiguation() -> None:
    """Bug 3 & Bug 4 regression test: 2 SAST + 1 DAST = 1 Confirmed issue; multi-param route snippet affinity."""
    routes = [
        RouteEntry(
            method="GET",
            path_pattern="/api/orders",
            file="orders.py",
            func_name="get_orders",
            start_line=80,
            end_line=110,
            params=["id", "sort"],
        )
    ]

    # Case A: 2 SAST scanners + 1 DAST scanner on the exact same sink (orders.py:88)
    sast_multi_scanner = [
        CanonicalFinding(
            source="SAST",
            scanner_name="gordon-sast",
            cwe="CWE-89",
            severity="Critical",
            file="orders.py",
            line=88,
            func_name="get_orders",
            param="id",
            snippet="cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")",
        ),
        CanonicalFinding(
            source="SAST",
            scanner_name="semgrep-pro",
            cwe="CWE-89",
            severity="Critical",
            file="orders.py",
            line=88,
            func_name="get_orders",
            param="id",
            snippet="cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")",
        ),
    ]
    dast_single = [
        CanonicalFinding(
            source="DAST",
            scanner_name="gordon-dast",
            cwe="CWE-89",
            severity="Critical",
            url="http://localhost:5000/api/orders?id=1%27",
            canonical_path="/api/orders",
            method="GET",
            param="id",
            payload="1'",
            evidence="sqlite3.OperationalError: syntax error",
        )
    ]
    issues_a = fallback_correlate_findings(routes, sast_multi_scanner, dast_single)
    assert len(issues_a) == 1
    assert issues_a[0].status == "Confirmed"
    assert issues_a[0].finding_count == 3

    # Case B: Two different SQLi sinks in the same route handler (line 88 for `id`, line 98 for `sort`)
    # where SAST scanner omitted `sf.param` (`param=None`), requiring snippet token disambiguation.
    sast_two_sinks = [
        CanonicalFinding(
            source="SAST",
            scanner_name="gordon-sast",
            cwe="CWE-89",
            severity="Critical",
            file="orders.py",
            line=88,
            func_name="get_orders",
            param=None,
            snippet="cursor.execute(f\"SELECT * FROM orders WHERE id = '{id}'\")",
        ),
        CanonicalFinding(
            source="SAST",
            scanner_name="gordon-sast",
            cwe="CWE-89",
            severity="Critical",
            file="orders.py",
            line=98,
            func_name="get_orders",
            param=None,
            snippet="cursor.execute(f\"SELECT * FROM orders ORDER BY {sort}\")",
        ),
    ]
    dast_two_params = [
        CanonicalFinding(
            source="DAST",
            scanner_name="gordon-dast",
            cwe="CWE-89",
            severity="Critical",
            url="http://localhost:5000/api/orders?sort=1%27",
            canonical_path="/api/orders",
            method="GET",
            param="sort",
            payload="1'",
            evidence="sqlite3.OperationalError: near sort",
        ),
        CanonicalFinding(
            source="DAST",
            scanner_name="gordon-dast",
            cwe="CWE-89",
            severity="Critical",
            url="http://localhost:5000/api/orders?id=1%27",
            canonical_path="/api/orders",
            method="GET",
            param="id",
            payload="1'",
            evidence="sqlite3.OperationalError: near id",
        ),
    ]
    issues_b = fallback_correlate_findings(routes, sast_two_sinks, dast_two_params)
    assert len(issues_b) == 2
    by_param = {i.param: i for i in issues_b}
    assert by_param["id"].status == "Confirmed"
    assert by_param["id"].line == 88
    assert by_param["sort"].status == "Confirmed"
    assert by_param["sort"].line == 98


def test_multi_app_sqlite_isolation() -> None:
    """Bug 5 regression test: Primary app and unseen second app do not collide in SQLite."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "multi_app.db")
        store = DatabaseStore(db_path=db_path)

        shared_runtime_finding = CanonicalFinding(
            source="DAST",
            scanner_name="gordon-dast-phase-b",
            cwe="CWE-693",
            severity="Medium",
            url="http://localhost:5000/",
            canonical_path="/",
            method="GET",
            param="header:Content-Security-Policy",
            payload="Passive HTTP Header Audit",
            evidence="Missing Content-Security-Policy header",
        )

        # Scan App 1 ("target-web-shop")
        s1 = store.create_scan(app_name="target-web-shop", target_url="http://localhost:5000")
        store.save_findings(s1, [shared_runtime_finding], app_name="target-web-shop")
        issues_app1 = fallback_correlate_findings([], [], [shared_runtime_finding])
        store.upsert_issues(s1, issues_app1, app_name="target-web-shop")

        # Scan App 2 ("unseen-flask-app") with an identical Runtime-only finding fingerprint
        s2 = store.create_scan(app_name="unseen-flask-app", target_url="http://localhost:5000")
        store.save_findings(s2, [shared_runtime_finding], app_name="unseen-flask-app")
        issues_app2 = fallback_correlate_findings([], [], [shared_runtime_finding])
        store.upsert_issues(s2, issues_app2, app_name="unseen-flask-app")

        app1_rows = store.get_issues(app_name="target-web-shop")
        app2_rows = store.get_issues(app_name="unseen-flask-app")
        assert len(app1_rows) == 1
        assert len(app2_rows) == 1
        assert app1_rows[0].id != app2_rows[0].id


def test_subblock2_ui_dashboard_and_checkpoint1_slice() -> None:
    """
    Verify Sub-block 2 (`feat/b-api-ui`):
      - `GET /` serves `ui/index.html` containing Sarvam AI design tokens and Apple fluid spring inspector.
      - `POST /scans` with `seed_checkpoint_slice_if_empty=True` populates Confirmed, Code-only, Runtime-only,
        and B-2 Safe Decoys idempotently across consecutive runs.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "ui_slice.db")
        os.environ["GORDON_DB_PATH"] = db_path
        try:
            with TestClient(gordon_api_app) as client:
                # 1. Verify GET / serves ui/index.html with Sarvam + Apple design system
                ui_res = client.get("/")
                assert ui_res.status_code == 200
                assert "text/html" in ui_res.headers.get("content-type", "")
                html_body = ui_res.text
                assert "--color-sr-indigo-900" in html_body
                assert "--font-season-mix" in html_body
                assert "animateSheetSpring" in html_body
                assert "rubberband" in html_body

                # 2. Trigger Checkpoint 1 vertical slice twice and verify FR-6 idempotency
                scan1 = client.post(
                    "/scans",
                    json={
                        "app_name": "checkpoint1-demo",
                        "run_live_dast": False,
                        "seed_checkpoint_slice_if_empty": True,
                    },
                )
                assert scan1.status_code == 200
                s1_data = scan1.json()
                assert s1_data["confirmed_count"] == 2
                assert s1_data["code_only_count"] == 1
                assert s1_data["runtime_only_count"] == 2
                assert s1_data["safe_decoys_suppressed"] == 2

                scan2 = client.post(
                    "/scans",
                    json={
                        "app_name": "checkpoint1-demo",
                        "run_live_dast": False,
                        "seed_checkpoint_slice_if_empty": True,
                    },
                )
                assert scan2.status_code == 200
                s2_data = scan2.json()
                assert s2_data["total_issues"] == s1_data["total_issues"] == 5
        finally:
            os.environ.pop("GORDON_DB_PATH", None)


def test_full_e2e_mock_shop_scan_and_ui_ux_requirements() -> None:
    """
    Verify all fixed backend bugs and UI/UX hardening requirements:
      1. POST /scans on ./tests/mock_shop_app with run_live_dast=True runs AST RouteMapper,
         SAST, DecoyFilter, 2-phase in-process DAST, Correlator (including cross-file
         services/order_service.py helper correlation), and SCA reachability.
      2. GET /health reports server-isolated credentials, GET /favicon.ico returns SVG,
         and SPA routes (/privacy, /terms, /404, and unknown paths) respond properly.
      3. ui/index.html has zero emojis, zero em dashes, crisp radii (<= 6px), onboarding,
         scroll progress bar, back-to-top button, skeleton loaders, and error banner.
    """
    import re

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "e2e_mock_shop.db")
        os.environ["CYBERFORGE_DB_PATH"] = db_path
        try:
            with TestClient(gordon_api_app) as client:
                # 1. Verify UI HTML constraints
                ui_res = client.get("/")
                assert ui_res.status_code == 200
                html_text = ui_res.text

                # Zero em dashes or en dashes
                assert "\u2014" not in html_text
                assert "\u2013" not in html_text
                assert "&mdash;" not in html_text

                # Zero emojis (check supplementary pictographs and miscellaneous symbols)
                emoji_pattern = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]")
                assert emoji_pattern.search(html_text) is None

                # Crisp radii only (no 9999px pill radii)
                assert "9999px" not in html_text
                assert "--radius-xs: 2px" in html_text
                assert "--radius-sm: 4px" in html_text
                assert "--radius-md: 6px" in html_text

                # Required UI components present
                assert "scrollProgressBar" in html_text
                assert "backToTopBtn" in html_text
                assert "onboardingModal" in html_text
                assert "errorBanner" in html_text
                assert "viewPrivacy" in html_text
                assert "viewTerms" in html_text
                assert "view404" in html_text
                assert 'rel="icon"' in html_text

                # 2. Verify favicon, health credential isolation, privacy, terms, and 404 routes
                fav_res = client.get("/favicon.ico")
                assert fav_res.status_code == 200
                assert "image/svg+xml" in fav_res.headers.get("content-type", "")

                health_res = client.get("/health")
                assert health_res.status_code == 200
                h_json = health_res.json()
                assert h_json["credential_isolation"]["frontend_api_keys"] is False

                assert client.get("/privacy").status_code == 200
                assert client.get("/terms").status_code == 200
                assert client.get("/404").status_code == 404
                not_found_html = client.get("/nonexistent-page-route", headers={"Accept": "text/html"})
                assert not_found_html.status_code == 404
                assert "view404" in not_found_html.text

                # 3. Run full E2E scan on ./tests/mock_shop_app with live DAST
                scan_res = client.post(
                    "/scans",
                    json={
                        "target_url": "http://127.0.0.1:5000",
                        "source_dir": "./tests/mock_shop_app",
                        "run_live_dast": True,
                    },
                )
                assert scan_res.status_code == 200
                scan_data = scan_res.json()
                assert scan_data["confirmed_count"] >= 4
                assert scan_data["safe_decoys_suppressed"] >= 3

                # Verify cross-file helper correlation (services/order_service.py) is Confirmed
                issues_res = client.get("/issues")
                assert issues_res.status_code == 200
                issues_list = issues_res.json()
                confirmed_files = {
                    (i.get("file_path") or i.get("file") or "")
                    for i in issues_list
                    if i["status"] == "Confirmed"
                }
                assert any("order_service.py" in f for f in confirmed_files)

                # Verify decoys and SCA endpoints populate
                decoys_res = client.get("/decoys")
                assert decoys_res.status_code == 200
                assert len(decoys_res.json()) >= 3

                sca_res = client.get("/sca")
                assert sca_res.status_code == 200
                assert len(sca_res.json()) >= 1
        finally:
            os.environ.pop("CYBERFORGE_DB_PATH", None)


def test_adversarial_review_regression_suite() -> None:
    """
    Regression suite verifying all 7 issues caught during adversarial review:
      1. Zero leftover 'gordon' canary tokens or branding in engine/dast_scanner.py,
         core/config.py, and tests/demo_checkpoint1.py.
      2. tests/demo_checkpoint1.py runs cleanly and returns the expected 4-stage pipeline dict.
      3. ui/index.html binds to the real backend schema fields (`issue.link_reason`,
         `s.call_chain`, `diff.summary`, `Code only`, `Runtime only`, `CWE-798`, `CWE-693`).
      4. ui/index.html implements Apple fluid spring velocity handoff (`projectMomentum`,
         `initialVelocity`) and `@media (prefers-reduced-motion: reduce)` +
         `@media (prefers-reduced-transparency: reduce)`.
      5. GET /issues/{non-numeric} returns 404 JSON for API calls and 200 SPA HTML for
         browser document navigation instead of 422 Unprocessable Entity.
      6. GET /scans/compare returns both `summary` (`new_count`, `fixed_count`, `still_open_count`)
         and `counts` (`new`, `fixed`, `still_open`) plus issue arrays.
    """
    from pathlib import Path
    import subprocess
    import sys
    import json

    project_root = Path(__file__).resolve().parent.parent

    # 1. Verify zero 'gordon' occurrences in engine/dast_scanner.py, core/config.py, tests/demo_checkpoint1.py
    for rel_path in ("engine/dast_scanner.py", "core/config.py", "tests/demo_checkpoint1.py"):
        content = (project_root / rel_path).read_text(encoding="utf-8")
        assert "gordon" not in content.lower(), f"Found leftover 'gordon' string in {rel_path}"

    # 2. Verify tests/demo_checkpoint1.py executes end-to-end and exports accurate counts
    with tempfile.TemporaryDirectory() as demo_tmp:
        out_json = os.path.join(demo_tmp, "demo_out.json")
        proc = subprocess.run(
            [sys.executable, "-m", "tests.demo_checkpoint1", "--out", out_json],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            check=True,
        )
        assert proc.returncode == 0
        demo_report = json.loads(Path(out_json).read_text(encoding="utf-8"))
        assert len(demo_report["routes"]) in (16, 20)
        assert len(demo_report["sast_suppressed_decoys"]) in (10, 12)
        confirmed_demo = [i for i in demo_report["correlated_issues"] if i["status"] == "Confirmed"]
        assert len(confirmed_demo) == 6

    # 3 & 4. Verify UI schema bindings and Apple design velocity + reduced-motion media queries
    ui_html = (project_root / "ui/index.html").read_text(encoding="utf-8")
    assert "issue.link_reason" in ui_html
    assert "s.call_chain" in ui_html
    assert "diff.summary" in ui_html
    assert "projectMomentum" in ui_html
    assert "initialVelocity" in ui_html
    assert "@media (prefers-reduced-motion: reduce)" in ui_html
    assert "@media (prefers-reduced-transparency: reduce)" in ui_html
    assert '<option value="Code only">' in ui_html
    assert '<option value="Runtime only">' in ui_html
    assert '<option value="798">' in ui_html
    assert '<option value="693">' in ui_html

    # 5 & 6. Verify /issues/{issue_id} string handling and /scans/compare schema
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "review_reg.db")
        os.environ["CYBERFORGE_DB_PATH"] = db_path
        try:
            with TestClient(gordon_api_app) as client:
                s1 = client.post(
                    "/scans",
                    json={"app_name": "diff-app", "run_live_dast": False, "seed_checkpoint_slice_if_empty": True},
                ).json()
                s2 = client.post(
                    "/scans",
                    json={"app_name": "diff-app", "run_live_dast": False, "seed_checkpoint_slice_if_empty": True},
                ).json()

                diff_res = client.get(f"/scans/compare?scan_a={s1['scan_id']}&scan_b={s2['scan_id']}")
                assert diff_res.status_code == 200
                diff_data = diff_res.json()
                assert "summary" in diff_data
                assert "counts" in diff_data
                assert diff_data["summary"]["still_open_count"] == 5
                assert diff_data["counts"]["still_open"] == 5
                assert len(diff_data["still_open_issues"]) == 5

                # Non-numeric /issues/{id} for JSON client -> 404 (not 422)
                api_404 = client.get("/issues/non-numeric-id", headers={"Accept": "application/json"})
                assert api_404.status_code == 404

                # Non-numeric /issues/{id} for HTML browser client -> 200 SPA shell
                html_200 = client.get("/issues/non-numeric-id", headers={"Accept": "text/html"})
                assert html_200.status_code == 200
                assert "inspectorSheet" in html_200.text
        finally:
            os.environ.pop("CYBERFORGE_DB_PATH", None)
