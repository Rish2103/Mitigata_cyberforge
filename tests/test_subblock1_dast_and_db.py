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


# ===========================================================================
# Phase 2 Person B Tests: Task B2.1, Task B2.2, and Task B2.3
# ===========================================================================


def test_phase2_b21_adaptive_dast_scope_reduction() -> None:
    """
    Task B2.1: Verify DASTScanner enforces Adaptive Scope Reduction when
    `sast_findings` or `probe_plan` is supplied:
      - `PRUNED_SAFE` route (`/safe-about`) receives 0 active fuzzing probes.
      - `TARGETED_REDUCTION` route (`/orders` tainted only on `id` for `CWE-89`)
        only executes SQLi probes on `id` and skips XSS/CMDi/Redirect/Traversal.
      - `RUNTIME_DRIFT_EXTRA` route (`/legacy-drift?q=1`, discovered via HTML crawl
        and absent from AST routes) receives full 5-CWE active probing.
    """
    from engine.dast_scanner import DASTScanner, XSS_SCRIPT_CANARY

    probe_log: List[Tuple[str, str, Dict[str, str]]] = []
    vuln_Target = FastAPI()

    @vuln_Target.get("/", response_class=HTMLResponse)
    async def index_page() -> str:
        # Links to an unmapped runtime drift endpoint `/legacy-drift?q=hello`
        return '<html><body><a href="/legacy-drift?q=hello">Legacy</a></body></html>'

    @vuln_Target.get("/safe-about", response_class=HTMLResponse)
    async def safe_about(page: str = "1", theme: str = "dark") -> str:
        probe_log.append(("GET", "/safe-about", {"page": page, "theme": theme}))
        return f"<html><body>Safe About page={page}</body></html>"

    @vuln_Target.get("/orders", response_class=HTMLResponse)
    async def orders_ep(id: str = "1", sort: str = "asc") -> str:
        probe_log.append(("GET", "/orders", {"id": id, "sort": sort}))
        if "'" in id:
            return "<html><body>sqlite3.OperationalError: near \"'\": syntax error</body></html>"
        return f"<html><body>Order #{id}</body></html>"

    @vuln_Target.get("/legacy-drift", response_class=HTMLResponse)
    async def legacy_drift_ep(q: str = "hello") -> str:
        probe_log.append(("GET", "/legacy-drift", {"q": q}))
        return f"<html><body>Legacy search: {q}</body></html>"

    ast_routes = [
        RouteEntry(
            method="GET",
            path_pattern="/safe-about",
            file="app.py",
            func_name="safe_about",
            start_line=10,
            end_line=18,
            params=["page", "theme"],
            param_sources={"page": "query", "theme": "query"},
        ),
        RouteEntry(
            method="GET",
            path_pattern="/orders",
            file="app.py",
            func_name="orders_ep",
            start_line=20,
            end_line=32,
            params=["id", "sort"],
            param_sources={"id": "query", "sort": "query"},
        ),
    ]

    # SAST only flags CWE-89 on `id` in `/orders` (app.py:25)
    sast_findings = [
        CanonicalFinding(
            source="SAST",
            scanner_name="cyberforge-sast",
            cwe="CWE-89",
            title="SQL Injection in orders_ep",
            severity="Critical",
            confidence="High",
            file="app.py",
            line=25,
            func_name="orders_ep",
            param="id",
            snippet='cursor.execute(f"SELECT * FROM orders WHERE id = \'{id}\'")',
        )
    ]

    transport = httpx.ASGITransport(app=vuln_Target)
    scanner = DASTScanner(
        base_url="http://127.0.0.1:8000",
        transport=transport,
        enable_crawl=True,
        enable_passive_checks=True,
    )
    findings = asyncio.run(scanner.scan(routes=ast_routes, sast_findings=sast_findings))

    # 1. `/safe-about` was fetched ONCE for clean baseline, 0 active fuzzing probes sent!
    safe_requests = [params for _, path, params in probe_log if path == "/safe-about"]
    assert len(safe_requests) == 1, f"Expected 1 baseline request on PRUNED_SAFE route, got {len(safe_requests)}"

    # 2. `/orders` was only probed for CWE-89 on `id` (no XSS canary sent to `/orders` and `sort` untouched at baseline default "test")
    orders_requests = [params for _, path, params in probe_log if path == "/orders"]
    assert len(orders_requests) >= 2  # baseline + SQLi quote probe
    assert all(XSS_SCRIPT_CANARY not in p.get("id", "") for p in orders_requests)
    assert all(p.get("sort") == "test" for p in orders_requests)

    # 3. Crawled `/legacy-drift` is RUNTIME_DRIFT_EXTRA -> receives full probing including XSS canary
    drift_requests = [params for _, path, params in probe_log if path == "/legacy-drift"]
    assert any(XSS_SCRIPT_CANARY in p.get("q", "") for p in drift_requests)

    # 4. Both CWE-89 on `/orders` and CWE-79 on `/legacy-drift` were caught
    cwes_by_path = {(f.canonical_path, f.cwe) for f in findings}
    assert ("/orders", "CWE-89") in cwes_by_path
    assert ("/legacy-drift", "CWE-79") in cwes_by_path

    # 5. `scanner.last_scope_reduction` telemetry is populated
    report = scanner.last_scope_reduction
    assert report is not None
    assert report.naive_probe_count > report.reduced_probe_count
    assert report.probes_saved_count > 0
    assert report.runtime_drift_routes >= 1
    assert getattr(report, "drifted_routes", None) == report.runtime_drift_routes
    assert "O(" in getattr(report, "time_complexity_summary", "")


def test_phase2_b22_auto_verify_code_only_to_confirmed() -> None:
    """
    Task B2.2: Verify `engine/auto_verify.py` (`B-1` Code-Only -> Confirmed Active Verifier)
    synthesizes targeted diagnostic probes for `Code only` issues mapped to AST `RouteEntry`
    items, upgrades verified issues to `Confirmed`, sets `auto_verified = True`, attaches
    `dast_evidence` (`phase="B1-Auto-Verify"`), and recomputes `risk_score`.
    """
    from core.schemas import compute_issue_risk_score
    from engine.auto_verify import auto_verify_code_only_issues_sync

    routes = [
        RouteEntry(
            method="GET",
            path_pattern="/api/orders",
            file="orders.py",
            func_name="get_order",
            start_line=10,
            end_line=35,
            params=["id"],
            param_sources={"id": "query"},
        ),
        RouteEntry(
            method="GET",
            path_pattern="/api/redirect",
            file="auth.py",
            func_name="login_redirect",
            start_line=40,
            end_line=60,
            params=["next"],
            param_sources={"next": "query"},
        ),
    ]

    sast_sqli = CanonicalFinding(
        source="SAST",
        scanner_name="cyberforge-sast",
        cwe="CWE-89",
        title="SQL Injection in get_order",
        severity="Critical",
        confidence="High",
        file="orders.py",
        line=22,
        func_name="get_order",
        param="id",
        snippet='cursor.execute(f"SELECT * FROM orders WHERE id = {id}")',
    )
    sast_redir = CanonicalFinding(
        source="SAST",
        scanner_name="cyberforge-sast",
        cwe="CWE-601",
        title="Open Redirect in login_redirect",
        severity="Medium",
        confidence="High",
        file="auth.py",
        line=48,
        func_name="login_redirect",
        param="next",
        snippet="return RedirectResponse(url=next, status_code=302)",
    )
    sast_secret = CanonicalFinding(
        source="SAST",
        scanner_name="cyberforge-sast",
        cwe="CWE-798",
        title="Hardcoded Secret Key",
        severity="High",
        confidence="High",
        file="config.py",
        line=8,
        func_name="settings",
        snippet='SECRET_KEY = "sk_live_hardcoded"',
    )

    code_only_sqli = CorrelatedIssue(
        status="Code only",
        cwe="CWE-89",
        title=sast_sqli.title,
        severity="Critical",
        risk_score=compute_issue_risk_score("Code only", "Critical", "CWE-89"),
        file="orders.py",
        line=22,
        func_name="get_order",
        param="id",
        snippet=sast_sqli.snippet,
        sast_evidence=[sast_sqli],
        dast_evidence=[],
    )
    code_only_redir = CorrelatedIssue(
        status="Code only",
        cwe="CWE-601",
        title=sast_redir.title,
        severity="Medium",
        risk_score=compute_issue_risk_score("Code only", "Medium", "CWE-601"),
        file="auth.py",
        line=48,
        func_name="login_redirect",
        param="next",
        snippet=sast_redir.snippet,
        sast_evidence=[sast_redir],
        dast_evidence=[],
    )
    code_only_secret = CorrelatedIssue(
        status="Code only",
        cwe="CWE-798",
        title=sast_secret.title,
        severity="High",
        risk_score=compute_issue_risk_score("Code only", "High", "CWE-798"),
        file="config.py",
        line=8,
        func_name="settings",
        snippet=sast_secret.snippet,
        sast_evidence=[sast_secret],
        dast_evidence=[],
    )

    initial_sqli_score = code_only_sqli.risk_score
    transport = httpx.ASGITransport(app=build_mock_shop_asgi_app())

    upgraded = auto_verify_code_only_issues_sync(
        base_url="http://127.0.0.1:8000",
        routes=routes,
        issues=[code_only_sqli, code_only_redir, code_only_secret],
        transport=transport,
    )

    by_cwe = {i.cwe: i for i in upgraded}
    assert by_cwe["CWE-89"].status == "Confirmed"
    assert by_cwe["CWE-89"].auto_verified is True
    assert by_cwe["CWE-89"].risk_score > initial_sqli_score
    assert len(by_cwe["CWE-89"].dast_evidence) == 1
    assert by_cwe["CWE-89"].dast_evidence[0].phase == "B1-Auto-Verify"
    assert "B-1 Auto-Verify" in (by_cwe["CWE-89"].link_reason or "")

    assert by_cwe["CWE-601"].status == "Confirmed"
    assert by_cwe["CWE-601"].auto_verified is True
    assert len(by_cwe["CWE-601"].dast_evidence) == 1

    # CWE-798 is static-only and must remain `Code only`
    assert by_cwe["CWE-798"].status == "Code only"
    assert by_cwe["CWE-798"].auto_verified is False


def test_phase2_b23_api_scope_reduction_telemetry_and_get_scan_by_id() -> None:
    """
    Task B2.3: Verify `POST /scans` and `GET /scans/{scan_id}` expose the
    `scope_reduction` telemetry dictionary (`naive_probe_count`, `reduced_probe_count`,
    `probes_saved_count`, `scope_reduction_pct`, `exact_replica_routes`,
    `drifted_routes`, `time_complexity_summary`) for the Judge Complexity Banner.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "scope_telemetry.db")
        os.environ["CYBERFORGE_DB_PATH"] = db_path
        try:
            with TestClient(gordon_api_app) as client:
                post_res = client.post(
                    "/scans",
                    json={
                        "app_name": "telemetry-shop",
                        "run_live_dast": False,
                        "seed_checkpoint_slice_if_empty": True,
                    },
                )
                assert post_res.status_code == 200
                post_json = post_res.json()
                scan_id = post_json["scan_id"]

                for payload in (
                    post_json,
                    client.get(f"/scans/{scan_id}").json(),
                ):
                    sr = payload.get("scope_reduction")
                    assert sr is not None, "Expected scope_reduction in ScanSummary response"
                    assert sr["naive_probe_count"] > 0
                    assert sr["reduced_probe_count"] < sr["naive_probe_count"]
                    assert sr["probes_saved_count"] == (
                        sr["naive_probe_count"] - sr["reduced_probe_count"]
                    )
                    assert sr["scope_reduction_pct"] > 0
                    assert "exact_replica_routes" in sr
                    assert "drifted_routes" in sr
                    assert "time_complexity_summary" in sr
                    assert "O(" in sr["time_complexity_summary"]

                # Missing scan ID returns 404
                not_found = client.get("/scans/999999")
                assert not_found.status_code == 404
        finally:
            os.environ.pop("CYBERFORGE_DB_PATH", None)


# ===========================================================================
# Phase 3 Person B Tests: Task B3.1, Task B3.2, and Task B3.3
# ===========================================================================


def test_phase3_b31_sarif_v210_exporter_and_ci_gate_endpoints() -> None:
    """
    Task B3.1: Verify OASIS SARIF v2.1.0 Exporter (`api/sarif_exporter.py`),
    `GET /scans/{scan_id}/sarif`, `GET /export/sarif`, `GET /scans/{scan_id}/ci-gate`,
    and `GET /ci-gate`.
    """
    from api.sarif_exporter import evaluate_ci_gate

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "phase3_sarif.db")
        os.environ["CYBERFORGE_DB_PATH"] = db_path
        try:
            with TestClient(gordon_api_app) as client:
                # 1. Trigger a scan with Confirmed Critical/High issues
                scan_res = client.post(
                    "/scans",
                    json={
                        "app_name": "sarif-demo-shop",
                        "run_live_dast": False,
                        "seed_checkpoint_slice_if_empty": True,
                    },
                )
                assert scan_res.status_code == 200
                scan_id = scan_res.json()["scan_id"]

                # 2. Verify GET /scans/{scan_id}/sarif and GET /export/sarif return valid SARIF v2.1.0
                for sarif_url in (f"/scans/{scan_id}/sarif", "/export/sarif"):
                    sarif_res = client.get(sarif_url)
                    assert sarif_res.status_code == 200
                    sarif_doc = sarif_res.json()
                    assert sarif_doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
                    assert sarif_doc["version"] == "2.1.0"
                    assert len(sarif_doc["runs"]) == 1
                    run0 = sarif_doc["runs"][0]
                    assert run0["tool"]["driver"]["name"] == "CyberForge Correlate"
                    assert len(run0["results"]) >= 5
                    first_res = run0["results"][0]
                    assert "physicalLocation" in first_res["locations"][0]
                    props = first_res["properties"]
                    for required_prop in (
                        "status",
                        "url",
                        "param",
                        "payload",
                        "evidence",
                        "risk_score",
                        "fair_exposure_inr_lakhs",
                    ):
                        assert required_prop in props

                # 3. Verify GET /scans/{scan_id}/ci-gate and GET /ci-gate return FAIL (exit_code: 1)
                for gate_url in (f"/scans/{scan_id}/ci-gate", "/ci-gate"):
                    gate_res = client.get(gate_url)
                    assert gate_res.status_code == 200
                    gate_data = gate_res.json()
                    assert gate_data["status"] == "FAIL"
                    assert gate_data["exit_code"] == 1
                    assert gate_data["passed"] is False
                    assert gate_data["blocking_confirmed_count"] >= 2

                # 4. Verify evaluate_ci_gate returns PASS (exit_code: 0) when no Confirmed Critical/High or Reachable KEV SCA exist
                code_only_issue = CorrelatedIssue(
                    status="Code only",
                    cwe="CWE-798",
                    severity="High",
                    file="config.py",
                    line=10,
                )
                non_kev_sca = SCAFinding(
                    package_name="urllib3",
                    installed_version="1.26.0",
                    advisory_id="GHSA-test-0001",
                    cve_id="CVE-2023-0001",
                    reachability_status="Present-only",
                    in_cisa_kev=True,
                )
                pass_gate = evaluate_ci_gate(issues=[code_only_issue], sca_findings=[non_kev_sca])
                assert pass_gate["status"] == "PASS"
                assert pass_gate["exit_code"] == 0
                assert pass_gate["passed"] is True

                # 5. Verify Reachable CISA KEV SCA finding triggers FAIL (exit_code: 1)
                reachable_kev_sca = SCAFinding(
                    package_name="pyyaml",
                    installed_version="5.3.1",
                    advisory_id="GHSA-kev-9999",
                    cve_id="CVE-2020-14343",
                    reachability_status="Reachable",
                    in_cisa_kev=True,
                    call_chain=["POST /import -> load_yaml() -> yaml.load()"],
                )
                kev_fail_gate = evaluate_ci_gate(issues=[code_only_issue], sca_findings=[reachable_kev_sca])
                assert kev_fail_gate["status"] == "FAIL"
                assert kev_fail_gate["exit_code"] == 1
                assert kev_fail_gate["blocking_reachable_kev_sca_count"] == 1
        finally:
            os.environ.pop("CYBERFORGE_DB_PATH", None)


def test_phase3_b32_and_b33_ui_banner_remediation_diff_and_packaging() -> None:
    """
    Task B3.2 & B3.3: Verify `ui/index.html` contains the Judge Complexity & Scope Reduction
    Banner, Before/After Code Remediation Diff, 1-click SARIF v2.1.0 download, CI Gate badge,
    Live Storefront (:5000) link, and verify `Dockerfile`, `docker-compose.yml`,
    `.github/workflows/cyberforge-gate.yml`, and `README.md` exist and are valid.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    ui_html = (project_root / "ui/index.html").read_text(encoding="utf-8")

    # Task B3.2 UI verification
    for expected_token in (
        "judgeComplexityBanner",
        "Single-Pass AST O(N_ast + K_tainted_sinks)",
        "Naive Probes vs Reduced Probes",
        "% Active HTTP Traffic Saved",
        "EXACT_REPLICA",
        "RUNTIME_DRIFT_EXTRA",
        "buildBeforeAfterRemediationDiff",
        "Before / After Code Remediation Diff (B-4)",
        "B-1 Auto-Verified",
        "downloadJsonReport",
        "Export JSON",
        "downloadSarifReport",
        "Download SARIF v2.1.0",
        "http://localhost:5000",
    ):
        assert expected_token in ui_html, f"Missing expected UI token: {expected_token}"

    # Task B3.3 Docker & CI/CD packaging verification
    dockerfile = (project_root / "Dockerfile").read_text(encoding="utf-8")
    assert "uvicorn" in dockerfile
    assert "8000" in dockerfile

    compose_yml = (project_root / "docker-compose.yml").read_text(encoding="utf-8")
    assert "8000:8000" in compose_yml
    assert "5000:5000" in compose_yml
    assert "tests/mock_shop_app" in compose_yml

    workflow_yml = (project_root / ".github/workflows/cyberforge-gate.yml").read_text(encoding="utf-8")
    assert "pytest" in workflow_yml
    assert "/sarif" in workflow_yml
    assert "/ci-gate" in workflow_yml

    readme_md = (project_root / "README.md").read_text(encoding="utf-8")
    assert "docker compose up" in readme_md
    assert "SARIF v2.1.0" in readme_md


def test_phase4_b41_scan_diff_lifecycle_new_fixed_still_open_and_sarif_ci_gate_transition(
    tmp_path: Path,
) -> None:
    """
    Phase 4 (Task B4.1):
    Verifies full B-5 Scan Diff lifecycle (NEW, FIXED, STILL-OPEN) across 3 consecutive
    scans, SARIF v2.1.0 download fidelity, and CI/CD Gate FAIL -> PASS transition.
    """
    db_file = str(tmp_path / "phase4_diff_lifecycle.db")
    os.environ["GORDON_DB_PATH"] = db_file
    try:
        client = TestClient(gordon_api_app)

        seeded_routes = [
            {
                "method": "GET",
                "path_pattern": "/api/orders",
                "file": "orders.py",
                "func_name": "get_orders",
                "start_line": 10,
                "end_line": 22,
                "params": ["q"],
            },
            {
                "method": "GET",
                "path_pattern": "/api/search",
                "file": "search.py",
                "func_name": "search_items",
                "start_line": 30,
                "end_line": 42,
                "params": ["term"],
            },
            {
                "method": "POST",
                "path_pattern": "/api/diag",
                "file": "diag.py",
                "func_name": "run_diag",
                "start_line": 50,
                "end_line": 65,
                "params": ["host"],
            },
        ]

        # Scan 1 (Baseline): Confirmed CWE-89 on /api/orders + Confirmed CWE-79 on /api/search
        r1 = client.post(
            "/scans",
            json={
                "app_name": "phase4-shop",
                "target_url": "http://127.0.0.1:5000",
                "run_live_dast": False,
                "seeded_routes": seeded_routes,
                "seeded_sast_findings": [
                    {
                        "source": "SAST",
                        "cwe": "CWE-89",
                        "severity": "Critical",
                        "file": "orders.py",
                        "line": 15,
                        "func_name": "get_orders",
                        "param": "q",
                        "snippet": "conn.execute(f'SELECT * FROM orders WHERE q = {q}')",
                    },
                    {
                        "source": "SAST",
                        "cwe": "CWE-79",
                        "severity": "High",
                        "file": "search.py",
                        "line": 35,
                        "func_name": "search_items",
                        "param": "term",
                        "snippet": "return f'<div>{term}</div>'",
                    },
                ],
                "seeded_dast_findings": [
                    {
                        "source": "DAST",
                        "cwe": "CWE-89",
                        "severity": "Critical",
                        "url": "http://127.0.0.1:5000/api/orders?q=1",
                        "canonical_path": "/api/orders",
                        "method": "GET",
                        "param": "q",
                        "payload": "' OR '1'='1",
                        "evidence": "sqlite3.OperationalError",
                    },
                    {
                        "source": "DAST",
                        "cwe": "CWE-79",
                        "severity": "High",
                        "url": "http://127.0.0.1:5000/api/search?term=x",
                        "canonical_path": "/api/search",
                        "method": "GET",
                        "param": "term",
                        "payload": "<script>alert(1)</script>",
                        "evidence": "Unescaped reflection",
                    },
                ],
            },
        )
        assert r1.status_code == 200
        scan1_id = r1.json()["scan_id"]

        # Verify Scan 1 CI Gate blocks (FAIL, exit_code=1)
        gate1 = client.get(f"/scans/{scan1_id}/ci-gate")
        assert gate1.status_code == 200
        assert gate1.json()["status"] == "FAIL"
        assert gate1.json()["exit_code"] == 1
        assert gate1.json()["passed"] is False
        assert gate1.json()["blocking_confirmed_count"] == 2

        # Scan 2 (Evolution): CWE-89 fixed (FIXED), CWE-79 remains (STILL-OPEN), CWE-78 introduced (NEW)
        r2 = client.post(
            "/scans",
            json={
                "app_name": "phase4-shop",
                "target_url": "http://127.0.0.1:5000",
                "run_live_dast": False,
                "seeded_routes": seeded_routes,
                "seeded_sast_findings": [
                    {
                        "source": "SAST",
                        "cwe": "CWE-79",
                        "severity": "High",
                        "file": "search.py",
                        "line": 35,
                        "func_name": "search_items",
                        "param": "term",
                        "snippet": "return f'<div>{term}</div>'",
                    },
                    {
                        "source": "SAST",
                        "cwe": "CWE-78",
                        "severity": "Critical",
                        "file": "diag.py",
                        "line": 56,
                        "func_name": "run_diag",
                        "param": "host",
                        "snippet": "subprocess.check_output(f'ping -c 1 {host}', shell=True)",
                    },
                ],
                "seeded_dast_findings": [
                    {
                        "source": "DAST",
                        "cwe": "CWE-79",
                        "severity": "High",
                        "url": "http://127.0.0.1:5000/api/search?term=x",
                        "canonical_path": "/api/search",
                        "method": "GET",
                        "param": "term",
                        "payload": "<script>alert(1)</script>",
                        "evidence": "Unescaped reflection",
                    },
                    {
                        "source": "DAST",
                        "cwe": "CWE-78",
                        "severity": "Critical",
                        "url": "http://127.0.0.1:5000/api/diag",
                        "canonical_path": "/api/diag",
                        "method": "POST",
                        "param": "host",
                        "payload": "127.0.0.1; id",
                        "evidence": "uid=0(root)",
                    },
                ],
            },
        )
        assert r2.status_code == 200
        scan2_id = r2.json()["scan_id"]

        # Compare Scan 1 -> Scan 2 via /scans/compare
        diff_resp = client.get(f"/scans/compare?base={scan1_id}&target={scan2_id}")
        assert diff_resp.status_code == 200
        diff_data = diff_resp.json()
        assert diff_data["summary"]["new_count"] == 1
        assert diff_data["summary"]["fixed_count"] == 1
        assert diff_data["summary"]["still_open_count"] == 1
        assert diff_data["new_issues"][0]["cwe"] == "CWE-78"
        assert diff_data["fixed_issues"][0]["cwe"] == "CWE-89"
        assert diff_data["still_open_issues"][0]["cwe"] == "CWE-79"

        # Scan 3 (Remediated): Only Medium Runtime-only header finding remains -> CI Gate PASS
        r3 = client.post(
            "/scans",
            json={
                "app_name": "phase4-shop",
                "target_url": "http://127.0.0.1:5000",
                "run_live_dast": False,
                "seeded_routes": seeded_routes,
                "seeded_sast_findings": [],
                "seeded_dast_findings": [
                    {
                        "source": "DAST",
                        "cwe": "CWE-693",
                        "severity": "Medium",
                        "url": "http://127.0.0.1:5000/api/orders",
                        "canonical_path": "/api/orders",
                        "method": "GET",
                        "evidence": "Missing Content-Security-Policy header",
                    }
                ],
            },
        )
        assert r3.status_code == 200
        scan3_id = r3.json()["scan_id"]

        gate3 = client.get(f"/scans/{scan3_id}/ci-gate")
        assert gate3.status_code == 200
        assert gate3.json()["status"] == "PASS"
        assert gate3.json()["exit_code"] == 0
        assert gate3.json()["passed"] is True
    finally:
        os.environ.pop("GORDON_DB_PATH", None)


def test_phase4_sync2_single_pass_ast_and_unseen_polyglot_e2e(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Phase 4 (Sync #2 Verification):
    1. Verifies POST /scans executes RouteMapper.scan() strictly once (single-pass AST O(N_ast)).
    2. Verifies 3-hop helper call chain correlation through the FastAPI /scans endpoint.
    3. Verifies non-loopback LAN IPs (e.g. 192.168.60.139) are rejected with HTTP 403.
    """
    unseen_dir = tmp_path / "unseen_app"
    unseen_dir.mkdir(parents=True, exist_ok=True)
    (unseen_dir / "app.py").write_text(
        """
from flask import Flask, request
from service import step1_lookup

app = Flask(__name__)

@app.route("/api/v1/ledger", methods=["GET"])
def read_ledger():
    acct = request.args.get("acct", "")
    return step1_lookup(acct)
""",
        encoding="utf-8",
    )
    (unseen_dir / "service.py").write_text(
        """
from repository import step2_query

def step1_lookup(acct):
    return step2_query(acct)
""",
        encoding="utf-8",
    )
    (unseen_dir / "repository.py").write_text(
        """
import sqlite3

def step2_query(acct):
    conn = sqlite3.connect("ledger.db")
    return conn.execute(f"SELECT balance FROM accounts WHERE acct = '{acct}'")
""",
        encoding="utf-8",
    )

    from engine.route_mapper import RouteMapper

    scan_call_count = 0
    orig_scan = RouteMapper.scan

    def tracked_scan(self):
        nonlocal scan_call_count
        scan_call_count += 1
        return orig_scan(self)

    monkeypatch.setattr(RouteMapper, "scan", tracked_scan)

    db_file = str(tmp_path / "phase4_sync2.db")
    os.environ["GORDON_DB_PATH"] = db_file
    try:
        client = TestClient(gordon_api_app)

        # Reject LAN IP 192.168.60.139 with HTTP 403
        lan_blocked = client.post(
            "/scans",
            json={"target_url": "http://192.168.60.139:8000", "run_live_dast": False},
        )
        assert lan_blocked.status_code == 403

        # Run full scan against unseen_dir with seeded DAST proof on /api/v1/ledger
        resp = client.post(
            "/scans",
            json={
                "app_name": "unseen-ledger",
                "target_url": "http://127.0.0.1:5000",
                "source_dir": str(unseen_dir),
                "run_live_dast": False,
                "seeded_dast_findings": [
                    {
                        "source": "DAST",
                        "cwe": "CWE-89",
                        "severity": "Critical",
                        "url": "http://127.0.0.1:5000/api/v1/ledger?acct=101",
                        "canonical_path": "/api/v1/ledger",
                        "method": "GET",
                        "param": "acct",
                        "payload": "' OR '1'='1",
                        "evidence": "sqlite3.OperationalError",
                    }
                ],
            },
        )
        assert resp.status_code == 200
        # RouteMapper.scan() must be invoked strictly once across the entire pipeline
        assert scan_call_count == 1
        body = resp.json()
        assert body["confirmed_count"] == 1
        issues_resp = client.get(f"/issues?scan_id={body['scan_id']}")
        assert issues_resp.status_code == 200
        confirmed = [i for i in issues_resp.json() if i["status"] == "Confirmed"]
        assert len(confirmed) == 1
        assert confirmed[0]["file"] == "repository.py"
        assert "repository.py:6" in confirmed[0]["link_reason"]
    finally:
        os.environ.pop("GORDON_DB_PATH", None)



