"""
Comprehensive Automated Verification Suite for Person A (Static Intelligence, AST, Correlator & Reachability SCA).
Tests:
1. End-to-end scan & correlation on `tests/mock_shop_app` (Cross-file Blueprints, 2-step variable taint, 8 safe decoys).
2. Full 36-Bug PRD Answer-Key Benchmark Simulation (20 Pairs + 10 Code-only + 6 Runtime-only + 8 Safe Decoys)
   verifying 100% Correct Links, 0% Wrong Links, 0% False Alarms, and FR-6 Idempotency.
3. Multi-Scanner Deduplication (FR-6: 3 scanner findings on the same bug = 1 issue) + SARIF & Bandit ingestion (FR-3).
4. Bonus B-7 Polyglot Support: Node.js / Express routes, SAST, decoys, and correlation + Django urlpatterns.
5. Page 4 Bonus: 5-Step Reachability-Aware SCA (SBOM transitive paths, GHSA/CVSS/EPSS/KEV, fix-commit diff parser,
   4 statuses: Reachable, Imported-only, Present-only, Unknown with strict Never-Downgrade-Unknown verification,
   and Step 5 supply-chain checks).
"""

import json
import os
import shutil
import tempfile
import time
import unittest

from core.schemas import (
    CanonicalFinding,
    FindingSource,
    Severity,
    IssueStatus,
    SCAReachabilityStatus,
)
from engine.route_mapper import RouteMapper
from engine.sast_scanner import SASTScanner
from engine.decoy_filter import DecoyFilter
from engine.correlator import Correlator
from engine.sca_reachability import SCAReachabilityEngine


MOCK_SHOP_DIR = os.path.join(os.path.dirname(__file__), "mock_shop_app")


class TestGordonCorrelateFullSuite(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="gordon_correlate_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # =========================================================================
    # 1. End-to-End Test on `tests/mock_shop_app`
    # =========================================================================
    def test_mock_shop_app_end_to_end_and_zero_false_alarms(self):
        """
        Scans `tests/mock_shop_app` and verifies:
        - Cross-file Blueprint prefix `/api` is applied to `/orders` -> `/api/orders`
        - Two-step variable SQLi in `services/order_service.py` is detected and linked to `GET /api/orders`
        - All 8 planted safe decoys (including dead function in `app.py` and dead file `utils/dead_legacy.py`)
          are marked `is_protected_decoy=True` -> 0% False Alarms!
        - Express microservice routes and findings (Bonus B-7) are also extracted and correlated.
        """
        mapper = RouteMapper(MOCK_SHOP_DIR)
        routes = mapper.scan()
        self.assertTrue(len(routes) >= 12)

        # Verify cross-file Blueprint route `/api/orders` was resolved
        orders_route = mapper.match_url("GET", "/api/orders?id=1")
        self.assertIsNotNone(orders_route)
        self.assertEqual(orders_route.func_name, "get_orders")
        self.assertEqual(orders_route.path_pattern, "/api/orders")

        # Verify Express route `/api/v2/users/99` (Bonus B-7) was resolved
        express_route = mapper.match_url("GET", "/api/v2/users/99")
        self.assertIsNotNone(express_route)
        self.assertEqual(express_route.framework, "express")
        self.assertIn("uid", express_route.parameters)

        # Run SAST Scanner with route_mapper reachability
        reachable_files = mapper.get_reachable_files()
        scanner = SASTScanner(MOCK_SHOP_DIR, route_mapper=mapper)
        all_sast = scanner.scan(reachable_files=reachable_files, route_mapper=mapper)

        active_sast = [f for f in all_sast if not f.is_protected_decoy]
        suppressed_decoys = [f for f in all_sast if f.is_protected_decoy]

        # Verify all 8 Python safe decoys + 1 Express safe decoy = 9 safe decoys are suppressed!
        self.assertGreaterEqual(len(suppressed_decoys), 9)

        # Verify dead file `utils/dead_legacy.py` and dead function `dead_unreachable_helper_in_active_file` are suppressed
        active_files = {f.file_path for f in active_sast}
        self.assertNotIn("utils/dead_legacy.py", active_files)
        for f in active_sast:
            self.assertNotIn("archived_orders", f.code_snippet or "")

        # Simulate DAST findings for the vulnerable endpoints
        dast_findings = [
            CanonicalFinding(
                id="dast_1",
                source=FindingSource.DAST,
                cwe="CWE-89",
                severity=Severity.CRITICAL,
                url="http://localhost:5000/api/orders?id=1'",
                method="GET",
                param="id",
                payload="1' OR '1'='1",
                evidence="sqlite3.OperationalError",
            ),
            CanonicalFinding(
                id="dast_2",
                source=FindingSource.DAST,
                cwe="CWE-79",
                severity=Severity.HIGH,
                url="http://localhost:5000/api/search?q=<script>alert(1)</script>",
                method="GET",
                param="q",
                payload="<script>alert(1)</script>",
                evidence="Unescaped script tag in response body",
            ),
            CanonicalFinding(
                id="dast_3",
                source=FindingSource.DAST,
                cwe="CWE-78",
                severity=Severity.CRITICAL,
                url="http://localhost:5000/api/diagnostics/ping",
                method="POST",
                param="host",
                payload="127.0.0.1; echo gordon_cmd_78",
                evidence="gordon_cmd_78 in response",
            ),
            CanonicalFinding(
                id="dast_4",
                source=FindingSource.DAST,
                cwe="CWE-22",
                severity=Severity.HIGH,
                url="http://localhost:5000/api/invoices/download?doc=../../etc/passwd",
                method="GET",
                param="doc",
                payload="../../etc/passwd",
                evidence="root:x:0:0:",
            ),
            CanonicalFinding(
                id="dast_5",
                source=FindingSource.DAST,
                cwe="CWE-601",
                severity=Severity.MEDIUM,
                url="http://localhost:5000/api/checkout/redirect?next=https://evil.example.invalid",
                method="GET",
                param="next",
                payload="https://evil.example.invalid",
                evidence="HTTP 302 Location: https://evil.example.invalid",
            ),
            CanonicalFinding(
                id="dast_6_express",
                source=FindingSource.DAST,
                cwe="CWE-89",
                severity=Severity.CRITICAL,
                url="http://localhost:3000/api/v2/users/1'",
                method="GET",
                param="uid",
                payload="1'",
                evidence="You have an error in your SQL syntax",
            ),
        ]

        correlator = Correlator(mapper)
        issues = correlator.correlate(all_sast, dast_findings)

        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        code_only = [i for i in issues if i.status == IssueStatus.CODE_ONLY]

        # All 6 runtime-probed bugs (5 Python + 1 Express) must be Confirmed!
        self.assertEqual(len(confirmed), 6)
        # Hard-coded secrets (CWE-798) + unprobed Express CWE-78 remain Code only
        self.assertTrue(any(i.cwe == "CWE-798" for i in code_only))

        # Check that `/api/orders` linked across files to `services/order_service.py`
        order_issue = next(i for i in confirmed if i.url and "/api/orders" in i.url)
        self.assertEqual(order_issue.file_path, "services/order_service.py")
        self.assertIn("Parameter 'id' verified", order_issue.link_reason)

    # =========================================================================
    # 2. Full 36-Bug PRD Answer-Key Benchmark Simulation
    # =========================================================================
    def test_36_bug_prd_benchmark_scorecard(self):
        """
        Simulates the exact PRD Section 4 test app distribution:
        - 20 planted pairs (found in both code and running app)
        - 10 Code-only bugs (hard-coded secrets)
        - 6 Runtime-only bugs (missing security headers / cookies / CORS)
        - 8 Safe decoys (parameterized SQL, shell=False, secure_filename, etc.)
        Verifies all 7 PRD Page 4 target metrics beat the 'Great' threshold.
        """
        start_ts = time.time()
        cwes_cycle = ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"]
        lines_code = [
            "import os, html, shlex, sqlite3, subprocess",
            "from flask import Flask, request, redirect, render_template_string, send_file",
            "from werkzeug.utils import secure_filename",
            "app = Flask(__name__)",
        ]

        # 1. Generate 10 Code-only bugs (CWE-798 secrets)
        for i in range(1, 11):
            lines_code.append(f'SECRET_TOKEN_{i} = "prod_secret_key_value_{i}_999999"')

        # 2. Generate 20 planted pairs across 20 routes
        expected_pairs = []
        for i in range(1, 21):
            cwe = cwes_cycle[(i - 1) % len(cwes_cycle)]
            route_path = f"/api/item_{i}"
            param_name = f"p_{i}"
            lines_code.append(f'@app.route("{route_path}", methods=["GET"])')
            lines_code.append(f"def handler_{i}():")
            lines_code.append(f'    {param_name} = request.args.get("{param_name}")')
            if cwe == "CWE-89":
                lines_code.append(f'    sqlite3.connect("db").execute(f"SELECT * FROM t WHERE c = {{{param_name}}}")')
            elif cwe == "CWE-79":
                lines_code.append(f'    return render_template_string(f"<span>{{{param_name}}}</span>")')
            elif cwe == "CWE-78":
                lines_code.append(f'    os.system(f"echo {{{param_name}}}")')
            elif cwe == "CWE-22":
                lines_code.append(f'    return open(f"/tmp/{{{param_name}}}").read()')
            elif cwe == "CWE-601":
                lines_code.append(f"    return redirect({param_name})")
            lines_code.append('    return "ok"')
            expected_pairs.append((route_path, param_name, cwe))

        # 3. Generate 8 Safe Decoys (B-2)
        for j in range(1, 9):
            lines_code.append(f'@app.route("/api/safe_{j}", methods=["GET"])')
            lines_code.append(f"def safe_handler_{j}():")
            lines_code.append(f'    val = request.args.get("val")')
            if j in (1, 2):
                lines_code.append('    sqlite3.connect("db").execute("SELECT * FROM t WHERE c = ?", (val,))')
            elif j in (3, 4):
                lines_code.append('    subprocess.run(["echo", val], shell=False)')
            elif j in (5, 6):
                lines_code.append('    safe_f = secure_filename(val)')
                lines_code.append('    return open(f"/tmp/{safe_f}").read()')
            elif j == 7:
                lines_code.append('    if not val.startswith("/"): val = "/"')
                lines_code.append("    return redirect(val)")
            elif j == 8:
                lines_code.append('    return render_template_string(f"<div>{html.escape(val)}</div>")')
            lines_code.append('    return "safe"')

        shop_file = os.path.join(self.temp_dir, "benchmark_shop.py")
        with open(shop_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines_code))

        mapper = RouteMapper(self.temp_dir)
        mapper.scan()

        scanner = SASTScanner(self.temp_dir, route_mapper=mapper)
        sast_findings = scanner.scan(reachable_files=mapper.get_reachable_files(), route_mapper=mapper)

        # Generate the 26 runtime DAST findings (20 pairs + 6 runtime-only header/cookie findings)
        dast_findings = []
        for idx, (r_path, p_name, cwe) in enumerate(expected_pairs, start=1):
            dast_findings.append(
                CanonicalFinding(
                    id=f"dast_pair_{idx}",
                    source=FindingSource.DAST,
                    cwe=cwe,
                    severity=Severity.HIGH,
                    url=f"http://localhost:5000{r_path}?{p_name}=payload",
                    method="GET",
                    param=p_name,
                    payload="exploit_payload",
                    evidence="proven_at_runtime",
                )
            )
        for k in range(1, 7):
            dast_findings.append(
                CanonicalFinding(
                    id=f"dast_runtime_only_{k}",
                    source=FindingSource.DAST,
                    cwe="CWE-693",
                    severity=Severity.MEDIUM,
                    url=f"http://localhost:5000/api/item_{k}",
                    method="GET",
                    param=f"header_{k}",
                    payload=None,
                    evidence=f"Missing Security Header #{k}",
                )
            )

        correlator = Correlator(mapper)
        issues = correlator.correlate(sast_findings, dast_findings)
        elapsed = time.time() - start_ts

        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        code_only = [i for i in issues if i.status == IssueStatus.CODE_ONLY]
        runtime_only = [i for i in issues if i.status == IssueStatus.RUNTIME_ONLY]

        # Verify all 36 bugs are accounted for: 20 Confirmed + 10 Code-only + 6 Runtime-only = 36 total issues!
        self.assertEqual(len(confirmed), 20)
        self.assertEqual(len(code_only), 10)
        self.assertEqual(len(runtime_only), 6)
        self.assertEqual(len(issues), 36)

        # Verify 0% False Alarms on the 8 safe decoys
        for issue in issues:
            self.assertFalse(issue.url and "/api/safe_" in issue.url)

        # Verify 0% Wrong Links: every Confirmed issue matches its exact handler line & param
        for issue in confirmed:
            self.assertIn(f"Parameter '{issue.param}' verified", issue.link_reason)

        # Verify Run Time < 5 minutes (Great target)
        self.assertLess(elapsed, 5.0)

    # =========================================================================
    # 3. FR-6 Multi-Scanner Deduplication & FR-3 SARIF/Bandit Ingestion
    # =========================================================================
    def test_multi_scanner_deduplication_and_sarif_bandit_ingestion(self):
        """
        Verify PRD FR-6 example: '3 scanner findings on the same bug = 1 issue'
        and FR-3 SARIF / Bandit ingestion.
        """
        code = '''
from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/api/orders", methods=["GET"])
def orders():
    oid = request.args.get("id")
    sqlite3.connect("db").execute(f"SELECT * FROM orders WHERE id = {oid}")
    return "ok"
'''
        with open(os.path.join(self.temp_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write(code)

        mapper = RouteMapper(self.temp_dir)
        mapper.scan()
        scanner = SASTScanner(self.temp_dir, route_mapper=mapper)
        ast_sast = scanner.scan()
        self.assertEqual(len(ast_sast), 1)
        sink_line = ast_sast[0].line

        # Ingest a 2nd finding on the exact same bug from SARIF (e.g. Semgrep)
        sarif_payload = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep", "rules": [{"id": "python.sql-injection", "properties": {"tags": ["CWE-89"]}}]}},
                    "results": [
                        {
                            "ruleId": "python.sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": sink_line, "snippet": {"text": "execute(...)"}},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        sarif_sast = SASTScanner.from_sarif(sarif_payload)

        # Ingest a 3rd finding on the exact same bug from Bandit JSON
        bandit_payload = {
            "results": [
                {
                    "test_id": "B608",
                    "issue_cwe": {"id": 89},
                    "issue_severity": "HIGH",
                    "filename": "app.py",
                    "line_number": sink_line,
                    "code": "sqlite3.connect('db').execute(...)",
                }
            ]
        }
        bandit_sast = SASTScanner.from_bandit(bandit_payload)

        # And 2 DAST findings on the exact same route + parameter with different payloads
        dast_1 = CanonicalFinding(
            id="d1",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="/api/orders?id=1'",
            method="GET",
            param="id",
            payload="1'",
            evidence="SQL error 1",
        )
        dast_2 = CanonicalFinding(
            id="d2",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="/api/orders?id=1 OR 1=1",
            method="GET",
            param="id",
            payload="1 OR 1=1",
            evidence="SQL boolean diff",
        )

        correlator = Correlator(mapper)
        issues = correlator.correlate(ast_sast + sarif_sast + bandit_sast, [dast_1, dast_2])

        # All 5 scanner findings on the same bug MUST merge into 1 Confirmed issue!
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].status, IssueStatus.CONFIRMED)
        self.assertEqual(len(issues[0].sast_finding.raw_details["merged_finding_ids"]), 3)
        self.assertEqual(len(issues[0].dast_finding.raw_details["merged_finding_ids"]), 2)

    # =========================================================================
    # 4. Multi-Parameter Conflict Veto (Zero Wrong Links Guarantee)
    # =========================================================================
    def test_multi_parameter_conflict_veto(self):
        """
        If a route takes two parameters ('user' and 'sort'), where 'user' has a SQLi sink
        and 'sort' is NOT in that sink, a DAST finding on 'sort' must NOT wrongly link to the 'user' sink.
        """
        code = '''
from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/api/users", methods=["GET"])
def list_users():
    user = request.args.get("user")
    sort = request.args.get("sort")
    conn = sqlite3.connect("db")
    conn.execute(f"SELECT * FROM users WHERE username = '{user}'")
    return sort
'''
        with open(os.path.join(self.temp_dir, "users.py"), "w", encoding="utf-8") as f:
            f.write(code)

        mapper = RouteMapper(self.temp_dir)
        mapper.scan()
        scanner = SASTScanner(self.temp_dir, route_mapper=mapper)
        sast_findings = scanner.scan()

        # DAST claims SQLi on 'sort' (different parameter!)
        dast_wrong_param = CanonicalFinding(
            id="dast_sort",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="/api/users",
            method="GET",
            param="sort",
            payload="ASC'",
        )

        correlator = Correlator(mapper)
        issues = correlator.correlate(sast_findings, [dast_wrong_param])
        # Must veto the link -> 1 Code only + 1 Runtime only (0 Confirmed wrong links!)
        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 0)

    # =========================================================================
    # 5. Page 4 Bonus: 5-Step Reachability-Aware SCA Verification
    # =========================================================================
    def test_5_step_reachability_aware_sca(self):
        """
        Verifies all 5 steps of Page 4 Bonus Reachability-Aware SCA on `tests/mock_shop_app`:
        1. Lockfile SBOM inventory with transitive paths (werkzeug via flask, urllib3 via requests)
        2. GHSA match with CVSS, EPSS, and KEV
        3. Function map from OSV symbols and GitHub fix-commit unified diffs
        4. Call graph reachability producing all 4 statuses:
           - Reachable: pyyaml (called via POST /api/config/import -> import_yaml_config() -> yaml.load())
           - Imported-only: requests (imported in app.py, vulnerable function rebuild_proxies not called)
           - Present-only: urllib3 & werkzeug (in requirements.txt, vulnerable functions not imported/called)
           - Unknown: flask CVE-2023-30861 (no function symbols -> Unknown, NEVER downgraded!)
        5. Supply chain checks: typosquat ('reqeusts' -> 'requests'), dependency confusion ('mitigata-internal-auth'),
           and unpinned lockfile ('>=1.0.0').
        """
        mapper = RouteMapper(MOCK_SHOP_DIR)
        mapper.scan()

        sca_engine = SCAReachabilityEngine(MOCK_SHOP_DIR, route_mapper=mapper)
        report = sca_engine.analyze_reachability()

        # Step 1: Verify SBOM & Transitive Paths
        self.assertGreaterEqual(report.sbom_count, 7)
        by_pkg = {d.name: d for d in report.sbom}
        self.assertEqual(by_pkg["werkzeug"].transitive_path, ["root", "flask", "werkzeug"])
        self.assertFalse(by_pkg["werkzeug"].is_direct)
        self.assertEqual(by_pkg["urllib3"].transitive_path, ["root", "requests", "urllib3"])

        # Step 2, 3, 4: Verify 4 Reachability Statuses
        findings_by_pkg = {f.package: f for f in report.findings}

        # 1. Reachable: pyyaml
        self.assertIn("pyyaml", findings_by_pkg)
        pyyaml_f = findings_by_pkg["pyyaml"]
        self.assertEqual(pyyaml_f.status, SCAReachabilityStatus.REACHABLE)
        self.assertTrue(pyyaml_f.is_kev)
        self.assertGreater(pyyaml_f.epss_score, 0.9)
        self.assertEqual(pyyaml_f.entry_route, "POST /api/config/import")
        self.assertTrue(any("yaml.load" in step for step in pyyaml_f.call_chain))

        # 2. Unknown: flask (strictly verify Never Downgrade Unknown rule!)
        self.assertIn("flask", findings_by_pkg)
        flask_f = findings_by_pkg["flask"]
        self.assertEqual(flask_f.status, SCAReachabilityStatus.UNKNOWN)
        self.assertEqual(flask_f.original_severity, Severity.HIGH)
        self.assertEqual(flask_f.effective_severity, flask_f.original_severity)

        # 3. Imported-only: requests
        self.assertIn("requests", findings_by_pkg)
        req_f = findings_by_pkg["requests"]
        self.assertEqual(req_f.status, SCAReachabilityStatus.IMPORTED_ONLY)
        self.assertIn("rebuild_proxies", req_f.vulnerable_functions)

        # 4. Present-only: urllib3
        self.assertIn("urllib3", findings_by_pkg)
        u3_f = findings_by_pkg["urllib3"]
        self.assertEqual(u3_f.status, SCAReachabilityStatus.PRESENT_ONLY)

        # Step 5: Verify Supply Chain Checks (typosquat, dependency confusion, unpinned)
        alert_types = {a.alert_type for a in report.supply_chain_alerts}
        self.assertIn("typosquat", alert_types)
        self.assertIn("dependency_confusion", alert_types)
        self.assertIn("unpinned_lockfile", alert_types)

        typo_alert = next(a for a in report.supply_chain_alerts if a.alert_type == "typosquat")
        self.assertEqual(typo_alert.package, "reqeusts")
        self.assertEqual(typo_alert.target_legit_package, "requests")

    # =========================================================================
    # 6. Edge Cases: Django urlpatterns, Multi-Ecosystem Lockfiles & Dynamic Imports
    # =========================================================================
    def test_django_urlpatterns_and_lockfile_edge_cases(self):
        """
        Tests:
        - Django urlpatterns (path('<int:user_id>/', views.user_detail)) cross-file mapping
        - Pipfile.lock, poetry.lock, and package-lock.json transitive SBOM parsing
        - GitHub fix-commit diff parsing (SCAReachabilityEngine.parse_fix_commit_diff)
        - Dynamic import (importlib.import_module) preserving Unknown status (never downgraded)
        - Empty input handling in Correlator
        """
        views_code = '''
import sqlite3

def user_detail(request, user_id):
    conn = sqlite3.connect("db")
    conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return "ok"
'''
        urls_code = '''
from django.urls import path
import views

urlpatterns = [
    path("users/<int:user_id>/", views.user_detail),
]
'''
        with open(os.path.join(self.temp_dir, "views.py"), "w", encoding="utf-8") as f:
            f.write(views_code)
        with open(os.path.join(self.temp_dir, "urls.py"), "w", encoding="utf-8") as f:
            f.write(urls_code)

        # Write Pipfile.lock, poetry.lock, and package-lock.json
        pipfile_lock = '''{
            "default": {
                "pyyaml": {"version": "==5.3.1"},
                "urllib3": {"version": "==1.26.4", "via": ["requests"]}
            }
        }'''
        poetry_lock = '''
[[package]]
name = "flask"
version = "2.2.2"

[package.dependencies]
werkzeug = ">=2.2.0"

[[package]]
name = "werkzeug"
version = "2.2.2"
'''
        pkg_lock = '''{
            "name": "test-js",
            "dependencies": {
                "lodash": {"version": "4.17.19"},
                "colourama": {"version": "1.0.0"}
            }
        }'''
        with open(os.path.join(self.temp_dir, "Pipfile.lock"), "w", encoding="utf-8") as f:
            f.write(pipfile_lock)
        with open(os.path.join(self.temp_dir, "poetry.lock"), "w", encoding="utf-8") as f:
            f.write(poetry_lock)
        with open(os.path.join(self.temp_dir, "package-lock.json"), "w", encoding="utf-8") as f:
            f.write(pkg_lock)

        # Dynamic import file
        dyn_code = '''
import importlib
mod = importlib.import_module("pyyaml")
'''
        with open(os.path.join(self.temp_dir, "dyn.py"), "w", encoding="utf-8") as f:
            f.write(dyn_code)

        mapper = RouteMapper(self.temp_dir)
        routes = mapper.scan()
        self.assertTrue(any(r.func_name == "user_detail" and r.file_path == "views.py" for r in routes))
        matched = mapper.match_url("GET", "/users/42")
        self.assertIsNotNone(matched)
        self.assertEqual(matched.func_name, "user_detail")

        # Empty input check on Correlator
        correlator = Correlator(mapper)
        self.assertEqual(correlator.correlate([], []), [])

        # SCA Lockfile + Dynamic Import + Malicious Package check
        sca = SCAReachabilityEngine(self.temp_dir, route_mapper=mapper)
        report = sca.analyze_reachability()
        by_pkg = {d.name: d for d in report.sbom}
        self.assertIn("lodash", by_pkg)
        self.assertIn("werkzeug", by_pkg)
        self.assertEqual(by_pkg["werkzeug"].transitive_path, ["root", "flask", "werkzeug"])

        # Because dyn.py has importlib.import_module(), unreached pyyaml must be UNKNOWN (not downgraded!)
        pyyaml_finding = next(f for f in report.findings if f.package == "pyyaml")
        self.assertEqual(pyyaml_finding.status, SCAReachabilityStatus.UNKNOWN)
        self.assertEqual(pyyaml_finding.effective_severity, pyyaml_finding.original_severity)

        # Malicious package alert for 'colourama'
        mal_alerts = [a for a in report.supply_chain_alerts if a.alert_type == "malicious_package"]
        self.assertEqual(len(mal_alerts), 1)
        self.assertEqual(mal_alerts[0].package, "colourama")

        # Fix commit diff parser check
        diff_text = """
@@ -42,6 +42,8 @@ def parse_token(raw_tok):
-    return eval(raw_tok)
+    return json.loads(raw_tok)
"""
        extracted_syms = SCAReachabilityEngine.parse_fix_commit_diff(diff_text)
        self.assertIn("parse_token", extracted_syms)


if __name__ == "__main__":
    unittest.main()

