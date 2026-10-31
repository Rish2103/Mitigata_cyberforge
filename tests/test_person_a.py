"""
Unit and Integration Tests for Person A Components:
- FR-4: AST Route extraction, URL regex normalization, parameters and helper calls
- FR-1: SAST detection across all 6 CWEs (CWE-89, 79, 78, 22, 601, 798)
- B-2: Safe decoy filter suppressing parameterized queries, safe subprocesses, etc.
- FR-5 & FR-7: Correlation linking DAST to SAST into Confirmed, Code only, Runtime only
- FR-6: Deduplication and idempotency
- FR-9: Confirmed-first risk ranking
- B-3: Link explanation badges
"""

import os
import shutil
import tempfile
import unittest

from core.schemas import CanonicalFinding, FindingSource, Severity, IssueStatus
from core.config import is_safe_target_url
from engine.route_mapper import RouteMapper, _normalize_route_pattern_to_regex
from engine.sast_scanner import SASTScanner
from engine.decoy_filter import DecoyFilter
from engine.correlator import Correlator


class TestPersonACore(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="cyberforge_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_target_safety_guard(self):
        """Verify Disqualification Guard (PRD Rule 1)."""
        self.assertTrue(is_safe_target_url("http://localhost:5000/api/orders"))
        self.assertTrue(is_safe_target_url("http://127.0.0.1:8000/orders"))
        self.assertTrue(is_safe_target_url("http://testserver/"))
        # Must refuse public internet domains
        self.assertFalse(is_safe_target_url("https://google.com/"))
        self.assertFalse(is_safe_target_url("https://mitigata.com/"))
        self.assertFalse(is_safe_target_url("https://attacker.com/evil"))

    def test_route_mapper_flask_and_fastapi(self):
        """Verify FR-4 route extraction for Flask & FastAPI syntax."""
        flask_app_code = '''
from flask import Flask, request, Blueprint

app = Flask(__name__)
bp = Blueprint("orders", __name__, url_prefix="/api")

def query_database(order_id):
    pass

@bp.route("/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    query_database(order_id)
    return f"Order {order_id}"

@app.route("/search", methods=["GET", "POST"])
def search_items():
    q = request.args.get("query")
    return q
'''
        app_file = os.path.join(self.test_dir, "app.py")
        with open(app_file, "w", encoding="utf-8") as f:
            f.write(flask_app_code)

        mapper = RouteMapper(self.test_dir)
        routes = mapper.scan()

        self.assertEqual(len(routes), 3)  # 1 for get_order (GET), 2 for search_items (GET, POST)
        
        # Test route matching
        route1 = mapper.match_url("GET", "/api/orders/42")
        self.assertIsNotNone(route1)
        self.assertEqual(route1.func_name, "get_order")
        self.assertIn("order_id", route1.parameters)
        self.assertIn("query_database", route1.called_funcs)

        route2 = mapper.match_url("POST", "/search?query=laptop")
        self.assertIsNotNone(route2)
        self.assertEqual(route2.func_name, "search_items")
        self.assertIn("query", route2.parameters)

        # Verify line in route helper check
        self.assertTrue(mapper.is_line_in_route("app.py", route1.start_line, route1))

    def test_sast_scanner_and_decoy_filter(self):
        """Verify FR-1 SAST detection across CWEs and B-2 safe decoy suppression."""
        sample_code = '''
import sqlite3, os, subprocess
from flask import request, redirect, render_template_string

def vulnerable_sql(user_id):
    conn = sqlite3.connect("db.sqlite")
    # CWE-89 Vulnerable SQLi via f-string
    conn.execute(f"SELECT * FROM users WHERE id = {user_id}")

def safe_decoy_sql(user_id):
    conn = sqlite3.connect("db.sqlite")
    # B-2 Safe Parameterized Decoy (Should be suppressed)
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))

def vulnerable_cmdi(target_ip):
    # CWE-78 Vulnerable OS command injection
    os.system(f"ping -c 1 {target_ip}")

def safe_decoy_subprocess(target_ip):
    # B-2 Safe subprocess with list and shell=False
    subprocess.run(["ping", "-c", "1", target_ip], shell=False)

def vulnerable_xss(comment):
    # CWE-79 Vulnerable XSS
    return render_template_string(f"<div>{comment}</div>")

def vulnerable_path(file_name):
    # CWE-22 Vulnerable Path Traversal
    return open(f"/var/www/uploads/{file_name}").read()

def vulnerable_redirect(dest):
    # CWE-601 Vulnerable Open Redirect
    return redirect(dest)

# CWE-798 Hard-coded secret
API_SECRET_KEY = "super_secret_production_jwt_key_999"
'''
        test_file = os.path.join(self.test_dir, "vuln_sample.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(sample_code)

        scanner = SASTScanner(self.test_dir)
        findings = scanner.scan()

        # Count active vs suppressed
        active_findings = [f for f in findings if not f.is_protected_decoy]
        decoys = [f for f in findings if f.is_protected_decoy]

        cwes_found = {f.cwe for f in active_findings}
        self.assertIn("CWE-89", cwes_found)
        self.assertIn("CWE-78", cwes_found)
        self.assertIn("CWE-79", cwes_found)
        self.assertIn("CWE-22", cwes_found)
        self.assertIn("CWE-601", cwes_found)
        self.assertIn("CWE-798", cwes_found)

        # Check that safe decoys were suppressed with reasons (B-2)
        decoy_cwes = [f.cwe for f in decoys]
        self.assertIn("CWE-89", decoy_cwes)
        self.assertIn("CWE-78", decoy_cwes)
        for d in decoys:
            self.assertIsNotNone(d.decoy_reason)

    def test_correlator_three_buckets_and_deduplication(self):
        """Verify FR-5, FR-6, FR-7, FR-9, and B-3."""
        # Create a mock route file
        route_code = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/orders", methods=["GET"])
def get_orders():
    order_id = request.args.get("id")
    # Vulnerable line
    import sqlite3
    conn = sqlite3.connect("shop.db")
    conn.execute(f"SELECT * FROM orders WHERE id = '{order_id}'")
    return "ok"
'''
        with open(os.path.join(self.test_dir, "routes.py"), "w", encoding="utf-8") as f:
            f.write(route_code)

        mapper = RouteMapper(self.test_dir)
        mapper.scan()

        scanner = SASTScanner(self.test_dir)
        sast_findings = scanner.scan()

        # Mock DAST finding for SQLi on /api/orders
        dast_sqli = CanonicalFinding(
            id="dast_sqli_1",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="/api/orders",
            method="GET",
            param="id",
            payload="1' OR '1'='1",
            evidence="sqlite3.OperationalError: near syntax error",
        )

        # Mock DAST finding for missing security header (Runtime only)
        dast_header = CanonicalFinding(
            id="dast_header_1",
            source=FindingSource.DAST,
            cwe="CWE-693",
            severity=Severity.MEDIUM,
            url="/api/orders",
            method="GET",
            param=None,
            payload=None,
            evidence="Missing Content-Security-Policy header",
        )

        # Mock an extra SAST finding (Code only hard-coded secret)
        sast_secret = CanonicalFinding(
            id="sast_secret_1",
            source=FindingSource.SAST,
            cwe="CWE-798",
            severity=Severity.HIGH,
            file_path="config.py",
            line=12,
            code_snippet='JWT_KEY = "hardcoded123"',
        )

        all_sast = sast_findings + [sast_secret]
        all_dast = [dast_sqli, dast_header]

        correlator = Correlator(mapper)
        issues = correlator.correlate(all_sast, all_dast)

        # Verify 3 buckets (FR-7)
        statuses = {issue.status for issue in issues}
        self.assertIn(IssueStatus.CONFIRMED, statuses)
        self.assertIn(IssueStatus.CODE_ONLY, statuses)
        self.assertIn(IssueStatus.RUNTIME_ONLY, statuses)

        # Verify FR-9 ranking: Confirmed issue must be at index 0
        self.assertEqual(issues[0].status, IssueStatus.CONFIRMED)
        self.assertEqual(issues[0].cwe, "CWE-89")
        self.assertEqual(issues[0].url, "/api/orders")
        self.assertIsNotNone(issues[0].file_path)
        self.assertIsNotNone(issues[0].line)
        self.assertIsNotNone(issues[0].link_reason)
        self.assertIsNotNone(issues[0].fix_suggestion)

        # Verify FR-6 Idempotency: re-running does not duplicate issues
        issues_run2 = correlator.correlate(all_sast, all_dast)
        self.assertEqual(len(issues), len(issues_run2))
        self.assertEqual([i.id for i in issues], [i.id for i in issues_run2])

    def test_hard_negative_vetoes(self):
        """
        Verify Zero Wrong Links (<5%):
        Correlator must NEVER link findings across different routes or mismatching CWEs.
        """
        mapper = RouteMapper(self.test_dir)
        correlator = Correlator(mapper)

        # Route /api/cart vs DAST on /api/orders
        sast_cart = CanonicalFinding(
            id="sast_cart",
            source=FindingSource.SAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            file_path="cart.py",
            line=50,
            code_snippet="conn.execute(sql)",
        )
        dast_orders = CanonicalFinding(
            id="dast_orders",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="/api/orders",
            method="GET",
            param="id",
        )
        # Even with same CWE-89, different route cannot be linked
        issues = correlator.correlate([sast_cart], [dast_orders])
        self.assertEqual(len(issues), 2)
        self.assertTrue(all(i.status != IssueStatus.CONFIRMED for i in issues))

    def test_helper_call_chain_linking(self):
        """
        Verify 1-hop helper call-chain linking:
        Route /api/products handled in views.py calls helper in db_helper.py.
        """
        views_code = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/products", methods=["GET"])
def list_products():
    pid = request.args.get("pid")
    return query_products_db(pid)
'''
        helper_code = '''
import sqlite3

def query_products_db(pid):
    conn = sqlite3.connect("store.db")
    conn.execute(f"SELECT * FROM products WHERE pid = {pid}")
    return "products"
'''
        with open(os.path.join(self.test_dir, "views.py"), "w", encoding="utf-8") as f:
            f.write(views_code)
        with open(os.path.join(self.test_dir, "db_helper.py"), "w", encoding="utf-8") as f:
            f.write(helper_code)

        mapper = RouteMapper(self.test_dir)
        mapper.scan()

        scanner = SASTScanner(self.test_dir)
        sast_findings = scanner.scan()

        dast_finding = CanonicalFinding(
            id="dast_prod_1",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="/api/products",
            method="GET",
            param="pid",
            payload="1' OR '1'='1",
            evidence="SQL syntax error",
        )

        correlator = Correlator(mapper)
        issues = correlator.correlate(sast_findings, [dast_finding])

        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].file_path, "db_helper.py")
        self.assertIn("db_helper.py", confirmed[0].link_reason)
        self.assertIn("list_products", confirmed[0].link_reason)

    def test_dead_code_decoy_suppression(self):
        """
        Verify B-2 Dead Code Suppression:
        An unreachable file not invoked by any active route is suppressed as a safe decoy.
        """
        active_code = '''
from flask import Flask
app = Flask(__name__)

@app.route("/alive")
def alive():
    return "yes"
'''
        dead_code = '''
def unused_dead_function(param):
    import sqlite3
    conn = sqlite3.connect("unused.db")
    # Vulnerable sink in unreachable code
    conn.execute(f"SELECT * FROM test WHERE name = '{param}'")
'''
        with open(os.path.join(self.test_dir, "active.py"), "w", encoding="utf-8") as f:
            f.write(active_code)
        with open(os.path.join(self.test_dir, "dead.py"), "w", encoding="utf-8") as f:
            f.write(dead_code)

        mapper = RouteMapper(self.test_dir)
        mapper.scan()

        # Reachable files are active.py
        reachable_files = {"active.py"}
        scanner = SASTScanner(self.test_dir)
        findings = scanner.scan(reachable_files=reachable_files)

        # The finding in dead.py should be marked as protected decoy (suppressed)
        dead_findings = [f for f in findings if f.file_path == "dead.py"]
        self.assertTrue(len(dead_findings) > 0)
        self.assertTrue(all(f.is_protected_decoy for f in dead_findings))
        self.assertIn("Unreachable dead code", dead_findings[0].decoy_reason)

    def test_static_sql_not_flagged(self):
        """
        Verify that benign static SQL executions (e.g. conn.execute('SELECT 1'))
        are NOT flagged as vulnerabilities or false alarms.
        """
        code = '''
import sqlite3
def check_health():
    conn = sqlite3.connect("health.db")
    conn.execute("SELECT 1")
    conn.execute("SELECT id, name FROM users")
'''
        with open(os.path.join(self.test_dir, "health.py"), "w", encoding="utf-8") as f:
            f.write(code)

        scanner = SASTScanner(self.test_dir)
        findings = scanner.scan()
        # There should be 0 findings (no false positives for plain static queries)
        self.assertEqual(len(findings), 0)

    def test_fastapi_and_flask_path_converters(self):
        """
        Verify that path converters like <path:file_path> or {item_path:path}
        and typed parameters like {item_id:int} match multi-segment paths correctly.
        """
        code = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/files/{file_path:path}")
def read_file(file_path: str):
    return file_path

@app.get("/items/{item_id:int}")
def read_item(item_id: int):
    return item_id
'''
        with open(os.path.join(self.test_dir, "fastapi_app.py"), "w", encoding="utf-8") as f:
            f.write(code)

        mapper = RouteMapper(self.test_dir)
        mapper.scan()

        route_files = mapper.match_url("GET", "/files/docs/2026/report.pdf")
        self.assertIsNotNone(route_files)
        self.assertEqual(route_files.func_name, "read_file")

        route_item = mapper.match_url("GET", "/items/12345")
        self.assertIsNotNone(route_item)
        self.assertEqual(route_item.func_name, "read_item")

    def test_parameter_weighting_in_correlator(self):
        """
        When a route handler contains multiple sinks of the same CWE,
        the correlator should prioritize linking the sink whose code matches DAST parameter.
        """
        code = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/multi_search", methods=["GET"])
def multi_search():
    user = request.args.get("user")
    role = request.args.get("role")
    conn = sqlite3.connect("db.sqlite")
    conn.execute(f"SELECT * FROM users WHERE username = '{user}'")
    conn.execute(f"SELECT * FROM roles WHERE role_name = '{role}'")
    return "ok"
'''
        with open(os.path.join(self.test_dir, "multi.py"), "w", encoding="utf-8") as f:
            f.write(code)

        mapper = RouteMapper(self.test_dir)
        mapper.scan()

        scanner = SASTScanner(self.test_dir)
        sast_findings = scanner.scan()
        self.assertEqual(len(sast_findings), 2)

        # DAST finding specifically targeting the 'role' parameter
        dast_role = CanonicalFinding(
            id="dast_role_1",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="/multi_search",
            method="GET",
            param="role",
            payload="' OR '1'='1",
        )

        correlator = Correlator(mapper)
        issues = correlator.correlate(sast_findings, [dast_role])

        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertIn("role", confirmed[0].code_snippet)
        self.assertIn("role_name", confirmed[0].code_snippet)
        self.assertIn("verified in sink call", confirmed[0].link_reason)
        self.assertIn("Before:", confirmed[0].fix_suggestion)
        self.assertIn("After:", confirmed[0].fix_suggestion)

    def test_scope_reduction_exact_replica_and_runtime_drift_fallback(self):
        """
        Checkpoint 1 Judge Feedback Verification:
        1. EXACT_REPLICA routes with 0 SAST findings -> PRUNED_SAFE (0 active probes).
        2. EXACT_REPLICA routes with SAST finding -> TARGETED_REDUCTION (only flagged param+CWE probed).
        3. RUNTIME_DRIFT_EXTRA routes not in AST -> FULL_PROBE_DRIFT (all 5 active CWEs probed).
        4. CODE_ONLY_UNMOUNTED routes not in live app -> PRUNED_SAFE (0 active probes).
        """
        from engine.scope_reducer import ScopeReducer, ParityStatus, ScopeStrategy

        code = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/api/safe1", methods=["GET"])
def safe1():
    q = request.args.get("q", "")
    conn = sqlite3.connect("db.sqlite")
    conn.execute("SELECT * FROM items WHERE name = ?", (q,))
    return "safe1"

@app.route("/api/safe2", methods=["GET"])
def safe2():
    id_val = request.args.get("id", "1")
    conn = sqlite3.connect("db.sqlite")
    conn.execute("SELECT * FROM items WHERE id = ?", (id_val,))
    return "safe2"

@app.route("/api/vuln", methods=["GET"])
def vuln():
    search = request.args.get("search", "")
    conn = sqlite3.connect("db.sqlite")
    conn.execute(f"SELECT * FROM items WHERE name = '{search}'")
    return "vuln"

@app.route("/api/unmounted", methods=["POST"])
def unmounted():
    cmd = request.form.get("cmd", "")
    return cmd
'''
        with open(os.path.join(self.test_dir, "scope_app.py"), "w", encoding="utf-8") as f:
            f.write(code)

        mapper = RouteMapper(self.test_dir)
        routes = mapper.scan()
        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        sast_findings = scanner.scan(route_mapper=mapper)

        # Simulate live runtime endpoints:
        # /api/safe1, /api/safe2, /api/vuln are live (EXACT_REPLICA)
        # /api/unmounted is NOT live (CODE_ONLY_UNMOUNTED)
        # /api/debug/drift is live ONLY at runtime (RUNTIME_DRIFT_EXTRA)
        live_endpoints = [
            ("GET", "/api/safe1"),
            ("GET", "/api/safe2"),
            ("GET", "/api/vuln"),
            ("GET", "/api/debug/drift"),
        ]

        reducer = ScopeReducer(route_mapper=mapper)
        report = reducer.compute_scope_reduction(
            routes=routes,
            sast_findings=sast_findings,
            live_endpoints=live_endpoints,
        )

        self.assertIn("O(N_ast + K_tainted_sinks)", report.time_complexity)
        self.assertEqual(report.exact_replica_routes, 3)
        self.assertEqual(report.runtime_drift_routes, 1)
        self.assertEqual(report.code_only_routes, 1)
        self.assertFalse(report.is_exact_replica)
        self.assertGreater(report.probes_saved_count, 0)
        self.assertGreater(report.reduction_percentage, 50.0)

        # Verify per-route decisions via should_probe
        self.assertFalse(reducer.should_probe(report, "GET", "/api/safe1", "q", "CWE-89"))
        self.assertFalse(reducer.should_probe(report, "GET", "/api/safe1", "q", "CWE-79"))
        self.assertTrue(reducer.should_probe(report, "GET", "/api/vuln", "search", "CWE-89"))
        self.assertFalse(reducer.should_probe(report, "GET", "/api/vuln", "search", "CWE-78"))
        # Runtime drift endpoint must fall back to full 5-CWE probing
        for cwe in ("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"):
            self.assertTrue(reducer.should_probe(report, "GET", "/api/debug/drift", "any_param", cwe))

    def test_3_hop_cross_file_call_graph_and_blueprint_prefix(self):
        """
        Verifies 3-hop cross-file call graph resolution across:
        app.py (register_blueprint prefix='/api/v3') -> routes/billing.py -> services/payment.py -> repos/ledger.py
        """
        os.makedirs(os.path.join(self.test_dir, "routes"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "services"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "repos"), exist_ok=True)

        with open(os.path.join(self.test_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write(
                "from flask import Flask\n"
                "from routes.billing import billing_bp\n"
                "app = Flask(__name__)\n"
                "app.register_blueprint(billing_bp, url_prefix='/api/v3')\n"
            )

        with open(os.path.join(self.test_dir, "routes", "billing.py"), "w", encoding="utf-8") as f:
            f.write(
                "from flask import Blueprint, request\n"
                "from services.payment import process_charge\n"
                "billing_bp = Blueprint('billing', __name__)\n"
                "@billing_bp.route('/charge', methods=['GET'])\n"
                "def charge_endpoint():\n"
                "    acct = request.args.get('acct', '')\n"
                "    return str(process_charge(acct))\n"
            )

        with open(os.path.join(self.test_dir, "services", "payment.py"), "w", encoding="utf-8") as f:
            f.write(
                "from repos.ledger import query_ledger_by_acct\n"
                "def process_charge(acct):\n"
                "    return query_ledger_by_acct(acct)\n"
            )

        with open(os.path.join(self.test_dir, "repos", "ledger.py"), "w", encoding="utf-8") as f:
            f.write(
                "import sqlite3\n"
                "def query_ledger_by_acct(acct):\n"
                "    conn = sqlite3.connect('ledger.db')\n"
                "    return conn.execute(f\"SELECT * FROM ledger WHERE acct = '{acct}'\").fetchall()\n"
            )

        mapper = RouteMapper(self.test_dir)
        routes = mapper.scan()
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].path_pattern, "/api/v3/charge")

        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        sast = scanner.scan(reachable_files=mapper.get_reachable_files(), route_mapper=mapper)
        active_sast = [s for s in sast if not s.is_protected_decoy]
        self.assertEqual(len(active_sast), 1)
        self.assertIn("ledger.py", active_sast[0].file_path)

        dast = [
            CanonicalFinding(
                id="dast_3hop_1",
                source=FindingSource.DAST,
                cwe="CWE-89",
                severity=Severity.CRITICAL,
                url="http://localhost:5000/api/v3/charge?acct=1'",
                method="GET",
                param="acct",
                payload="1'",
            )
        ]
        correlator = Correlator(mapper)
        issues = correlator.correlate(sast, dast)
        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertIn("ledger.py", confirmed[0].file_path)

    def test_express_js_polyglot_router_and_correlation(self):
        """
        Verifies B-7 Express.js route extraction, SAST sink & B-2 safe decoy filtering,
        and end-to-end correlation with Before/After remediation diff.
        """
        js_code = """
const express = require('express');
const app = express();
const db = require('./db');

app.get('/api/node/items/:id', (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM items WHERE id = '" + id + "'", (err, rows) => {
        res.send(rows);
    });
});

app.get('/api/node/items-safe/:id', (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM items WHERE id = ?", [id], (err, rows) => {
        res.json(rows);
    });
});
"""
        with open(os.path.join(self.test_dir, "server.js"), "w", encoding="utf-8") as f:
            f.write(js_code)

        mapper = RouteMapper(self.test_dir)
        routes = mapper.scan()
        self.assertEqual(len(routes), 2)

        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        sast = scanner.scan(route_mapper=mapper)
        active = [f for f in sast if not f.is_protected_decoy]
        decoys = [f for f in sast if f.is_protected_decoy]
        self.assertEqual(len(active), 1)
        self.assertEqual(len(decoys), 1)

        dast = [
            CanonicalFinding(
                id="dast_express_1",
                source=FindingSource.DAST,
                cwe="CWE-89",
                severity=Severity.CRITICAL,
                url="http://localhost:3000/api/node/items/99'",
                method="GET",
                param="id",
                payload="99'",
            )
        ]
        correlator = Correlator(mapper)
        issues = correlator.correlate(sast, dast)
        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].cwe, "CWE-89")
        self.assertIn("Before:", confirmed[0].fix_suggestion)
        self.assertIn("After:", confirmed[0].fix_suggestion)


if __name__ == "__main__":
    unittest.main()

