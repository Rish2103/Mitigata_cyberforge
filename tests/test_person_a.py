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
        # Must refuse public internet domains and non-loopback LAN IPs (e.g. 192.168.60.139)
        self.assertFalse(is_safe_target_url("https://google.com/"))
        self.assertFalse(is_safe_target_url("https://mitigata.com/"))
        self.assertFalse(is_safe_target_url("https://attacker.com/evil"))
        self.assertFalse(is_safe_target_url("http://192.168.60.139/"))
        self.assertFalse(is_safe_target_url("http://192.168.60.139:8080/api"))
        self.assertFalse(is_safe_target_url("http://10.0.0.42:5000/"))

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

    def test_nested_fastapi_include_router_and_flask_methodview(self):
        """
        Task A2.2 & A4.1: Verifies 2-level nested FastAPI `include_router` prefix resolution
        (`app -> /api -> /v1 -> /accounts/{acc_id}`) and Flask `MethodView` (`as_view`)
        class-based view route & method extraction.
        """
        fastapi_main = """
from fastapi import FastAPI, APIRouter
from routers_v1 import v1_router

app = FastAPI()
api_router = APIRouter()
api_router.include_router(v1_router, prefix="/v1")
app.include_router(api_router, prefix="/api")
"""
        fastapi_v1 = """
import sqlite3
from fastapi import APIRouter

v1_router = APIRouter()

@v1_router.get("/accounts/{acc_id}")
def get_account(acc_id: str):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM accounts WHERE id = '{acc_id}'")
    return {"acc_id": acc_id}
"""
        flask_cbv = """
import os
from flask import Flask, request
from flask.views import MethodView

app = Flask(__name__)

class MemberAPI(MethodView):
    def get(self, mid):
        return {"mid": mid}

    def post(self, mid):
        cmd = request.args.get("cmd", "whoami")
        os.system(f"echo {cmd}")
        return {"ran": cmd}

app.add_url_rule("/api/v2/members/<int:mid>", view_func=MemberAPI.as_view("member_api"))
"""
        with open(os.path.join(self.test_dir, "main_api.py"), "w", encoding="utf-8") as f:
            f.write(fastapi_main)
        with open(os.path.join(self.test_dir, "routers_v1.py"), "w", encoding="utf-8") as f:
            f.write(fastapi_v1)
        with open(os.path.join(self.test_dir, "cbv_app.py"), "w", encoding="utf-8") as f:
            f.write(flask_cbv)

        mapper = RouteMapper(self.test_dir)
        routes = mapper.scan()
        patterns = {(r.method, r.path_pattern) for r in routes}
        self.assertIn(("GET", "/api/v1/accounts/{acc_id}"), patterns)
        self.assertIn(("GET", "/api/v2/members/<int:mid>"), patterns)
        self.assertIn(("POST", "/api/v2/members/<int:mid>"), patterns)

        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        sast = scanner.scan(route_mapper=mapper)
        dast = [
            CanonicalFinding(
                id="dast_nested_fastapi",
                source=FindingSource.DAST,
                cwe="CWE-89",
                severity=Severity.CRITICAL,
                url="http://localhost:8000/api/v1/accounts/42'",
                method="GET",
                param="acc_id",
                payload="42'",
            ),
            CanonicalFinding(
                id="dast_cbv_post",
                source=FindingSource.DAST,
                cwe="CWE-78",
                severity=Severity.CRITICAL,
                url="http://localhost:5000/api/v2/members/7?cmd=id",
                method="POST",
                param="cmd",
                payload=";id",
            ),
        ]
        correlator = Correlator(mapper)
        issues = correlator.correlate(sast, dast)
        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 2)

    def test_express_router_route_chaining(self):
        """
        Task A2.2 & A4.1: Verifies Express `router.route('/items/:id').get(...).post(...)`
        chained route definitions extract both GET and POST routes and correlate sinks.
        """
        js_chained = """
const express = require('express');
const router = express.Router();
const db = require('./db');
const { exec } = require('child_process');

router.route('/v1/chained/:id')
  .get((req, res) => {
      const itemId = req.params.id;
      db.query("SELECT * FROM chained WHERE id = '" + itemId + "'");
      res.send("ok");
  })
  .post((req, res) => {
      const host = req.body.host;
      exec("ping -c 1 " + host);
      res.send("pong");
  });
"""
        with open(os.path.join(self.test_dir, "chained.js"), "w", encoding="utf-8") as f:
            f.write(js_chained)

        mapper = RouteMapper(self.test_dir)
        routes = mapper.scan()
        methods_for_chained = {r.method for r in routes if r.path_pattern == "/v1/chained/:id"}
        self.assertEqual(methods_for_chained, {"GET", "POST"})

        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        sast = scanner.scan(route_mapper=mapper)
        self.assertEqual(len([f for f in sast if not f.is_protected_decoy]), 2)

    def test_3_hop_intermediate_dict_json_taint_and_real_world_sanitizers(self):
        """
        Task A2.2 & A4.1:
        1. Tracks `data = request.get_json(); val = data.get("query_filter")` across a 3-hop helper chain
           (`route -> hop1 -> hop2 -> hop3`) preserving `param="query_filter"`.
        2. Recognizes real-world sanitizers (`bleach.clean`, SQLAlchemy `.filter_by()`,
           Django `.objects.filter()`, `werkzeug.security.safe_join`, `Path.resolve().is_relative_to()`,
           `urlsplit().netloc`) as `is_protected_decoy=True`.
        """
        code = '''
import os
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit
import bleach
from werkzeug.security import safe_join
from flask import Flask, request, make_response, redirect

app = Flask(__name__)

def repo_hop3(sql_filter):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM audit_logs WHERE filter = '{sql_filter}'")

def service_hop2(extracted_filter):
    return repo_hop3(extracted_filter)

def controller_hop1(filter_val):
    return service_hop2(filter_val)

@app.route("/api/audit/search", methods=["POST"])
def audit_search():
    data = request.get_json()
    val = data.get("query_filter")
    controller_hop1(val)
    return {"status": "ok"}

@app.route("/api/safe-sanitizers", methods=["GET"])
def safe_sanitizers_route():
    raw_html = request.args.get("bio", "")
    clean_html = bleach.clean(raw_html)
    resp = make_response(f"<div>{clean_html}</div>")

    fname = request.args.get("file", "readme.txt")
    safe_path = safe_join("/var/data", fname)
    with open(safe_path, "r") as f:
        _ = f.read()

    base_dir = Path("/var/data").resolve()
    target = (base_dir / fname).resolve()
    if target.is_relative_to(base_dir):
        with open(target, "r") as f2:
            _ = f2.read()

    next_url = request.args.get("next", "/home")
    if not urlsplit(next_url).netloc:
        return redirect(next_url)
    return resp
'''
        with open(os.path.join(self.test_dir, "deep_app.py"), "w", encoding="utf-8") as f:
            f.write(code)

        mapper = RouteMapper(self.test_dir)
        mapper.scan()
        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        findings = scanner.scan(route_mapper=mapper)

        active = [f for f in findings if not f.is_protected_decoy]
        decoys = [f for f in findings if f.is_protected_decoy]

        # Only the 3-hop SQLi should be active, and its inferred parameter must be 'query_filter'
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].cwe, "CWE-89")
        self.assertEqual(active[0].param, "query_filter")
        self.assertEqual(active[0].file_path, "deep_app.py")

        # All sanitized sinks in safe_sanitizers_route must be marked as protected decoys
        self.assertGreaterEqual(len(decoys), 3)

    def test_dynamic_getattr_sca_unknown_never_downgraded(self):
        """
        Task A3.3 & A4.1: Verifies that dynamic `getattr(mod, dynamic_attr)` reflection
        causes unreached vulnerable packages to be classified as `SCAReachabilityStatus.UNKNOWN`
        and NEVER downgraded below `original_severity`.
        """
        from core.schemas import SCAReachabilityStatus
        from engine.sca_reachability import SCAReachabilityEngine

        with open(os.path.join(self.test_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("pyyaml==5.3.1\n")
        dyn_getattr_code = """
import yaml

def invoke_dynamic(loader_name, payload):
    fn = getattr(yaml, loader_name)
    return fn(payload)
"""
        with open(os.path.join(self.test_dir, "reflect_runner.py"), "w", encoding="utf-8") as f:
            f.write(dyn_getattr_code)

        mapper = RouteMapper(self.test_dir)
        mapper.scan()
        sca = SCAReachabilityEngine(self.test_dir, route_mapper=mapper)
        report = sca.analyze_reachability()
        pyyaml_f = next(f for f in report.findings if f.package == "pyyaml")
        self.assertEqual(pyyaml_f.status, SCAReachabilityStatus.UNKNOWN)
        self.assertEqual(pyyaml_f.effective_severity, pyyaml_f.original_severity)

    def test_java_spring_boot_polyglot_router_sast_decoy_and_correlation(self):
        """
        Bonus B-7 (Java Polyglot Support):
        Verifies that .java (Spring Boot) files are scanned for routes, real SAST sinks,
        B-2 safe decoys (PreparedStatement, ProcessBuilder, HtmlUtils.htmlEscape),
        and correlate with DAST findings into Confirmed issues.
        """
        java_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples", "java_spring_demo"))
        mapper = RouteMapper(java_dir)
        routes = mapper.scan()
        self.assertGreaterEqual(len(routes), 8)
        route_paths = {(r.method, r.path_pattern) for r in routes}
        self.assertIn(("GET", "/api/java/orders/search"), route_paths)
        self.assertIn(("POST", "/api/java/diagnostics/ping"), route_paths)

        scanner = SASTScanner(java_dir, route_mapper=mapper)
        sast_findings = scanner.scan(reachable_files=mapper.get_reachable_files(), route_mapper=mapper)
        active = [f for f in sast_findings if not f.is_protected_decoy]
        decoys = [f for f in sast_findings if f.is_protected_decoy]

        # Must suppress PreparedStatement, ProcessBuilder, and HtmlUtils.htmlEscape safe decoys
        self.assertGreaterEqual(len(decoys), 3)
        active_cwes = {f.cwe for f in active}
        self.assertTrue({"CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-601", "CWE-798"}.issubset(active_cwes))

        # Correlate Java SQLi SAST finding with runtime DAST finding on /api/java/orders/search
        dast_java_sqli = CanonicalFinding(
            id="dast_java_sqli_1",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="http://127.0.0.1:8080/api/java/orders/search?q=test",
            method="GET",
            param="q",
            payload="' OR '1'='1",
            evidence="java.sql.SQLException: syntax error",
        )
        correlator = Correlator(mapper)
        issues = correlator.correlate(sast_findings, [dast_java_sqli])
        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].cwe, "CWE-89")
        self.assertIn("/api/java/orders/search", confirmed[0].matched_route)
        self.assertIn("searchOrders()", confirmed[0].matched_route)
        self.assertEqual(confirmed[0].param, "q")

    def test_phase4_unseen_django_include_prefixes_re_path_and_cbv_correlation(self):
        """
        Phase 4 (Task A4.1 - Unseen Django App Torture Test):
        Verifies multi-file Django urlpatterns with include('billing.urls'),
        urlpatterns += [...], re_path named regex groups, class-based View.as_view(),
        cross-file helper SQLi/CMDi correlation, and ORM .filter() decoy suppression.
        """
        os.makedirs(os.path.join(self.test_dir, "billing"), exist_ok=True)
        root_urls = '''
from django.urls import path, include

urlpatterns = [
    path("api/v1/billing/", include("billing.urls")),
]
'''
        billing_urls = '''
from django.urls import path, re_path
from billing import views

urlpatterns = [
    path("invoices/<int:invoice_id>/", views.get_invoice),
]

urlpatterns += [
    re_path(r"^export/(?P<fmt>\\w+)/$", views.InvoiceExportView.as_view()),
]
'''
        billing_views = '''
from django.views import View
from billing.db import query_invoice_raw, run_export_tool

def get_invoice(request, invoice_id):
    sort = request.GET.get("sort", "created_at")
    # B-2 Safe Decoys: Django ORM filter() + parameterized raw()
    InvoiceModel.objects.filter(id=invoice_id)
    InvoiceModel.objects.raw("SELECT * FROM invoices WHERE id = %s", [invoice_id])
    return query_invoice_raw(invoice_id, sort)

class InvoiceExportView(View):
    def post(self, request, fmt):
        flag = request.POST.get("flag", "--csv")
        return run_export_tool(fmt, flag)
'''
        billing_db = '''
import sqlite3
import subprocess

def query_invoice_raw(invoice_id, sort):
    conn = sqlite3.connect("billing.db")
    # Real CWE-89 SQLi in 1-hop helper
    return conn.execute(f"SELECT * FROM invoices WHERE id = {invoice_id} ORDER BY {sort}")

def run_export_tool(fmt, flag):
    # Real CWE-78 CMDi in 1-hop helper
    return subprocess.check_output(f"invoice-cli --format {fmt} {flag}", shell=True)
'''
        with open(os.path.join(self.test_dir, "urls.py"), "w", encoding="utf-8") as f:
            f.write(root_urls)
        with open(os.path.join(self.test_dir, "billing", "urls.py"), "w", encoding="utf-8") as f:
            f.write(billing_urls)
        with open(os.path.join(self.test_dir, "billing", "views.py"), "w", encoding="utf-8") as f:
            f.write(billing_views)
        with open(os.path.join(self.test_dir, "billing", "db.py"), "w", encoding="utf-8") as f:
            f.write(billing_db)

        mapper = RouteMapper(self.test_dir)
        routes = mapper.scan()

        # Verify included prefix '/api/v1/billing' propagated to both path() and re_path()
        m_inv = mapper.match_url("GET", "/api/v1/billing/invoices/42/")
        self.assertIsNotNone(m_inv)
        self.assertEqual(m_inv.func_name, "get_invoice")
        self.assertIn("invoice_id", m_inv.parameters)
        self.assertIn("sort", m_inv.parameters)

        m_exp = mapper.match_url("POST", "/api/v1/billing/export/pdf/")
        self.assertIsNotNone(m_exp)
        self.assertEqual(m_exp.func_name, "InvoiceExportView.post")
        self.assertIn("fmt", m_exp.parameters)
        self.assertIn("flag", m_exp.parameters)

        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        sast_findings = scanner.scan(reachable_files=mapper.get_reachable_files(), route_mapper=mapper)
        decoys = [f for f in sast_findings if f.is_protected_decoy]
        self.assertGreaterEqual(len(decoys), 1)

        dast_findings = [
            CanonicalFinding(
                id="dast_django_sqli",
                source=FindingSource.DAST,
                cwe="CWE-89",
                severity=Severity.CRITICAL,
                url="http://127.0.0.1:8000/api/v1/billing/invoices/42/?sort=id",
                method="GET",
                param="sort",
                payload="id; DROP TABLE invoices--",
                evidence="sqlite3.OperationalError",
            ),
            CanonicalFinding(
                id="dast_django_cmdi",
                source=FindingSource.DAST,
                cwe="CWE-78",
                severity=Severity.CRITICAL,
                url="http://127.0.0.1:8000/api/v1/billing/export/pdf/",
                method="POST",
                param="flag",
                payload="; id",
                evidence="uid=0(root)",
            ),
        ]
        correlator = Correlator(mapper)
        issues = correlator.correlate(sast_findings, dast_findings)
        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 2)
        confirmed_cwes = {i.cwe for i in confirmed}
        self.assertEqual(confirmed_cwes, {"CWE-89", "CWE-78"})

    def test_phase4_unseen_express_cross_file_router_mount_and_3hop_correlation(self):
        """
        Phase 4 (Task A4.1 - Unseen Express.js Cross-File Router Torture Test):
        Verifies app.use('/api/v2/orders', ordersRouter) where ordersRouter is required
        from './routes/orders', calling a 2-hop service helper in './services/orderService.js'.
        """
        os.makedirs(os.path.join(self.test_dir, "routes"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "services"), exist_ok=True)

        app_js = '''
const express = require('express');
const app = express();
const ordersRouter = require('./routes/orders');

app.use('/api/v2/orders', ordersRouter);
'''
        orders_js = '''
const express = require('express');
const router = express.Router();
const orderService = require('../services/orderService');

router.get('/lookup/:orderId', (req, res) => {
    const filter = req.query.filter;
    // B-2 Safe Decoy: parameterized SQL with $1
    db.query("SELECT * FROM orders WHERE id = $1", [req.params.orderId]);
    const rows = orderService.fetchOrderUnsafe(req.params.orderId, filter);
    res.json(rows);
});

module.exports = router;
'''
        service_js = '''
const child_process = require('child_process');

function fetchOrderUnsafe(orderId, filter) {
    return runRawSql(orderId, filter);
}

function runRawSql(orderId, filter) {
    return db.query(`SELECT * FROM orders WHERE id = ${orderId} AND status = '${filter}'`);
}

module.exports = { fetchOrderUnsafe, runRawSql };
'''
        with open(os.path.join(self.test_dir, "app.js"), "w", encoding="utf-8") as f:
            f.write(app_js)
        with open(os.path.join(self.test_dir, "routes", "orders.js"), "w", encoding="utf-8") as f:
            f.write(orders_js)
        with open(os.path.join(self.test_dir, "services", "orderService.js"), "w", encoding="utf-8") as f:
            f.write(service_js)

        mapper = RouteMapper(self.test_dir)
        routes = mapper.scan()
        matched = mapper.match_url("GET", "/api/v2/orders/lookup/99")
        self.assertIsNotNone(matched)
        self.assertEqual(matched.path_pattern, "/api/v2/orders/lookup/:orderId")
        self.assertIn("orderId", matched.parameters)
        self.assertIn("filter", matched.parameters)
        self.assertIn("fetchOrderUnsafe", matched.called_funcs)
        self.assertIn("runRawSql", matched.called_funcs)

        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        sast_findings = scanner.scan(reachable_files=mapper.get_reachable_files(), route_mapper=mapper)
        decoys = [f for f in sast_findings if f.is_protected_decoy]
        self.assertGreaterEqual(len(decoys), 1)

        dast_sqli = CanonicalFinding(
            id="dast_express_sqli",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="http://127.0.0.1:3000/api/v2/orders/lookup/99?filter=OPEN",
            method="GET",
            param="filter",
            payload="' OR '1'='1",
            evidence="SequelizeDatabaseError: syntax error",
        )
        correlator = Correlator(mapper)
        issues = correlator.correlate(sast_findings, [dast_sqli])
        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0].cwe, "CWE-89")
        self.assertEqual(confirmed[0].file_path, "services/orderService.js")
        self.assertIn("services/orderService.js", confirmed[0].link_reason)

    def test_phase4_unseen_fastapi_depends_pydantic_3hop_and_multi_param_disambiguation(self):
        """
        Phase 4 (Task A4.1 - Unseen FastAPI Multi-Param & 3-Hop Torture Test):
        Verifies FastAPI nested APIRouter + Depends() + Pydantic BaseModel JSON body
        + 3-hop helper chain and disambiguates two CWE-89 sinks on the same route
        (coupon_code vs referral_code) with 0 wrong links.
        """
        app_py = '''
from fastapi import FastAPI, APIRouter, Depends
from pydantic import BaseModel
from service_layer import process_checkout_step1

app = FastAPI()
v1_router = APIRouter(prefix="/v1")

class CheckoutBody(BaseModel):
    coupon_code: str
    referral_code: str

def get_current_tenant(tenant_id: str = "acme"):
    return tenant_id

@v1_router.post("/checkout/apply")
async def apply_checkout(payload: CheckoutBody, tenant: str = Depends(get_current_tenant)):
    return process_checkout_step1(payload.coupon_code, payload.referral_code, tenant)

app.include_router(v1_router, prefix="/api")
'''
        service_py = '''
from repo_layer import apply_coupon_and_referral_sql

def process_checkout_step1(coupon_code, referral_code, tenant):
    return process_checkout_step2(coupon_code, referral_code)

def process_checkout_step2(coupon_code, referral_code):
    return apply_coupon_and_referral_sql(coupon_code, referral_code)
'''
        repo_py = '''
import sqlite3

def apply_coupon_and_referral_sql(coupon_code, referral_code):
    conn = sqlite3.connect("checkout.db")
    conn.execute(f"SELECT discount FROM coupons WHERE code = '{coupon_code}'")
    conn.execute(f"SELECT bonus FROM referrals WHERE ref = '{referral_code}'")
    return True
'''
        with open(os.path.join(self.test_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write(app_py)
        with open(os.path.join(self.test_dir, "service_layer.py"), "w", encoding="utf-8") as f:
            f.write(service_py)
        with open(os.path.join(self.test_dir, "repo_layer.py"), "w", encoding="utf-8") as f:
            f.write(repo_py)

        mapper = RouteMapper(self.test_dir)
        mapper.scan()
        matched = mapper.match_url("POST", "/api/v1/checkout/apply")
        self.assertIsNotNone(matched)
        self.assertIn("coupon_code", matched.parameters)
        self.assertIn("referral_code", matched.parameters)
        self.assertNotIn("tenant", matched.parameters)
        self.assertIn("get_current_tenant", matched.called_funcs)
        self.assertIn("apply_coupon_and_referral_sql", matched.called_funcs)

        scanner = SASTScanner(self.test_dir, route_mapper=mapper)
        sast_findings = scanner.scan(reachable_files=mapper.get_reachable_files(), route_mapper=mapper)
        self.assertEqual(len(sast_findings), 2)

        # DAST specifically proves 'referral_code' is exploitable
        dast_referral = CanonicalFinding(
            id="dast_fastapi_ref",
            source=FindingSource.DAST,
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            url="http://127.0.0.1:8000/api/v1/checkout/apply",
            method="POST",
            param="referral_code",
            payload="' OR 1=1--",
            evidence="sqlite3.OperationalError",
        )
        correlator = Correlator(mapper)
        issues = correlator.correlate(sast_findings, [dast_referral])
        confirmed = [i for i in issues if i.status == IssueStatus.CONFIRMED]
        code_only = [i for i in issues if i.status == IssueStatus.CODE_ONLY]
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(len(code_only), 1)
        self.assertIn("referral_code", confirmed[0].code_snippet)
        self.assertIn("coupon_code", code_only[0].code_snippet)

    def test_phase5_unseen_app_sim_and_preflight_doctor_100pct_correlation(self):
        """
        Phase 5 Verification:
        Run the Unseen-App Pre-Flight Doctor (`tests.phase5_unseen_doctor`) against
        `tests/unseen_app_sim` and verify:
          - 12 routes discovered across multi-file Flask Blueprints with 0 unmapped decorators
          - 6 active SAST findings and 5 B-2 safe decoys suppressed (0% false alarms)
          - 5 Confirmed issues, 1 Code-Only issue, 1 Runtime-Only issue (100.0% correlation rate >= 65% Great threshold)
          - 1 Reachable SCA package (`pyyaml`), 1 Unreachable (`urllib3`), 1 Typosquat (`reqeusts`)
          - 90.0% DAST scope reduction (`Naive=60 -> Reduced=6`)
          - JSON and OASIS SARIF v2.1.0 export
        """
        from tests.phase5_unseen_doctor import run_phase5_unseen_doctor

        res = run_phase5_unseen_doctor(export_dir=self.test_dir)
        self.assertEqual(res["routes_discovered"], 12)
        self.assertEqual(len(res["unmapped_decorators"]), 0)
        self.assertEqual(res["active_sast_count"], 6)
        self.assertEqual(res["suppressed_decoy_count"], 5)
        self.assertEqual(res["confirmed_count"], 5)
        self.assertEqual(res["code_only_count"], 1)
        self.assertEqual(res["runtime_only_count"], 1)
        self.assertEqual(res["correlation_rate_pct"], 100.0)
        self.assertTrue(res["meets_great_threshold_gt_65_pct"])
        self.assertEqual(res["sca_findings_count"], 3)
        self.assertEqual(res["sca_reachable_count"], 1)
        self.assertEqual(res["scope_reduction"]["naive_probe_count"], 60)
        self.assertEqual(res["scope_reduction"]["reduced_probe_count"], 6)
        self.assertEqual(res["scope_reduction"]["probes_saved_pct"], 90.0)
        self.assertTrue(os.path.isfile(res["exported_json"]))
        self.assertTrue(os.path.isfile(res["exported_sarif"]))


if __name__ == "__main__":
    unittest.main()


