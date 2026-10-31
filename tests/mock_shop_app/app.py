"""
Mock Online Web Shop Application (Pre-Kickoff & Benchmark Test Harness).
Includes:
- Multi-file Flask routes + Blueprints (/api/orders, /api/search, /api/ping, /api/invoice, /api/redirect)
- All 6 Hackathon CWEs (CWE-89, CWE-79, CWE-78, CWE-22, CWE-601, CWE-798)
- 8 Planted Safe Decoys (parameterized SQL, shell=False, html.escape, secure_filename, realpath+startswith,
  url_has_allowed_host_and_scheme, startswith('/'), and dead unreachable functions/files)
- Library calls for Page 4 Reachability-Aware SCA (yaml.load reachable from /api/config/import)
"""

import html
import os
import shlex
import sqlite3
import subprocess
import yaml
import requests
from flask import Flask, request, redirect, render_template_string, send_file
from werkzeug.utils import secure_filename
from routes.orders import orders_bp

app = Flask(__name__)

# Planted Code-Only Bug 1 (CWE-798): Hard-coded production secret
STRIPE_LIVE_SECRET_KEY = "sk_live_998877665544332211_mitigata_shop"
app.config["JWT_SECRET_KEY"] = "jwt_prod_signing_secret_2026_cyberforge"

app.register_blueprint(orders_bp, url_prefix="/api")

UPLOAD_DIR = "/var/www/shop/invoices"


@app.route("/api/search", methods=["GET"])
def search_products():
    q = request.args.get("q", "")
    # Planted Pair (CWE-79): Unescaped reflection in render_template_string
    return render_template_string(f"<div class='results'>Search results for: {q}</div>")


@app.route("/api/search/safe", methods=["GET"])
def search_products_safe():
    q = request.args.get("q", "")
    # Safe Decoy 1 (CWE-79 B-2): Explicitly escaped with html.escape()
    clean_q = html.escape(q)
    return render_template_string(f"<div class='results'>Safe results for: {clean_q}</div>")


@app.route("/api/diagnostics/ping", methods=["POST"])
def ping_warehouse():
    host = request.form.get("host", "127.0.0.1")
    # Planted Pair (CWE-78): OS Command Injection via os.system with f-string
    cmd = f"ping -c 1 {host}"
    os.system(cmd)
    return "Ping executed"


@app.route("/api/diagnostics/ping-safe-list", methods=["POST"])
def ping_warehouse_safe_list():
    host = request.form.get("host", "127.0.0.1")
    # Safe Decoy 2 (CWE-78 B-2): Argument vector list with shell=False
    subprocess.run(["ping", "-c", "1", host], shell=False)
    return "Safe ping executed"


@app.route("/api/diagnostics/ping-safe-quote", methods=["POST"])
def ping_warehouse_safe_quote():
    host = request.form.get("host", "127.0.0.1")
    # Safe Decoy 3 (CWE-78 B-2): Sanitized via shlex.quote
    os.system(f"ping -c 1 {shlex.quote(host)}")
    return "Quoted ping executed"


@app.route("/api/invoices/download", methods=["GET"])
def download_invoice():
    doc = request.args.get("doc", "inv.pdf")
    # Planted Pair (CWE-22): Path Traversal via unvalidated path join
    target_path = f"{UPLOAD_DIR}/{doc}"
    return send_file(target_path)


@app.route("/api/invoices/download-safe-werkzeug", methods=["GET"])
def download_invoice_safe_werkzeug():
    doc = request.args.get("doc", "inv.pdf")
    # Safe Decoy 4 (CWE-22 B-2): Sanitized via werkzeug.utils.secure_filename
    safe_name = secure_filename(doc)
    return send_file(f"{UPLOAD_DIR}/{safe_name}")


@app.route("/api/invoices/download-safe-realpath", methods=["GET"])
def download_invoice_safe_realpath():
    doc = request.args.get("doc", "inv.pdf")
    # Safe Decoy 5 (CWE-22 B-2): Canonicalized with os.path.realpath + startswith check
    candidate = os.path.realpath(os.path.join(UPLOAD_DIR, doc))
    if not candidate.startswith(os.path.realpath(UPLOAD_DIR)):
        return "Forbidden", 403
    return open(candidate, "rb").read()


@app.route("/api/checkout/redirect", methods=["GET"])
def checkout_redirect():
    next_url = request.args.get("next", "/home")
    # Planted Pair (CWE-601): Unvalidated Open Redirect
    return redirect(next_url)


@app.route("/api/checkout/redirect-safe", methods=["GET"])
def checkout_redirect_safe():
    next_url = request.args.get("next", "/home")
    # Safe Decoy 6 (CWE-601 B-2): Relative path check startswith('/')
    if not next_url.startswith("/"):
        next_url = "/home"
    return redirect(next_url)


@app.route("/api/config/import", methods=["POST"])
def import_yaml_config():
    raw_yaml = request.form.get("config", "")
    # Page 4 Bonus SCA Reachable Call: yaml.load reachable from POST /api/config/import
    parsed = yaml.load(raw_yaml, Loader=yaml.FullLoader)
    return str(parsed)


def dead_unreachable_helper_in_active_file(raw_id):
    # Safe Decoy 7 (B-2 Dead Function inside active file): Never called by any route!
    conn = sqlite3.connect("shop.db")
    conn.execute(f"SELECT * FROM archived_orders WHERE id = {raw_id}")
