"""
Blueprint routes for the Phase 5 Unseen Second Application Simulator.
Mounted at `/api/v1/billing` in `app.py`.
"""
import os
from flask import Blueprint, jsonify, redirect, request
from services.payment_service import (
    lookup_invoice_safe_decoy,
    lookup_invoice_step1,
    parse_settlement_manifest,
    render_safe_notice_decoy,
    run_safe_gateway_decoy,
    run_settlement_gateway_check,
)

billing_bp = Blueprint("billing_bp", __name__, url_prefix="/api/v1/billing")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "unseen_billing.db")
RECEIPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "receipts")


@billing_bp.route("/invoices", methods=["GET"])
def search_invoices():
    """
    Vulnerable Route 1 (CWE-89 SQL Injection via 2-hop helper chain):
    GET /api/v1/billing/invoices?customer=acme-corp
    """
    customer = request.args.get("customer", "acme-corp")
    rows = lookup_invoice_step1(DB_PATH, customer)
    return jsonify({"invoices": rows, "count": len(rows)})


@billing_bp.route("/invoices/safe", methods=["GET"])
def search_invoices_safe():
    """
    B-2 Safe Decoy Route (Parameterized SQL):
    GET /api/v1/billing/invoices/safe?invoice_id=101
    """
    invoice_id = request.args.get("invoice_id", "101")
    rows = lookup_invoice_safe_decoy(DB_PATH, invoice_id)
    return jsonify({"invoices": rows})


@billing_bp.route("/preview", methods=["GET"])
def preview_statement():
    """
    Vulnerable Route 2 (CWE-79 Reflected XSS):
    GET /api/v1/billing/preview?note= Q4-Statement
    """
    note = request.args.get("note", "Statement Ready")
    return f"<html><body><h2>Billing Statement Preview</h2><div class='banner'>{note}</div></body></html>"


@billing_bp.route("/preview/safe", methods=["GET"])
def preview_statement_safe():
    """
    B-2 Safe Decoy Route (html.escape):
    GET /api/v1/billing/preview/safe?memo=test
    """
    memo = request.args.get("memo", "Safe Memo")
    return render_safe_notice_decoy(memo)


@billing_bp.route("/diagnostics", methods=["GET", "POST"])
def gateway_diagnostics():
    """
    Vulnerable Route 3 (CWE-78 Command Injection via helper):
    GET/POST /api/v1/billing/diagnostics?host=127.0.0.1
    """
    host = request.values.get("host", "127.0.0.1")
    output = run_settlement_gateway_check(host)
    return jsonify({"gateway_output": output})


@billing_bp.route("/diagnostics/safe", methods=["GET"])
def gateway_diagnostics_safe():
    """
    B-2 Safe Decoy Route (subprocess shell=False):
    GET /api/v1/billing/diagnostics/safe?host=127.0.0.1
    """
    host = request.args.get("host", "127.0.0.1")
    output = run_safe_gateway_decoy(host)
    return jsonify({"gateway_output": output})


@billing_bp.route("/receipt", methods=["GET"])
def download_receipt():
    """
    Vulnerable Route 4 (CWE-22 Path Traversal):
    GET /api/v1/billing/receipt?doc=receipt_101.txt
    """
    doc = request.args.get("doc", "receipt_101.txt")
    target_path = os.path.join(RECEIPT_DIR, doc)
    with open(target_path, "r", encoding="utf-8", errors="ignore") as fh:
        content = fh.read()
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}


@billing_bp.route("/return", methods=["GET"])
def portal_return_redirect():
    """
    Vulnerable Route 5 (CWE-601 Open Redirect):
    GET /api/v1/billing/return?next_url=/dashboard
    """
    next_url = request.args.get("next_url", "/api/v1/billing/invoices")
    return redirect(next_url)


@billing_bp.route("/manifest", methods=["POST"])
def import_billing_manifest():
    """
    Reachable SCA Endpoint (yaml.load CVE-2020-14343):
    POST /api/v1/billing/manifest
    """
    raw_yaml = request.values.get("manifest", "version: 1")
    parsed = parse_settlement_manifest(raw_yaml)
    return jsonify({"parsed": parsed})
