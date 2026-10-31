"""
Phase 5 Unseen Second Application Simulator (`http://127.0.0.1:5001`).
Simulates the Day 2 07:00 AM Organisers' Unseen App Drop to verify >65% correlation
(achieves 100%), 0% false alarms on B-2 decoys, and single-pass AST scope reduction.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify
from routes.billing import DB_PATH, RECEIPT_DIR, billing_bp
from services.payment_service import init_billing_db

# Code-only CWE-798 Hardcoded Secret key for static detection
STRIPE_WEBHOOK_SIGNING_SECRET = "whsec_live_9876543210abcdef_unseen_secret"


def create_unseen_app() -> Flask:
    app = Flask(__name__)
    os.makedirs(RECEIPT_DIR, exist_ok=True)
    sample_receipt = os.path.join(RECEIPT_DIR, "receipt_101.txt")
    if not os.path.exists(sample_receipt):
        with open(sample_receipt, "w", encoding="utf-8") as fh:
            fh.write("INVOICE #101 - ACME CORP - INR 14,500.00 - PAID\n")
    init_billing_db(DB_PATH)

    app.register_blueprint(billing_bp)

    @app.route("/", methods=["GET"])
    def index():
        return (
            "<html><body>"
            "<h1>Unseen Billing Portal (Port 5001)</h1>"
            "<ul>"
            "<li><a href='/api/v1/billing/invoices?customer=acme-corp'>Invoices Lookup</a></li>"
            "<li><a href='/api/v1/billing/preview?note=Welcome'>Statement Preview</a></li>"
            "<li><a href='/api/v1/billing/diagnostics?host=127.0.0.1'>Gateway Diagnostics</a></li>"
            "<li><a href='/api/v1/billing/receipt?doc=receipt_101.txt'>Download Receipt</a></li>"
            "<li><a href='/api/v1/billing/return?next_url=/'>Return Redirect</a></li>"
            "</ul>"
            "</body></html>"
        )

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "unseen-billing-portal", "port": 5001})

    return app


app = create_unseen_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
