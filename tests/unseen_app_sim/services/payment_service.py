"""
Service helpers for the Phase 5 Unseen Second Application Simulator.
Demonstrates 2-hop cross-file call chains from routes/billing.py -> services/payment_service.py.
"""
import html
import os
import sqlite3
import subprocess
import yaml


def init_billing_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS invoices ("
        "id INTEGER PRIMARY KEY, customer TEXT, status TEXT, amount REAL)"
    )
    cur.execute("SELECT COUNT(*) FROM invoices")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO invoices (id, customer, status, amount) VALUES (?, ?, ?, ?)",
            [
                (101, "acme-corp", "PAID", 14500.0),
                (102, "globex-india", "OPEN", 28900.0),
                (103, "initech-blr", "OVERDUE", 9200.0),
            ],
        )
        conn.commit()
    conn.close()


def lookup_invoice_step1(db_path: str, customer: str):
    """Hop 1 helper forwarding tainted 'customer' parameter to Hop 2 SQL sink."""
    return execute_invoice_query_step2(db_path, customer)


def execute_invoice_query_step2(db_path: str, customer: str):
    """Hop 2 vulnerable SQL sink (CWE-89)."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # REAL VULNERABILITY (CWE-89): Unsanitized f-string SQL query
    query = f"SELECT id, customer, status, amount FROM invoices WHERE customer = '{customer}'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return [
        {"id": r[0], "customer": r[1], "status": r[2], "amount": r[3]}
        for r in rows
    ]


def lookup_invoice_safe_decoy(db_path: str, invoice_id: str):
    """B-2 Safe Decoy: Parameterized SQL query with ? placeholder."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, customer, status, amount FROM invoices WHERE id = ?", (invoice_id,))
    rows = cur.fetchall()
    conn.close()
    return [
        {"id": r[0], "customer": r[1], "status": r[2], "amount": r[3]}
        for r in rows
    ]


def run_settlement_gateway_check(gateway_host: str) -> str:
    """Real CWE-78 Command Injection sink in service helper."""
    cmd = f"echo Checking gateway {gateway_host}"
    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    return output.strip()


def run_safe_gateway_decoy(gateway_host: str) -> str:
    """B-2 Safe Decoy: subprocess.run with shell=False and list arguments."""
    res = subprocess.run(["echo", gateway_host], shell=False, capture_output=True, text=True, check=False)
    return res.stdout.strip()


def render_safe_notice_decoy(memo: str) -> str:
    """B-2 Safe Decoy: html.escape prevents Reflected XSS."""
    safe_memo = html.escape(memo, quote=True)
    return f"<div class='safe-memo'>{safe_memo}</div>"


def parse_settlement_manifest(raw_yaml: str):
    """Reachable SCA sink calling vulnerable yaml.load (CVE-2020-14343)."""
    if not raw_yaml:
        return {"status": "empty"}
    return yaml.load(raw_yaml, Loader= getattr(yaml, "Loader", None))
