"""
Order Service Helper Module (1-hop & 2-hop call graph target).
"""

import html
import sqlite3

_SEED_SQL = (
    "DROP TABLE IF EXISTS orders;"
    "CREATE TABLE orders (id TEXT PRIMARY KEY, item TEXT, customer TEXT, amount TEXT, status TEXT);"
    "INSERT INTO orders VALUES ('1', 'MacBook Pro 16 M3 Max (64GB)', 'Aarav Sharma', 'Rs. 3,49,900', 'DELIVERED');"
    "INSERT INTO orders VALUES ('2', 'CyberForge Hardware HSM Vault', 'Priya Nair', 'Rs. 1,85,000', 'SHIPPED');"
    "INSERT INTO orders VALUES ('3', 'Zero-Trust Enterprise Firewall', 'Vikram Rao', 'Rs. 4,20,000', 'PROCESSING');"
    "INSERT INTO orders VALUES ('99', 'CONFIDENTIAL: Root Master Key Backup', 'Admin Vault', 'Rs. 99,99,999', 'RESTRICTED');"
)


def fetch_order_by_id(id):
    conn = sqlite3.connect("shop.db")
    conn.executescript(_SEED_SQL)
    # Planted Pair (CWE-89): Two-step variable SQLi (assigned to query, then passed to execute)
    query = f"SELECT * FROM orders WHERE id = '{id}'"
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        return f"order_data | matched={len(rows)} | rows={rows}"
    except Exception as exc:
        return f"sqlite3.OperationalError: {html.escape(str(exc))}", 500


def fetch_order_safe_parameterized(id):
    conn = sqlite3.connect("shop.db")
    conn.executescript(_SEED_SQL)
    # Safe Decoy 8 (CWE-89 B-2): Parameterized SQL query with bound tuple
    sql = "SELECT * FROM orders WHERE id = ?"
    cursor = conn.execute(sql, (id,))
    rows = cursor.fetchall()
    return f"safe_order_data | matched={len(rows)} | rows={rows}"
