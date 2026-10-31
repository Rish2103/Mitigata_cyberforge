"""
Order Service Helper Module (1-hop & 2-hop call graph target).
"""

import sqlite3


def fetch_order_by_id(id):
    conn = sqlite3.connect("shop.db")
    # Planted Pair (CWE-89): Two-step variable SQLi (assigned to query, then passed to execute)
    query = f"SELECT * FROM orders WHERE id = '{id}'"
    cursor = conn.cursor()
    cursor.execute(query)
    return "order_data"


def fetch_order_safe_parameterized(id):
    conn = sqlite3.connect("shop.db")
    # Safe Decoy 8 (CWE-89 B-2): Parameterized SQL query with bound tuple
    sql = "SELECT * FROM orders WHERE id = ?"
    conn.execute(sql, (id,))
    return "safe_order_data"
