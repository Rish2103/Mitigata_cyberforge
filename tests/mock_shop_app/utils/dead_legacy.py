"""
Completely unreachable legacy file (B-2 Dead File Decoy).
Never imported or invoked by any route.
"""

import sqlite3


def legacy_migration_query(user_filter):
    conn = sqlite3.connect("legacy.db")
    conn.execute(f"DELETE FROM old_users WHERE filter = '{user_filter}'")
