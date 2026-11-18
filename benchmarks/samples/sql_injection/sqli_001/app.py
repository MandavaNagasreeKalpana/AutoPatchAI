# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code.
"""User lookup that builds SQL with an f-string."""

import sqlite3


def find_user(conn: sqlite3.Connection, username: str):
    cursor = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
