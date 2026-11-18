# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code.
"""Product listing that builds SQL with str.format, including a dynamic
ORDER BY column (which cannot be a bound parameter, so a correct fix needs
an allow-list)."""

import sqlite3


def list_products(conn: sqlite3.Connection, category: str, sort_column: str):
    sql = "SELECT name, price FROM products WHERE category = '{}' ORDER BY {}".format(category, sort_column)
    return conn.execute(sql).fetchall()
