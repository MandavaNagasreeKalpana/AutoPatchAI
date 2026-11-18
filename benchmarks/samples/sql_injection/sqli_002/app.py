# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code.
"""Order deletion that builds SQL with %-formatting."""

import sqlite3


def delete_order(conn: sqlite3.Connection, order_id: str) -> None:
    conn.execute("DELETE FROM orders WHERE id = %s" % order_id)
    conn.commit()
