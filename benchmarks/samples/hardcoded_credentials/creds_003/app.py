# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code. The credential below is fake.
"""Admin login helper with a hardcoded default password argument."""


def admin_login(host: str, username: str = "admin", password: str = "fake-benchmark-admin-003") -> dict:
    return {"host": host, "username": username, "password_length": len(password)}
