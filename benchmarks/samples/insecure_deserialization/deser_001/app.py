# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code.
"""Session loader that unpickles a client-supplied cookie."""

import base64
import pickle


def load_session(cookie_value: str) -> dict:
    raw = base64.b64decode(cookie_value)
    return pickle.loads(raw)
