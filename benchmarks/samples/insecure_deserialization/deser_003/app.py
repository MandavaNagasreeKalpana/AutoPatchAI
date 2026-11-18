# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code.
"""Cache reader that unmarshals bytes from a file whose path is caller-controlled."""

import marshal
from pathlib import Path


def read_cache(path: str):
    data = Path(path).read_bytes()
    return marshal.loads(data)
