# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code.
"""Config parser that loads untrusted YAML with the full (unsafe) loader."""

import yaml


def parse_config(text: str) -> dict:
    return yaml.load(text, Loader=yaml.Loader)
