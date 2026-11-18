# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code. The credential below is fake.
"""API client built with a token passed as a hardcoded keyword argument."""

from dataclasses import dataclass


@dataclass
class ApiClient:
    base_url: str
    token: str


def build_client() -> ApiClient:
    return ApiClient(base_url="https://api.example.invalid", token="fake-benchmark-token-002")
