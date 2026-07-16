from __future__ import annotations

from pathlib import Path

import pytest

from lawless_waf.sample import write_sample


@pytest.fixture(scope="session")
def sample_path(tmp_path_factory) -> Path:
    """A synthetic Front Door WAF-log NDJSON file (no real/customer data)."""
    p = tmp_path_factory.mktemp("waf") / "merged.json"
    write_sample(p)
    return p


@pytest.fixture(scope="session")
def sample_path_appgw(tmp_path_factory) -> Path:
    """A synthetic Application Gateway WAF-log NDJSON file (no real/customer data)."""
    p = tmp_path_factory.mktemp("waf-appgw") / "merged.json"
    write_sample(p, waf_type="appgw")
    return p


@pytest.fixture
def dataset(sample_path):
    from lawless_waf.cache import Dataset

    return Dataset(
        id="frontdoor:2026-06-24", waf_type="frontdoor", date="2026-06-24", hour=None,
        merged_path=sample_path,
    )


@pytest.fixture
def dataset_appgw(sample_path_appgw):
    from lawless_waf.cache import Dataset

    return Dataset(
        id="appgw:2026-06-24", waf_type="appgw", date="2026-06-24", hour=None,
        merged_path=sample_path_appgw,
    )


@pytest.fixture
def scope(dataset):
    from lawless_waf.cache import Scope

    return Scope((dataset,), None)


@pytest.fixture
def scope_appgw(dataset_appgw):
    from lawless_waf.cache import Scope

    return Scope((dataset_appgw,), None)


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import lawless_waf.settings as st
    from lawless_waf.ratelimit import limiter

    data_dir = tmp_path / "data"
    write_sample(data_dir / "frontdoor" / "2026-06-24" / "merged.json")
    # A second identical day so multi-day (?dataset=) and diff (?against=) paths are testable.
    write_sample(data_dir / "frontdoor" / "2026-06-23" / "merged.json")
    # An Application Gateway day so the AppGw path is exercised end-to-end alongside Front Door.
    write_sample(data_dir / "appgw" / "2026-06-24" / "merged.json", waf_type="appgw")

    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("OFFLINE", "true")
    monkeypatch.setenv("CORS_ORIGINS", "")
    st._settings = None
    limiter.enabled = False  # rate limiting tested separately

    from lawless_waf.main import create_app

    app = create_app()
    # base_url sets the Host header: TestClient's default ("testserver") is rejected by the
    # host allowlist, same as any other non-local name.
    yield TestClient(app, base_url="http://localhost")

    st._settings = None
    limiter.enabled = True
