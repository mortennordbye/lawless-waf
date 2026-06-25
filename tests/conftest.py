from __future__ import annotations

from pathlib import Path

import pytest

from lawless_waf.sample import write_sample


@pytest.fixture(scope="session")
def sample_path(tmp_path_factory) -> Path:
    """A synthetic WAF-log NDJSON file (no real/customer data)."""
    p = tmp_path_factory.mktemp("waf") / "merged.json"
    write_sample(p)
    return p


@pytest.fixture
def dataset(sample_path):
    from lawless_waf.cache import Dataset

    return Dataset(id="2026-06-24", date="2026-06-24", hour=None, merged_path=sample_path)


@pytest.fixture
def scope(dataset):
    from lawless_waf.cache import Scope

    return Scope((dataset,), None)


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import lawless_waf.settings as st
    from lawless_waf.ratelimit import limiter

    data_dir = tmp_path / "data"
    write_sample(data_dir / "2026-06-24" / "merged.json")
    # A second identical day so multi-day (?dataset=) and diff (?against=) paths are testable.
    write_sample(data_dir / "2026-06-23" / "merged.json")

    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("OFFLINE", "true")
    monkeypatch.setenv("CORS_ORIGINS", "")
    st._settings = None
    limiter.enabled = False  # rate limiting tested separately

    from lawless_waf.main import create_app

    app = create_app()
    yield TestClient(app)

    st._settings = None
    limiter.enabled = True
