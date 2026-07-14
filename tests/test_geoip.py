"""GeoIP: opt-in gating, IP validation, and the local private-address path."""

import pytest

from lawless_waf.api import geoip


@pytest.fixture(autouse=True)
def _clear_cache():
    geoip._cache.clear()
    yield
    geoip._cache.clear()


@pytest.fixture
def no_outbound(monkeypatch):
    """Fail loudly if anything tries to reach ip-api.com."""
    calls = []

    def boom(ips):
        calls.append(ips)
        raise AssertionError(f"unexpected outbound geoip lookup for {ips}")

    monkeypatch.setattr(geoip, "_batch_lookup", boom)
    return calls


def test_disabled_by_default_returns_unknown_without_calling_out(client, no_outbound):
    r = client.post("/api/geoip", json={"ips": ["8.8.8.8"]})
    assert r.status_code == 200
    assert r.json()["results"]["8.8.8.8"] == geoip._UNKNOWN_RESULT


def test_private_ips_resolve_locally_even_when_disabled(client, no_outbound):
    r = client.post("/api/geoip", json={"ips": ["10.0.0.1", "127.0.0.1"]})
    results = r.json()["results"]
    assert results["10.0.0.1"] == geoip._PRIVATE_RESULT
    assert results["127.0.0.1"] == geoip._PRIVATE_RESULT


def test_non_ip_strings_are_never_forwarded(client, monkeypatch, no_outbound):
    monkeypatch.setenv("GEOIP_ENABLED", "true")
    import lawless_waf.settings as st

    st._settings = None
    r = client.post("/api/geoip", json={"ips": ["not-an-ip", "'; DROP TABLE--"]})
    results = r.json()["results"]
    assert results["not-an-ip"] == geoip._UNKNOWN_RESULT
    assert results["'; DROP TABLE--"] == geoip._UNKNOWN_RESULT
    assert no_outbound == []
    st._settings = None


def test_enabled_flag_permits_lookup(client, monkeypatch):
    monkeypatch.setenv("GEOIP_ENABLED", "true")
    import lawless_waf.settings as st

    st._settings = None
    monkeypatch.setattr(
        geoip,
        "_batch_lookup",
        lambda ips: {ip: {"country_code": "NO", "country": "Norway", "flag": "🇳🇴"} for ip in ips},
    )
    r = client.post("/api/geoip", json={"ips": ["8.8.8.8"]})
    assert r.json()["results"]["8.8.8.8"]["country"] == "Norway"
    st._settings = None


def test_transient_failure_does_not_poison_the_cache(client, monkeypatch):
    """A network blip must not pin an IP to Unknown until the process restarts — the next
    request retries it."""
    monkeypatch.setenv("GEOIP_ENABLED", "true")
    import lawless_waf.settings as st

    st._settings = None
    calls: list[list[str]] = []

    def flaky(ips):
        calls.append(ips)
        if len(calls) == 1:
            return {}  # first call: the lookup failed
        return {ip: {"country_code": "NO", "country": "Norway", "flag": "🇳🇴"} for ip in ips}

    monkeypatch.setattr(geoip, "_batch_lookup", flaky)
    r = client.post("/api/geoip", json={"ips": ["8.8.8.8"]})
    assert r.json()["results"]["8.8.8.8"] == geoip._UNKNOWN_RESULT
    assert "8.8.8.8" not in geoip._cache  # nothing cached, so recovery is visible

    r = client.post("/api/geoip", json={"ips": ["8.8.8.8"]})
    assert r.json()["results"]["8.8.8.8"]["country"] == "Norway"
    st._settings = None


def test_disabled_result_is_not_cached(client, monkeypatch):
    """A public IP seen while disabled must still be resolvable once enabled."""
    client.post("/api/geoip", json={"ips": ["8.8.8.8"]})
    assert "8.8.8.8" not in geoip._cache

    monkeypatch.setenv("GEOIP_ENABLED", "true")
    import lawless_waf.settings as st

    st._settings = None
    monkeypatch.setattr(
        geoip,
        "_batch_lookup",
        lambda ips: {ip: {"country_code": "NO", "country": "Norway", "flag": "🇳🇴"} for ip in ips},
    )
    r = client.post("/api/geoip", json={"ips": ["8.8.8.8"]})
    assert r.json()["results"]["8.8.8.8"]["country"] == "Norway"
    st._settings = None
