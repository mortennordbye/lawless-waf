"""Download-size/ETA estimation: date expansion, the service aggregation, and the endpoint."""

import pytest

from lawless_waf import service
from lawless_waf.azure.downloader import AzureConfig
from lawless_waf.cache import DatasetCache

CFG = AzureConfig(account="acct", container="c", subscription="sub")


def test_expand_dates_inclusive():
    assert service._expand_dates("2026-06-23", "2026-06-25") == ["2026-06-23", "2026-06-24", "2026-06-25"]


def test_expand_dates_rejects_reversed():
    with pytest.raises(ValueError, match="before"):
        service._expand_dates("2026-06-25", "2026-06-23")


def test_expand_dates_rejects_huge_range():
    with pytest.raises(ValueError, match="exceeds"):
        service._expand_dates("2026-01-01", "2026-12-31")


def test_estimate_range_aggregates_and_skips_cached(tmp_path, monkeypatch):
    cache = DatasetCache(tmp_path)
    # Pre-seed 2026-06-24 so it counts as cached (its real on-disk size is read, no Azure call).
    (tmp_path / "frontdoor" / "2026-06-24").mkdir(parents=True)
    (tmp_path / "frontdoor" / "2026-06-24" / "merged.json").write_text("x" * 500)

    monkeypatch.setattr("lawless_waf.azure.estimate.discover_base_prefix", lambda cfg: "base")
    monkeypatch.setattr("lawless_waf.azure.estimate.day_bytes", lambda cfg, base, date, hour: (1_000_000, 12))

    out = service.estimate_range(
        cache, CFG, "2026-06-23", "2026-06-24", None, offline=False, blobs_per_sec=6.0
    )

    assert out["cached_days"] == 1
    assert out["download_bytes"] == 1_000_000  # only the uncached day is downloaded
    assert out["download_blob_count"] == 12
    assert out["on_disk_bytes"] == 1_000_500  # uncached estimate + cached file size
    assert out["estimated_seconds"] == 2.0  # 12 blobs / 6 per sec
    assert [d["cached"] for d in out["days"]] == [False, True]


def test_estimate_fully_cached_hour_needs_no_azure(tmp_path, monkeypatch):
    """A cached hour reports its real on-disk size without any Azure call."""
    cache = DatasetCache(tmp_path)
    hour_dir = tmp_path / "frontdoor" / "2026-06-25" / "h08"
    hour_dir.mkdir(parents=True)
    (hour_dir / "merged.json").write_text("x" * 1234)

    def boom(*a, **k):  # would fire only if we tried to reach Azure
        raise AssertionError("should not call Azure when everything is cached")

    monkeypatch.setattr("lawless_waf.azure.estimate.discover_base_prefix", boom)
    monkeypatch.setattr("lawless_waf.azure.estimate.day_bytes", boom)

    out = service.estimate_range(
        cache, CFG, "2026-06-25", "2026-06-25", 8, offline=False, blobs_per_sec=6.0
    )
    assert out["on_disk_bytes"] == 1234
    assert out["download_bytes"] == 0 and out["download_blob_count"] == 0
    assert out["cached_days"] == 1


def test_estimate_range_offline_raises(tmp_path):
    with pytest.raises(service.OfflineError):
        service.estimate_range(
            DatasetCache(tmp_path), CFG, "2026-06-23", "2026-06-24", None, offline=True, blobs_per_sec=6.0
        )


def test_estimate_endpoint_offline_409(client):
    r = client.post("/api/datasets/estimate", json={"date_from": "2026-06-23", "date_to": "2026-06-24"})
    assert r.status_code == 409


def test_estimate_endpoint_bad_range_422(client):
    r = client.post("/api/datasets/estimate", json={"date_from": "2026-06-25", "date_to": "2026-06-23"})
    assert r.status_code == 422


def test_estimate_endpoint_bad_date_format_422(client):
    r = client.post("/api/datasets/estimate", json={"date_from": "nope", "date_to": "2026-06-23"})
    assert r.status_code == 422


def test_speedtest_offline_raises(tmp_path):
    with pytest.raises(service.OfflineError):
        service.speedtest(CFG, offline=True)


def test_speedtest_returns_measured(monkeypatch):
    monkeypatch.setattr(
        "lawless_waf.azure.estimate.measure_rate",
        lambda cfg: {"blobs_per_sec": 8.0, "blobs": 12, "bytes": 1_000_000, "seconds": 1.5, "mbps": 0.7},
    )
    assert service.speedtest(CFG, offline=False)["blobs_per_sec"] == 8.0


def test_speedtest_endpoint_offline_409(client):
    assert client.post("/api/datasets/speedtest").status_code == 409
