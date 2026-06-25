"""Deleting cached datasets: cache layer + the DELETE endpoints."""

from lawless_waf.cache import DatasetCache


def _seed(cache: DatasetCache, date: str, hour: int | None) -> None:
    ds = cache.resolve(date, hour)
    ds.merged_path.parent.mkdir(parents=True, exist_ok=True)
    ds.merged_path.write_text("{}\n")


def test_delete_hour_keeps_day(tmp_path):
    cache = DatasetCache(tmp_path)
    _seed(cache, "2026-06-24", None)
    _seed(cache, "2026-06-24", 10)

    assert cache.delete("2026-06-24-h10") is True
    assert not cache.resolve("2026-06-24", 10).exists
    assert cache.resolve("2026-06-24", None).exists  # day survives


def test_delete_day_keeps_hour(tmp_path):
    cache = DatasetCache(tmp_path)
    _seed(cache, "2026-06-24", None)
    _seed(cache, "2026-06-24", 10)

    assert cache.delete("2026-06-24") is True
    assert not cache.resolve("2026-06-24", None).exists
    assert cache.resolve("2026-06-24", 10).exists  # hour survives


def test_delete_missing_returns_false(tmp_path):
    assert DatasetCache(tmp_path).delete("2099-01-01") is False


def test_clear_removes_all(tmp_path):
    cache = DatasetCache(tmp_path)
    _seed(cache, "2026-06-23", None)
    _seed(cache, "2026-06-24", None)
    _seed(cache, "2026-06-24", 10)

    assert cache.clear() == 3
    assert cache.list() == []


def test_delete_endpoint(client):
    assert any(d["dataset_id"] == "2026-06-24" for d in client.get("/api/datasets").json()["datasets"])
    r = client.delete("/api/datasets/2026-06-24")
    assert r.status_code == 200 and r.json()["deleted"] is True
    remaining = [d["dataset_id"] for d in client.get("/api/datasets").json()["datasets"]]
    assert "2026-06-24" not in remaining


def test_delete_unknown_dataset_404(client):
    assert client.delete("/api/datasets/2099-01-01").status_code == 404


def test_delete_invalid_dataset_422(client):
    assert client.delete("/api/datasets/not-a-date").status_code == 422


def test_clear_endpoint(client):
    r = client.delete("/api/datasets")
    assert r.status_code == 200 and r.json()["deleted"] >= 1
    assert client.get("/api/datasets").json()["datasets"] == []
