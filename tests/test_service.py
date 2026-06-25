import pytest

from lawless_waf import service
from lawless_waf.azure.downloader import AzureConfig
from lawless_waf.cache import Dataset, DatasetCache, Scope
from lawless_waf.sample import write_sample


def test_exclusion_context_headline(scope):
    """The FP cookie is excludable+false_positive; the scanner's hits on the same rule are noise."""
    ctx = service.exclusion_context(scope, "942100")
    by_mv = {c["match_variable_name"]: c for c in ctx["contexts"]}

    fp = by_mv["CookieValue:sessionId"]
    assert fp["classification"] == "false_positive"
    assert fp["terraform"] == {"match_variable": "RequestCookieNames", "selector": "sessionId"}
    assert fp["scanner_share"] == 0.0

    assert by_mv["QueryParamValue:q"]["classification"] == "scanner_noise"


def test_exclusion_context_not_excludable(scope):
    ctx = service.exclusion_context(scope, "942100")
    by_mv = {c["match_variable_name"]: c for c in ctx["contexts"]}
    assert by_mv["InitialBodyContents"]["classification"] == "not_excludable"
    assert by_mv["InitialBodyContents"]["terraform"] is None
    assert by_mv["InitialBodyContents"]["not_excludable_reason"]


def test_request_detail_parses_anomaly_score(scope):
    """The full-request view stitches all rows for a tracking ref and reads the score."""
    detail = service.request_detail(scope, "fp-0")
    assert detail["anomaly_score"] == 8  # from the blocking-evaluation message
    actions = {r["action"] for r in detail["rows"]}
    assert {"Block", "AnomalyScoring"} <= actions
    scored = next(r for r in detail["rows"] if r["action"] == "AnomalyScoring")
    assert "CookieValue:sessionId" in scored["match_variable_names"]


def test_diff_rule_resolved(scope, tmp_path):
    """Before has the FP firing; after (scanner-only) has it gone -> resolved."""
    after_path = tmp_path / "after.json"
    after_path.write_text(_scanner_only_ndjson())
    after = Scope((Dataset(id="after", date="2026-06-30", hour=None, merged_path=after_path),), None)

    d = service.diff_rule(scope, after, "942100", match_variable="CookieValue:sessionId")
    assert d["before_hits"] == 2
    assert d["after_hits"] == 0
    assert d["resolved"] is True
    assert d["match_variables"][0]["status"] == "resolved"


def test_multi_day_doubles_volume(scope, sample_path):
    """A scope spanning two copies of the same day sees twice the events."""
    one = service.summary(scope)
    two_scope = Scope(
        (
            scope.datasets[0],
            Dataset(id="dup", date="2026-06-30", hour=None, merged_path=sample_path),
        ),
        None,
    )
    two = service.summary(two_scope)
    assert two["actions"]["Block"] == one["actions"]["Block"] * 2


def _scanner_only_ndjson() -> str:
    """A reduced day: the scanner's SQLI hits but none of the FP cookie rows."""
    import json

    from lawless_waf.sample import HOST, SCANNER_IP, SQLI, _rec

    recs = [
        _rec(SCANNER_IP, f"https://{HOST}/p{i}", "AnomalyScoring", SQLI, f"s-{i}",
             "QueryParamValue:q", "1 UNION SELECT", "SQL Injection")
        for i in range(3)
    ]
    return "\n".join(json.dumps(r) for r in recs) + "\n"


def test_ensure_dataset_offline_refuses(tmp_path):
    cache = DatasetCache(tmp_path)
    cfg = AzureConfig("acct", "container", "sub")
    with pytest.raises(service.OfflineError):
        service.ensure_dataset(cache, cfg, "2026-01-01", None, force=False, offline=True)


def test_ensure_dataset_cached_no_download(tmp_path, monkeypatch):
    cache = DatasetCache(tmp_path)
    write_sample(tmp_path / "2026-06-24" / "merged.json")

    def boom(*a, **k):
        raise AssertionError("download must not be called for a cached dataset")

    monkeypatch.setattr("lawless_waf.service.downloader.download", boom)
    meta = service.ensure_dataset(
        cache, AzureConfig("a", "c", "s"), "2026-06-24", None, force=False, offline=False
    )
    assert meta["cached"] is True
    assert meta["line_count"] == 48


def test_stream_dataset_cached_yields_single_event(tmp_path, monkeypatch):
    cache = DatasetCache(tmp_path)
    write_sample(tmp_path / "2026-06-24" / "merged.json")

    def boom(*a, **k):
        raise AssertionError("download must not run for a cached dataset")

    monkeypatch.setattr("lawless_waf.service.downloader.download", boom)
    events = list(
        service.stream_dataset(cache, AzureConfig("a", "c", "s"), "2026-06-24", None, False, offline=False)
    )
    assert [e["phase"] for e in events] == ["cached"]
    assert events[0]["dataset"]["cached"] is True


def test_stream_dataset_offline_errors(tmp_path):
    cache = DatasetCache(tmp_path)
    events = list(
        service.stream_dataset(cache, AzureConfig("a", "c", "s"), "2026-01-01", None, False, offline=True)
    )
    assert [e["phase"] for e in events] == ["error"]


def test_stream_dataset_reports_progress_and_done(tmp_path, monkeypatch):
    cache = DatasetCache(tmp_path)

    def fake_download(cfg, date, hour, raw_dir, merged_path, overwrite=False):
        write_sample(merged_path)  # the merged file the "done" event reports on
        return 48

    monkeypatch.setattr("lawless_waf.service.downloader.download", fake_download)
    events = list(
        service.stream_dataset(
            cache, AzureConfig("a", "c", "s"), "2026-06-24", None, False, offline=False, total=5
        )
    )
    phases = [e["phase"] for e in events]
    assert phases[0] == "start" and phases[-1] == "done"  # total supplied → no "listing"
    assert all(e.get("total") == 5 for e in events if e["phase"] in {"start", "progress"})
    assert events[-1]["dataset"]["cached"] is False
    assert not cache.lock_path("2026-06-24", None).exists()  # lock released


def test_stream_dataset_lists_when_total_unknown(tmp_path, monkeypatch):
    cache = DatasetCache(tmp_path)
    monkeypatch.setattr("lawless_waf.service.downloader.download", lambda *a, **k: write_sample(a[4]) or 48)
    monkeypatch.setattr("lawless_waf.service._discover_blob_count", lambda *a: 7)
    events = list(
        service.stream_dataset(cache, AzureConfig("a", "c", "s"), "2026-06-24", None, False, offline=False)
    )
    phases = [e["phase"] for e in events]
    assert phases[0] == "listing"
    assert events[-1]["phase"] == "done"


def test_ensure_dataset_force_overwrites(tmp_path, monkeypatch):
    """A forced re-download must overwrite local blobs (live tailing of the current hour)."""
    cache = DatasetCache(tmp_path)
    write_sample(tmp_path / "2026-06-24" / "merged.json")
    seen = {}

    def fake_download(cfg, date, hour, raw_dir, merged_path, overwrite=False):
        seen["overwrite"] = overwrite
        return 0

    monkeypatch.setattr("lawless_waf.service.downloader.download", fake_download)
    service.ensure_dataset(
        cache, AzureConfig("a", "c", "s"), "2026-06-24", None, force=True, offline=False
    )
    assert seen["overwrite"] is True
