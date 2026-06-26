import subprocess
from pathlib import Path

import pytest

from lawless_waf.azure import downloader
from lawless_waf.azure.discovery import AzureCliError
from lawless_waf.azure.downloader import AzureConfig

CFG = AzureConfig(
    account="example-account",
    container="insights-logs-frontdoorwebapplicationfirewalllog",
    subscription="example-subscription",
)


def test_blob_pattern_day_and_hour():
    assert downloader.blob_pattern("2026-04-08", None) == "*/y=2026/m=04/d=08/*"
    assert downloader.blob_pattern("2026-04-08", 10) == "*/y=2026/m=04/d=08/h=10/*"


def test_download_argv_matches_runbook():
    argv = downloader.build_download_argv(CFG, "2026-04-08", None, Path("/tmp/raw"))
    assert argv == [
        "az", "storage", "blob", "download-batch",
        "--account-name", "example-account",
        "--source", "insights-logs-frontdoorwebapplicationfirewalllog",
        "--destination", "/tmp/raw",
        "--pattern", "*/y=2026/m=04/d=08/*",
        "--auth-mode", "login",
        "--subscription", "example-subscription",
    ]


def test_download_argv_overwrite_for_live_refresh():
    argv = downloader.build_download_argv(CFG, "2026-04-08", 10, Path("/tmp/raw"), overwrite=True)
    assert argv[-2:] == ["--overwrite", "true"]
    assert "--pattern" in argv and "*/y=2026/m=04/d=08/h=10/*" in argv


def test_merge_blobs(tmp_path):
    raw = tmp_path / "raw"
    (raw / "h00").mkdir(parents=True)
    (raw / "h01").mkdir(parents=True)
    (raw / "h00" / "PT5M.json").write_text('{"a":1}\n{"a":2}\n')
    (raw / "h01" / "PT5M.json").write_text('{"a":3}')  # no trailing newline
    merged = tmp_path / "merged.json"
    lines = downloader.merge_blobs(raw, merged)
    assert lines == 3
    assert merged.read_text().splitlines() == ['{"a":1}', '{"a":2}', '{"a":3}']


def test_merge_blobs_skips_truncated_blob(tmp_path):
    """A truncated blob (killed mid-download) is skipped, not merged — so the dataset stays valid
    NDJSON instead of becoming unreadable. The good blobs still come through."""
    raw = tmp_path / "raw"
    (raw / "h00").mkdir(parents=True)
    (raw / "h01").mkdir(parents=True)
    (raw / "h00" / "PT5M.json").write_text('{"a":1}\n{"a":2}\n')
    (raw / "h01" / "PT5M.json").write_text('{"a":3}\n{"a":4', encoding="utf-8")  # truncated last line
    merged = tmp_path / "merged.json"
    lines = downloader.merge_blobs(raw, merged)
    assert lines == 2
    assert merged.read_text().splitlines() == ['{"a":1}', '{"a":2}']


def test_download_surfaces_az_failure_as_actionable_error(tmp_path, monkeypatch):
    """An az failure becomes an AzureCliError with a real message — not a bare CalledProcessError
    that the API would turn into a generic 500."""
    def boom(*a, **k):
        raise subprocess.CalledProcessError(1, "az", stderr="ERROR: Please run 'az login' to setup account.")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(AzureCliError, match="not signed in"):
        downloader.download(CFG, "2026-04-08", None, tmp_path / "raw", tmp_path / "merged.json")
