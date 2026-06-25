from pathlib import Path

from lawless_waf.azure import downloader
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
