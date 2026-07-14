"""Azure resource discovery: az JSON parsing + the cascading API endpoints (mocked az)."""

import subprocess
from types import SimpleNamespace

import pytest

from lawless_waf.azure import discovery


def _proc(returncode=0, stdout="[]", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_list_subscriptions_parses(monkeypatch):
    stdout = '[{"id":"s1","name":"Prod","isDefault":true},{"id":"s2","name":"Dev","isDefault":false}]'
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _proc(stdout=stdout))
    subs = discovery.list_subscriptions()
    assert subs == [
        {"id": "s1", "name": "Prod", "is_default": True},
        {"id": "s2", "name": "Dev", "is_default": False},
    ]


def test_list_storage_accounts_sorted(monkeypatch):
    stdout = '[{"name":"zacct","resourceGroup":"rg1"},{"name":"aacct","resourceGroup":"rg2"}]'
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _proc(stdout=stdout))
    accts = discovery.list_storage_accounts("Prod")
    assert [a["name"] for a in accts] == ["aacct", "zacct"]


def test_not_signed_in_raises(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _proc(returncode=1, stderr="Please run 'az login' to setup account."),
    )
    with pytest.raises(discovery.AzureCliError, match="not signed in"):
        discovery.list_subscriptions()


def test_blob_auth_denied_maps_to_actionable_hint(monkeypatch):
    """az's cryptic '--auth-mode key' line becomes a stale-token / missing-role hint."""
    stderr = (
        "You do not have the required permissions needed to perform this operation.\n"
        'If you want to use the old authentication method and allow querying for the '
        'right account key, please use the "--auth-mode" parameter and "key" value.'
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _proc(returncode=1, stderr=stderr))
    with pytest.raises(discovery.AzureCliError, match="az logout && az login"):
        discovery.list_containers("acct", "Prod")


def test_error_line_wins_over_trailing_notice():
    """az often ends stderr with an unrelated notice; the ERROR: line is the real cause."""
    stderr = (
        "WARNING: the default action is deny.\n"
        "ERROR: The specified container does not exist.\n"
        "If you want to change the default action to apply when no rule matches, "
        "please use 'az storage account update'."
    )
    assert discovery.az_error_detail(stderr) == "The specified container does not exist."


def test_unrecognized_stderr_is_attributed_to_az():
    assert discovery.az_error_detail("something odd happened") == "az: something odd happened"


def test_empty_stderr_falls_back():
    assert discovery.az_error_detail("") == "az command failed"
    assert discovery.az_error_detail(None) == "az command failed"


def test_subscriptions_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        "lawless_waf.api.azure.discovery.list_subscriptions",
        lambda: [{"id": "s1", "name": "Prod", "is_default": True}],
    )
    r = client.get("/api/azure/subscriptions")
    assert r.status_code == 200
    assert r.json()["subscriptions"][0]["name"] == "Prod"


def test_storage_accounts_endpoint_requires_subscription(client):
    assert client.get("/api/azure/storage-accounts").status_code == 422


def test_containers_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        "lawless_waf.api.azure.discovery.list_containers",
        lambda account, subscription: [{"name": "insights-logs"}],
    )
    r = client.get("/api/azure/containers?account=acct&subscription=Prod")
    assert r.status_code == 200
    assert r.json()["containers"] == [{"name": "insights-logs"}]


def test_endpoint_surfaces_az_failure_as_502(client, monkeypatch):
    def boom():
        raise discovery.AzureCliError("az timed out — check the VPN connection")

    monkeypatch.setattr("lawless_waf.api.azure.discovery.list_subscriptions", boom)
    r = client.get("/api/azure/subscriptions")
    assert r.status_code == 502
    assert "VPN" in r.json()["detail"]
