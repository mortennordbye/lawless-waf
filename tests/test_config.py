"""Config store + azure status endpoints."""


def test_config_defaults_then_update(client):
    r = client.get("/api/config")
    assert r.status_code == 200
    assert r.json()["storage_account"] == "your-storage-account"  # placeholder default

    new = {"storage_account": "myacct", "container": "mycontainer", "subscription": "My Sub"}
    put = client.put("/api/config", json=new)
    assert put.status_code == 200 and put.json() == new

    # persisted
    assert client.get("/api/config").json() == new


def test_config_validation(client):
    payload = {"storage_account": "", "container": "c", "subscription": "s"}
    bad = client.put("/api/config", json=payload)
    assert bad.status_code == 422


def test_azure_status_shape(client, monkeypatch):
    from lawless_waf.azure.session import AzureStatus

    monkeypatch.setattr(
        "lawless_waf.api.azure.az_status",
        lambda: AzureStatus(logged_in=True, user="me@x", subscription="Sub", subscription_id="123"),
    )
    r = client.get("/api/azure/status")
    assert r.status_code == 200
    assert r.json()["logged_in"] is True and r.json()["user"] == "me@x"
