"""Config store + azure status endpoints."""


def test_config_defaults_then_update(client):
    r = client.get("/api/config")
    assert r.status_code == 200
    assert r.json()["storage_account"] == "your-storage-account"  # placeholder default

    new = {"storage_account": "myacct", "container": "mycontainer", "subscription": "My Sub"}
    saved = {**new, "waf_type": "frontdoor"}  # waf_type is derived from the container name
    put = client.put("/api/config", json=new)
    assert put.status_code == 200 and put.json() == saved

    # persisted
    assert client.get("/api/config").json() == saved


def test_config_derives_appgw_waf_type_from_container(client):
    appgw = {
        "storage_account": "a", "container": "insights-logs-applicationgatewayfirewalllog",
        "subscription": "s",
    }
    assert client.put("/api/config", json=appgw).json()["waf_type"] == "appgw"
    # An explicit waf_type overrides the container-name guess.
    override = {**appgw, "container": "custom-container", "waf_type": "appgw"}
    assert client.put("/api/config", json=override).json()["waf_type"] == "appgw"


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
