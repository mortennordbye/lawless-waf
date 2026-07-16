"""Persisted, operator-editable Azure target config (storage account / container /
subscription). Stored as JSON under DATA_DIR; falls back to the env defaults in settings.

Kept separate from :mod:`.settings` (process/secrets config) because this is data the user
edits at runtime from the web UI, not deploy-time configuration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from .azure.downloader import AzureConfig
from .duck.schema import APP_GATEWAY, FRONT_DOOR
from .settings import Settings

CONFIG_FILENAME = "config.json"


def waf_type_for_container(container: str) -> str:
    """Guess the WAF product from an Azure diagnostic-log container name. Application Gateway
    writes ``insights-logs-applicationgatewayfirewalllog``; Front Door writes
    ``...frontdoorwebapplicationfirewalllog``. Anything else defaults to Front Door."""
    return APP_GATEWAY if "applicationgateway" in container.lower() else FRONT_DOOR


class AzureTarget(BaseModel):
    storage_account: str = Field(min_length=1, max_length=200)
    container: str = Field(min_length=1, max_length=200)
    subscription: str = Field(min_length=1, max_length=200)
    # Which WAF product the container holds. Defaults from the container name (the operator can
    # override in Settings, e.g. for a custom container name).
    waf_type: Literal["frontdoor", "appgw"] | None = None

    @model_validator(mode="after")
    def _default_waf_type(self) -> AzureTarget:
        if self.waf_type is None:
            object.__setattr__(self, "waf_type", waf_type_for_container(self.container))
        return self


def _path(data_dir: Path) -> Path:
    return data_dir / CONFIG_FILENAME


def load_target(settings: Settings) -> AzureTarget:
    """Stored config if present, else the env defaults."""
    p = _path(settings.data_dir)
    if p.is_file():
        return AzureTarget.model_validate_json(p.read_text())
    return AzureTarget(
        storage_account=settings.azure_storage_account,
        container=settings.azure_container,
        subscription=settings.azure_subscription,
    )


def save_target(settings: Settings, target: AzureTarget) -> AzureTarget:
    p = _path(settings.data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(target.model_dump(), indent=2))
    return target


def to_azure_config(target: AzureTarget) -> AzureConfig:
    return AzureConfig(
        account=target.storage_account,
        container=target.container,
        subscription=target.subscription,
        waf_type=target.waf_type or waf_type_for_container(target.container),
    )
