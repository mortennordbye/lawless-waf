"""Central configuration.

This tool always runs on the operator's own laptop and is bound to localhost, so it has no
API-key auth: the only real gate is Azure (PIM + VPN + `az login`), which protects the
sensitive operation (downloading prod blobs). See README "Running against real Azure".
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    data_dir: Path = Path("./data")
    offline: bool = True

    # Placeholders — set the real values via the Settings UI or .env (per deployment).
    azure_storage_account: str = "your-storage-account"
    azure_container: str = "insights-logs-frontdoorwebapplicationfirewalllog"
    azure_subscription: str = "your-subscription"

    # Domains the app treats as "own" — a URL pointing here in a param is a likely FP, not RFI.
    trusted_domains: str = ""

    # Country lookup for client IPs. Off by default: enabling sends IPs harvested from your
    # WAF logs (personal data) to ip-api.com over plain HTTP. See .env.example.
    geoip_enabled: bool = False

    # WAF logs are many small 5-minute blobs, so download time is dominated by per-blob
    # overhead, not bandwidth. The ETA is therefore driven by blobs/second, not MB/s.
    # This is the assumed rate; the Speedtest button measures the real one.
    download_blobs_per_sec: float = 6.0

    download_rate_limit: str = "5/minute"
    query_rate_limit: str = "60/minute"
    cors_origins: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def trusted_domain_list(self) -> list[str]:
        return [d.strip() for d in self.trusted_domains.split(",") if d.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    """Lazily build and cache settings so import never triggers validation errors."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
