"""Read the ambient ``az`` login session status (we reuse the operator's host session)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class AzureStatus:
    logged_in: bool
    user: str | None = None
    subscription: str | None = None
    subscription_id: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict:
        return {
            "logged_in": self.logged_in,
            "user": self.user,
            "subscription": self.subscription,
            "subscription_id": self.subscription_id,
            "detail": self.detail,
        }


def az_status() -> AzureStatus:
    """Run ``az account show``; report whether a usable session exists."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            ["az", "account", "show", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        return AzureStatus(logged_in=False, detail="az CLI not found")
    except subprocess.TimeoutExpired:
        return AzureStatus(logged_in=False, detail="az account show timed out")

    if proc.returncode != 0:
        return AzureStatus(logged_in=False, detail="not signed in — run `az login` on the host")

    try:
        acct = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return AzureStatus(logged_in=False, detail="could not parse az output")

    return AzureStatus(
        logged_in=True,
        user=(acct.get("user") or {}).get("name"),
        subscription=acct.get("name"),
        subscription_id=acct.get("id"),
    )
