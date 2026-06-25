"""Enumerate Azure subscriptions / storage accounts / containers via the ambient ``az`` session.

Powers the Settings dropdowns so the operator picks from real resources instead of typing
free text. Every call shells out to the Azure CLI as an argv list (never a shell string),
reusing the host ``az login`` / PIM / VPN session — no Azure secrets in the app.
"""

from __future__ import annotations

import json
import subprocess


class AzureCliError(RuntimeError):
    """An ``az`` invocation failed; ``str(self)`` is a human-readable reason."""


def _run_az(argv: list[str], timeout: int) -> list[dict]:
    """Run ``az ... -o json`` and return the parsed JSON array, or raise AzureCliError."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [*argv, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise AzureCliError("az CLI not found") from e
    except subprocess.TimeoutExpired as e:
        raise AzureCliError("az timed out — check the VPN connection") from e

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        detail = stderr.splitlines()[-1] if stderr else "az command failed"
        if "az login" in stderr.lower() or "not logged in" in stderr.lower():
            detail = "not signed in — run `az login` on the host"
        raise AzureCliError(detail)

    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as e:
        raise AzureCliError("could not parse az output") from e
    return data if isinstance(data, list) else []


def list_subscriptions() -> list[dict]:
    """All subscriptions the session can see: ``[{id, name, is_default}]``."""
    rows = _run_az(["az", "account", "list", "--all"], timeout=30)
    return [
        {"id": r.get("id"), "name": r.get("name"), "is_default": bool(r.get("isDefault"))}
        for r in rows
    ]


def list_storage_accounts(subscription: str) -> list[dict]:
    """Storage accounts in a subscription: ``[{name, resource_group}]`` (sorted by name)."""
    rows = _run_az(
        ["az", "storage", "account", "list", "--subscription", subscription],
        timeout=60,
    )
    accounts = [
        {"name": r.get("name"), "resource_group": r.get("resourceGroup")} for r in rows
    ]
    return sorted(accounts, key=lambda a: (a["name"] or "").lower())


def list_containers(account: str, subscription: str) -> list[dict]:
    """Blob containers in a storage account: ``[{name}]`` (sorted).

    Uses ``--auth-mode login`` so it works with the operator's AAD session (no account key).
    """
    rows = _run_az(
        [
            "az", "storage", "container", "list",
            "--account-name", account,
            "--subscription", subscription,
            "--auth-mode", "login",
        ],
        timeout=60,
    )
    names = [{"name": r.get("name")} for r in rows]
    return sorted(names, key=lambda c: (c["name"] or "").lower())
