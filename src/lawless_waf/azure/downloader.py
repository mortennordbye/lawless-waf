"""Download WAF blobs via the documented ``az storage blob download-batch`` command.

We shell out to the Azure CLI (not the SDK) so authentication is the operator's ambient
``az login`` / PIM / VPN session — no Azure secrets in the app. The command is invoked as
an argv list (never a shell string); all interpolated values are validated upstream.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AzureConfig:
    account: str
    container: str
    subscription: str


def blob_pattern(date: str, hour: int | None) -> str:
    """Runbook glob: a whole day, or a single hour."""
    y, m, d = date.split("-")
    base = f"*/y={y}/m={m}/d={d}"
    return f"{base}/*" if hour is None else f"{base}/h={hour:02d}/*"


def build_download_argv(
    cfg: AzureConfig, date: str, hour: int | None, raw_dir: Path, overwrite: bool = False
) -> list[str]:
    """The exact documented command, as an argv list.

    ``overwrite`` re-fetches blobs that already exist locally — needed to refresh the
    still-being-written current hour during live tailing (a forced re-download).
    """
    argv = [
        "az", "storage", "blob", "download-batch",
        "--account-name", cfg.account,
        "--source", cfg.container,
        "--destination", str(raw_dir),
        "--pattern", blob_pattern(date, hour),
        "--auth-mode", "login",
        "--subscription", cfg.subscription,
    ]
    if overwrite:
        argv += ["--overwrite", "true"]
    return argv


def merge_blobs(raw_dir: Path, merged_path: Path) -> int:
    """Concatenate all PT5M.json blobs (sorted) into a single NDJSON file. Returns lines."""
    blobs = sorted(raw_dir.rglob("PT5M.json"))
    lines = 0
    with merged_path.open("wb") as out:
        for blob in blobs:
            data = blob.read_bytes()
            out.write(data)
            if data and not data.endswith(b"\n"):
                out.write(b"\n")
            lines += data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    return lines


def download(
    cfg: AzureConfig,
    date: str,
    hour: int | None,
    raw_dir: Path,
    merged_path: Path,
    overwrite: bool = False,
) -> int:
    """Run the download + merge. Raises CalledProcessError on az failure. Returns line count."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(  # noqa: S603 — argv list, no shell, validated inputs
        build_download_argv(cfg, date, hour, raw_dir, overwrite),
        check=True,
        capture_output=True,
        text=True,
    )
    return merge_blobs(raw_dir, merged_path)
