"""Download WAF blobs via the documented ``az storage blob download-batch`` command.

We shell out to the Azure CLI (not the SDK) so authentication is the operator's ambient
``az login`` / PIM / VPN session — no Azure secrets in the app. The command is invoked as
an argv list (never a shell string); all interpolated values are validated upstream.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .discovery import AzureCliError, az_error_detail


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


def download_blob(cfg: AzureConfig, name: str, dest_file: Path) -> None:
    """Download a single blob by name to ``dest_file`` (with overwrite). Used by the incremental
    live tail to pull just the new / still-growing 5-minute window blobs, not the whole hour.

    ``download-batch`` *errors* on already-present files (no skip), so a live refresh can't re-run
    it over a populated raw dir — we fetch individual blobs instead.
    """
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    # Download to a temp file and atomically rename into place. If az is killed mid-write (a dev
    # reload, Ctrl+C, a crash), dest_file is left untouched and the half-written .tmp is ignored by
    # merge_blobs (it globs PT5M.json, not .tmp) — so a truncated blob never poisons the merge.
    tmp = dest_file.with_name(dest_file.name + ".tmp")
    argv = [
        "az", "storage", "blob", "download",
        "--account-name", cfg.account,
        "--container-name", cfg.container,
        "--name", name,
        "--file", str(tmp),
        "--auth-mode", "login",
        "--subscription", cfg.subscription,
        "--overwrite", "true",
        "--no-progress",
    ]
    try:
        subprocess.run(argv, check=True, capture_output=True, text=True)  # noqa: S603 — argv, no shell
    except FileNotFoundError as e:
        tmp.unlink(missing_ok=True)
        raise AzureCliError("az CLI not found") from e
    except subprocess.CalledProcessError as e:
        tmp.unlink(missing_ok=True)
        raise AzureCliError(az_error_detail(e.stderr)) from e
    os.replace(tmp, dest_file)


def merge_blobs(raw_dir: Path, merged_path: Path) -> int:
    """Concatenate all PT5M.json blobs (sorted) into a single NDJSON file. Returns lines.

    Writes to a temp file and atomically renames into place, so an interrupted merge (a dev
    reload, Ctrl+C, a crash) never leaves a half-written merged.json that later reads choke on —
    the previous good file stays until the new one is complete.
    """
    blobs = sorted(raw_dir.rglob("PT5M.json"))
    lines = 0
    merged_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = merged_path.with_name(merged_path.name + ".tmp")
    try:
        with tmp.open("wb") as out:
            for blob in blobs:
                data = blob.read_bytes()
                out.write(data)
                if data and not data.endswith(b"\n"):
                    out.write(b"\n")
                lines += data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
        os.replace(tmp, merged_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return lines


def download(
    cfg: AzureConfig,
    date: str,
    hour: int | None,
    raw_dir: Path,
    merged_path: Path,
    overwrite: bool = False,
) -> int:
    """Run the download + merge. Raises AzureCliError with an actionable message on az failure
    (so the API surfaces the real reason instead of a generic 500). Returns line count."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(  # noqa: S603 — argv list, no shell, validated inputs
            build_download_argv(cfg, date, hour, raw_dir, overwrite),
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise AzureCliError("az CLI not found") from e
    except subprocess.CalledProcessError as e:
        raise AzureCliError(az_error_detail(e.stderr)) from e
    return merge_blobs(raw_dir, merged_path)
