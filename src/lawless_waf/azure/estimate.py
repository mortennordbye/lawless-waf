"""Estimate how much a date range will cost to download, before pulling it.

Lists blob ``contentLength`` for the matching ``y=/m=/d=[/h=]`` prefixes and sums them, so
the operator sees disk size + an ETA up front. Granularity is the hour — the finest the
WAF diagnostic blob layout exposes (``download-batch`` patterns stop at ``h=HH/*``).

Reuses the ambient ``az`` session (argv list, no shell, no secrets), like the downloader.

Limitation: if a single container holds blobs for *multiple* WAF resources, this
estimates only the first resource prefix it discovers. The actual download (a ``*/`` glob)
still fetches them all, so the real size may exceed the estimate in that uncommon case.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from . import downloader
from .discovery import AzureCliError, _run_az
from .downloader import AzureConfig

_PATH_RE = re.compile(r"y=(\d{4})/m=(\d{2})/d=(\d{2})(?:/h=(\d{2}))?")


def discover_base_prefix(cfg: AzureConfig) -> str:
    """The blob-name segment before ``/y=`` (the resource's diagnostic path), or ``""``."""
    rows = _run_az(
        [
            "az", "storage", "blob", "list",
            "--account-name", cfg.account,
            "--container-name", cfg.container,
            "--subscription", cfg.subscription,
            "--auth-mode", "login",
            "--num-results", "1",
        ],
        timeout=60,
    )
    if not rows:
        raise AzureCliError("no blobs found in the container")
    name = rows[0].get("name", "")
    return name.split("/y=")[0] if "/y=" in name else ""


def day_bytes(cfg: AzureConfig, base: str, date: str, hour: int | None) -> tuple[int, int]:
    """Return ``(total_bytes, blob_count)`` for one day (or one hour) under ``base``."""
    y, m, d = date.split("-")
    seg = f"y={y}/m={m}/d={d}"
    if hour is not None:
        seg += f"/h={hour:02d}"
    prefix = f"{base}/{seg}" if base else seg
    sizes = _run_az(
        [
            "az", "storage", "blob", "list",
            "--account-name", cfg.account,
            "--container-name", cfg.container,
            "--subscription", cfg.subscription,
            "--auth-mode", "login",
            "--prefix", prefix,
            "--query", "[].properties.contentLength",
        ],
        timeout=120,
    )
    total = sum(int(s) for s in sizes if s is not None)
    return total, len(sizes)


def _latest_day_hour(cfg: AzureConfig) -> tuple[str, int | None]:
    """Pick a real (date, hour) to download for the speedtest, from an existing blob."""
    rows = _run_az(
        [
            "az", "storage", "blob", "list",
            "--account-name", cfg.account,
            "--container-name", cfg.container,
            "--subscription", cfg.subscription,
            "--auth-mode", "login",
            "--num-results", "1",
        ],
        timeout=60,
    )
    if not rows:
        raise AzureCliError("no blobs found in the container")
    m = _PATH_RE.search(rows[0].get("name", ""))
    if not m:
        raise AzureCliError("could not parse a date from the blob layout")
    y, mo, d, h = m.groups()
    return f"{y}-{mo}-{d}", (int(h) if h is not None else None)


def measure_rate(cfg: AzureConfig) -> dict:
    """Download one real hour of blobs to a temp dir, timing it, to get actual blobs/second.

    blobs/second is the meaningful rate for this workload (lots of tiny 5-minute blobs, so
    per-blob overhead dominates bandwidth). Returns ``{blobs_per_sec, blobs, bytes, seconds,
    mbps}``; the downloaded data is discarded.
    """
    date, hour = _latest_day_hour(cfg)
    tmp = Path(tempfile.mkdtemp(prefix="waf-speedtest-"))
    try:
        argv = downloader.build_download_argv(cfg, date, hour, tmp)
        start = time.monotonic()
        subprocess.run(  # noqa: S603 — argv list, no shell, validated inputs
            argv, check=True, capture_output=True, text=True, timeout=600
        )
        elapsed = time.monotonic() - start
        files = [f for f in tmp.rglob("*") if f.is_file()]
        blobs = len(files)
        total = sum(f.stat().st_size for f in files)
    except subprocess.CalledProcessError as e:
        raise AzureCliError((e.stderr or "speedtest download failed").strip().splitlines()[-1]) from e
    except subprocess.TimeoutExpired as e:
        raise AzureCliError("speedtest timed out — check the VPN connection") from e
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return {
        "blobs_per_sec": round(blobs / elapsed, 2) if elapsed > 0 and blobs else 0.0,
        "blobs": blobs,
        "bytes": total,
        "seconds": round(elapsed, 2),
        "mbps": round(total / elapsed / 1_000_000, 2) if elapsed > 0 and total else 0.0,
    }
