"""Filesystem dataset cache, namespaced by WAF type so Front Door and Application Gateway logs
for the same date coexist.

A *dataset* is one day (or one hour of a day) of merged WAF logs of one WAF type:

    DATA_DIR/<waf_type>/<date>/merged.json          # whole day,  id = "frontdoor:2026-06-24"
    DATA_DIR/<waf_type>/<date>/h<HH>/merged.json    # one hour,   id = "appgw:2026-06-24-h10"

where <waf_type> is "frontdoor" or "appgw". Downloaded raw blobs land under <date>/raw/ (or
<date>/h<HH>/raw/) before merge.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from .duck.schema import FRONT_DOOR, WAF_TYPES

log = logging.getLogger("lawless_waf")

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DATASET_ID_RE = re.compile(r"^(frontdoor|appgw):\d{4}-\d{2}-\d{2}(-h\d{2})?$")


def _pid_alive(pid: int) -> bool:
    """True if a process with this PID exists (signal 0 probes without sending one)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just not ours to signal
    return True


def dataset_id(waf_type: str, date: str, hour: int | None) -> str:
    base = f"{waf_type}:{date}"
    return base if hour is None else f"{base}-h{hour:02d}"


def parse_dataset_id(ds_id: str) -> tuple[str, str, int | None]:
    if not DATASET_ID_RE.match(ds_id):
        raise ValueError(f"invalid dataset id: {ds_id!r}")
    waf_type, _, rest = ds_id.partition(":")
    if "-h" in rest:
        date, hour = rest.split("-h")
        return waf_type, date, int(hour)
    return waf_type, rest, None


@dataclass(frozen=True)
class Dataset:
    id: str
    waf_type: str
    date: str
    hour: int | None
    merged_path: Path

    @property
    def exists(self) -> bool:
        return self.merged_path.is_file()

    @property
    def count_path(self) -> Path:
        """Sidecar holding merged.json's line count, so listing datasets needn't read them."""
        return self.merged_path.with_suffix(".count")

    @property
    def line_count(self) -> int:
        """Lines in merged.json, from the sidecar when it matches the current file.

        Counting means reading the whole file, and ``list_datasets`` asks every dataset for this
        on every call — with multi-GB days that's the tab switch stalling. The sidecar records the
        size it was computed for, so a re-merge (live tailing appends new blobs) recounts once
        instead of reporting a stale number.
        """
        if not self.exists:
            return 0
        size = self.merged_path.stat().st_size
        try:
            meta = json.loads(self.count_path.read_text())
            if meta["size"] == size:
                return int(meta["lines"])
        except (OSError, ValueError, TypeError, KeyError):
            pass  # absent, corrupt, or stale — count it and rewrite below
        with self.merged_path.open("rb") as fh:
            lines = sum(1 for _ in fh)
        try:
            self.count_path.write_text(json.dumps({"lines": lines, "size": size}))
        except OSError as e:  # a read-only data dir costs speed, not correctness
            log.warning("could not write line-count sidecar %s: %s", self.count_path, e)
        return lines


@dataclass(frozen=True)
class Scope:
    """What an analysis runs over: one or more datasets (to span several days) plus an
    optional WAF ``policy`` filter. The query engine applies both when it builds the
    ``logs`` view, so analysis code just hands queries the scope's ``source`` + ``policy``."""

    datasets: tuple[Dataset, ...]
    policy: str | None = None

    @property
    def paths(self) -> list[Path]:
        return [d.merged_path for d in self.datasets]

    @property
    def source(self) -> Path | list[Path]:
        paths = self.paths
        return paths[0] if len(paths) == 1 else paths

    @property
    def id(self) -> str:
        return "+".join(d.id for d in self.datasets)

    @property
    def dataset_ids(self) -> list[str]:
        return [d.id for d in self.datasets]

    @property
    def waf_type(self) -> str:
        """The WAF product this scope analyzes — drives exclusion mapping. Every dataset in a
        scope is the same type (the id namespaces it), so the first one is authoritative."""
        return self.datasets[0].waf_type if self.datasets else FRONT_DOOR

    @property
    def spans_multiple_days(self) -> bool:
        return len({d.date for d in self.datasets}) > 1


class DatasetCache:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def _dir(self, waf_type: str, date: str, hour: int | None) -> Path:
        base = self.data_dir / waf_type / date
        return base if hour is None else base / f"h{hour:02d}"

    def resolve(self, waf_type: str, date: str, hour: int | None) -> Dataset:
        d = self._dir(waf_type, date, hour)
        return Dataset(
            id=dataset_id(waf_type, date, hour),
            waf_type=waf_type,
            date=date,
            hour=hour,
            merged_path=d / "merged.json",
        )

    def get(self, ds_id: str) -> Dataset:
        waf_type, date, hour = parse_dataset_id(ds_id)
        return self.resolve(waf_type, date, hour)

    def migrate_legacy_layout(self) -> int:
        """Move pre-namespacing datasets (``DATA_DIR/<date>/``) under ``DATA_DIR/frontdoor/``.

        Older versions stored Front Door datasets directly under the date. Relocate them once at
        startup so existing downloads survive the move to WAF-type namespacing. Returns how many
        day-directories were relocated."""
        if not self.data_dir.is_dir():
            return 0
        moved = 0
        dest_root = self.data_dir / FRONT_DOOR
        for date_dir in sorted(self.data_dir.iterdir()):
            if not date_dir.is_dir() or not DATE_RE.match(date_dir.name):
                continue
            dest = dest_root / date_dir.name
            if dest.exists():
                continue  # already migrated / a namespaced copy exists — leave the legacy one
            dest.parent.mkdir(parents=True, exist_ok=True)
            date_dir.rename(dest)
            moved += 1
        if moved:
            log.info("migrated %d legacy dataset day(s) under %s/", moved, FRONT_DOOR)
        return moved

    def list(self) -> list[Dataset]:
        out: list[Dataset] = []
        if not self.data_dir.is_dir():
            return out
        for waf_type in WAF_TYPES:
            type_dir = self.data_dir / waf_type
            if not type_dir.is_dir():
                continue
            for date_dir in sorted(type_dir.iterdir()):
                if not date_dir.is_dir() or not DATE_RE.match(date_dir.name):
                    continue
                whole = self.resolve(waf_type, date_dir.name, None)
                if whole.exists:
                    out.append(whole)
                for hour_dir in sorted(date_dir.glob("h[0-9][0-9]")):
                    ds = self.resolve(waf_type, date_dir.name, int(hour_dir.name[1:]))
                    if ds.exists:
                        out.append(ds)
        return out

    def raw_dir(self, waf_type: str, date: str, hour: int | None) -> Path:
        return self._dir(waf_type, date, hour) / "raw"

    def lock_path(self, waf_type: str, date: str, hour: int | None) -> Path:
        return self._dir(waf_type, date, hour) / ".download.lock"

    def acquire_lock(self, waf_type: str, date: str, hour: int | None, stale_after: float = 900.0) -> int:
        """Take the per-(date,hour) download lock, returning an open fd. Raises ``FileExistsError``
        only if a *live* download already holds it.

        A lock left behind by a killed run — its owner PID is dead, or it's a *foreign* PID whose
        lock is older than ``stale_after`` (a PID-reuse backstop) — is reclaimed automatically, so a
        crash mid-download no longer wedges that hour until the app restarts (it previously only
        self-cleared at startup). A lock this process still owns is never reclaimed on age: a
        whole-day download can legitimately run longer than ``stale_after``."""
        lock = self.lock_path(waf_type, date, hour)
        lock.parent.mkdir(parents=True, exist_ok=True)
        try:
            return self._create_lock(lock)
        except FileExistsError:
            if not self._lock_is_stale(lock, stale_after):
                raise
            lock.unlink(missing_ok=True)
            return self._create_lock(lock)  # re-raises if another caller just reclaimed it first

    def _create_lock(self, lock: Path) -> int:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())  # owner PID, so a stale lock is detectable
        return fd

    def _lock_is_stale(self, lock: Path, stale_after: float) -> bool:
        try:
            owner = int(lock.read_text().strip() or 0)
        except (OSError, ValueError):
            owner = 0
        if owner == os.getpid():
            return False  # our own live lock: a download in this process is still running
        if owner and not _pid_alive(owner):
            return True  # the process that took the lock no longer exists
        try:
            return (time.time() - lock.stat().st_mtime) > stale_after
        except OSError:
            return True  # vanished between our checks — effectively free

    def clear_stale_locks(self) -> int:
        """Remove leftover ``.download.lock`` files. Safe to call at startup: this is a
        single-process app, so nothing is downloading then — any lock on disk is stale,
        left by a run that was killed mid-download before its ``finally`` could release it.
        Returns how many were removed."""
        if not self.data_dir.is_dir():
            return 0
        locks = list(self.data_dir.rglob(".download.lock"))
        for lock in locks:
            lock.unlink(missing_ok=True)
        return len(locks)

    def delete(self, ds_id: str) -> bool:
        """Remove a cached dataset's files. Returns False if it wasn't present.

        An hour dataset removes its ``h<HH>/`` dir; a day dataset removes only the day-level
        artifacts (merged.json / raw / lock), leaving any hour datasets under it intact.

        A failed download leaves partial blobs in ``raw/`` with no ``merged.json`` — that
        counts as present too, so the operator can reclaim the disk space instead of keeping
        the leftovers around for a retry.
        """
        waf_type, date, hour = parse_dataset_id(ds_id)
        if not self.resolve(waf_type, date, hour).exists and not self.raw_dir(waf_type, date, hour).is_dir():
            return False
        d = self._dir(waf_type, date, hour)
        if hour is not None:
            shutil.rmtree(d, ignore_errors=True)
            day_dir = self.data_dir / waf_type / date
            if day_dir.is_dir() and not any(day_dir.iterdir()):
                day_dir.rmdir()
        else:
            (d / "merged.json").unlink(missing_ok=True)
            (d / "merged.count").unlink(missing_ok=True)
            shutil.rmtree(d / "raw", ignore_errors=True)
            self.lock_path(waf_type, date, None).unlink(missing_ok=True)
            if d.is_dir() and not any(d.iterdir()):
                d.rmdir()
        return True

    def clear(self) -> int:
        """Remove every cached dataset. Returns the number of datasets removed."""
        count = len(self.list())
        if self.data_dir.is_dir():
            for waf_type in WAF_TYPES:
                type_dir = self.data_dir / waf_type
                if type_dir.is_dir():
                    shutil.rmtree(type_dir, ignore_errors=True)
        return count
