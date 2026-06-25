"""Filesystem dataset cache, mirroring the runbook's ~/waf-logs/<date>/ layout.

A *dataset* is one day (or one hour of a day) of merged WAF logs:

    DATA_DIR/<date>/merged.json          # whole day,  id = "2026-06-24"
    DATA_DIR/<date>/h<HH>/merged.json    # one hour,   id = "2026-06-24-h10"

Downloaded raw blobs land under <date>/raw/ (or <date>/h<HH>/raw/) before merge.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DATASET_ID_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(-h\d{2})?$")


def dataset_id(date: str, hour: int | None) -> str:
    return date if hour is None else f"{date}-h{hour:02d}"


def parse_dataset_id(ds_id: str) -> tuple[str, int | None]:
    if not DATASET_ID_RE.match(ds_id):
        raise ValueError(f"invalid dataset id: {ds_id!r}")
    if "-h" in ds_id:
        date, hour = ds_id.split("-h")
        return date, int(hour)
    return ds_id, None


@dataclass(frozen=True)
class Dataset:
    id: str
    date: str
    hour: int | None
    merged_path: Path

    @property
    def exists(self) -> bool:
        return self.merged_path.is_file()

    @property
    def line_count(self) -> int:
        if not self.exists:
            return 0
        with self.merged_path.open("rb") as fh:
            return sum(1 for _ in fh)


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
    def spans_multiple_days(self) -> bool:
        return len({d.date for d in self.datasets}) > 1


class DatasetCache:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def _dir(self, date: str, hour: int | None) -> Path:
        base = self.data_dir / date
        return base if hour is None else base / f"h{hour:02d}"

    def resolve(self, date: str, hour: int | None) -> Dataset:
        d = self._dir(date, hour)
        return Dataset(
            id=dataset_id(date, hour),
            date=date,
            hour=hour,
            merged_path=d / "merged.json",
        )

    def get(self, ds_id: str) -> Dataset:
        date, hour = parse_dataset_id(ds_id)
        return self.resolve(date, hour)

    def list(self) -> list[Dataset]:
        out: list[Dataset] = []
        if not self.data_dir.is_dir():
            return out
        for date_dir in sorted(self.data_dir.iterdir()):
            if not date_dir.is_dir() or not DATE_RE.match(date_dir.name):
                continue
            whole = self.resolve(date_dir.name, None)
            if whole.exists:
                out.append(whole)
            for hour_dir in sorted(date_dir.glob("h[0-9][0-9]")):
                ds = self.resolve(date_dir.name, int(hour_dir.name[1:]))
                if ds.exists:
                    out.append(ds)
        return out

    def raw_dir(self, date: str, hour: int | None) -> Path:
        return self._dir(date, hour) / "raw"

    def lock_path(self, date: str, hour: int | None) -> Path:
        return self._dir(date, hour) / ".download.lock"

    def delete(self, ds_id: str) -> bool:
        """Remove a cached dataset's files. Returns False if it wasn't present.

        An hour dataset removes its ``h<HH>/`` dir; a day dataset removes only the day-level
        artifacts (merged.json / raw / lock), leaving any hour datasets under it intact.
        """
        date, hour = parse_dataset_id(ds_id)
        if not self.resolve(date, hour).exists:
            return False
        d = self._dir(date, hour)
        if hour is not None:
            shutil.rmtree(d, ignore_errors=True)
            day_dir = self.data_dir / date
            if day_dir.is_dir() and not any(day_dir.iterdir()):
                day_dir.rmdir()
        else:
            (d / "merged.json").unlink(missing_ok=True)
            shutil.rmtree(d / "raw", ignore_errors=True)
            self.lock_path(date, None).unlink(missing_ok=True)
            if d.is_dir() and not any(d.iterdir()):
                d.rmdir()
        return True

    def clear(self) -> int:
        """Remove every cached dataset. Returns the number of datasets removed."""
        count = len(self.list())
        if self.data_dir.is_dir():
            for date_dir in self.data_dir.iterdir():
                if date_dir.is_dir() and DATE_RE.match(date_dir.name):
                    shutil.rmtree(date_dir, ignore_errors=True)
        return count
