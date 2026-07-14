import json
import os

import pytest

from lawless_waf.cache import DatasetCache

DATE, HOUR = "2026-06-26", 7


def _write_merged(cache, date, hour, lines):
    ds = cache.resolve(date, hour)
    ds.merged_path.parent.mkdir(parents=True, exist_ok=True)
    ds.merged_path.write_text("".join('{"a":1}\n' for _ in range(lines)))
    return ds


def test_line_count_counts_and_writes_the_sidecar_when_absent(tmp_path):
    cache = DatasetCache(tmp_path)
    ds = _write_merged(cache, DATE, None, 3)
    assert not ds.count_path.exists()

    assert ds.line_count == 3
    assert json.loads(ds.count_path.read_text())["lines"] == 3


def test_line_count_reads_the_sidecar_without_recounting(tmp_path):
    """The whole point: listing datasets must not re-read multi-GB merged files. Rewriting the
    file with the same size but a different number of lines proves the answer came from the
    sidecar rather than from a fresh count."""
    cache = DatasetCache(tmp_path)
    ds = _write_merged(cache, DATE, None, 3)
    size = ds.merged_path.stat().st_size
    assert ds.line_count == 3  # writes the sidecar

    ds.merged_path.write_text("x" * (size - 1) + "\n")  # same bytes, 1 line
    assert ds.line_count == 3  # sidecar trusted; a recount would say 1


def test_line_count_recounts_when_the_merged_file_changed(tmp_path):
    """Live tailing re-merges and appends: a sidecar from the smaller file must not be trusted."""
    cache = DatasetCache(tmp_path)
    ds = _write_merged(cache, DATE, None, 3)
    assert ds.line_count == 3

    _write_merged(cache, DATE, None, 5)  # re-merged, sidecar now stale
    assert ds.line_count == 5
    assert json.loads(ds.count_path.read_text())["lines"] == 5


def test_delete_removes_the_count_sidecar(tmp_path):
    cache = DatasetCache(tmp_path)
    ds = _write_merged(cache, DATE, None, 3)
    assert ds.line_count == 3  # sidecar written

    assert cache.delete(DATE) is True
    assert not ds.count_path.exists()


def test_acquire_lock_blocks_while_owner_is_live(tmp_path):
    """A second acquire while a live download holds the lock is refused."""
    cache = DatasetCache(tmp_path)
    fd = cache.acquire_lock(DATE, HOUR)
    try:
        with pytest.raises(FileExistsError):
            cache.acquire_lock(DATE, HOUR)
    finally:
        os.close(fd)
        cache.lock_path(DATE, HOUR).unlink()


def test_acquire_lock_reclaims_dead_owner(tmp_path):
    """A lock left by a killed run (owner PID no longer exists) is reclaimed, not honored —
    so a crash mid-download doesn't wedge the hour until restart."""
    cache = DatasetCache(tmp_path)
    lock = cache.lock_path(DATE, HOUR)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("2147483647")  # a PID that isn't running

    fd = cache.acquire_lock(DATE, HOUR)  # reclaims instead of raising
    os.close(fd)
    assert lock.read_text().strip() == str(os.getpid())
    lock.unlink()


def test_acquire_lock_reclaims_aged_out(tmp_path):
    """Backstop: a lock held by a live *foreign* PID (e.g. PID reuse) that is older than
    stale_after is reclaimed."""
    cache = DatasetCache(tmp_path)
    lock = cache.lock_path(DATE, HOUR)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("1")  # pid 1 is alive, but isn't us
    old = lock.stat().st_mtime - 10_000
    os.utime(lock, (old, old))  # aged well past the threshold

    fd = cache.acquire_lock(DATE, HOUR, stale_after=1.0)  # reclaims on age
    os.close(fd)
    lock.unlink()


def test_acquire_lock_never_steals_our_own_live_lock(tmp_path):
    """A download this process is still running keeps its lock however long it takes: a whole-day
    pull can outlast stale_after, and stealing it would start a second concurrent download."""
    cache = DatasetCache(tmp_path)
    fd = cache.acquire_lock(DATE, HOUR)
    lock = cache.lock_path(DATE, HOUR)
    old = lock.stat().st_mtime - 10_000
    os.utime(lock, (old, old))  # aged out, but the owner (us) is alive and downloading
    try:
        with pytest.raises(FileExistsError):
            cache.acquire_lock(DATE, HOUR, stale_after=1.0)
    finally:
        os.close(fd)
        lock.unlink()
