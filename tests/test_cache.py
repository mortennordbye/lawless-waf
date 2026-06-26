import os

import pytest

from lawless_waf.cache import DatasetCache

DATE, HOUR = "2026-06-26", 7


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
    """Backstop: even if the recorded PID is alive (e.g. PID reuse), a lock older than
    stale_after is reclaimed."""
    cache = DatasetCache(tmp_path)
    lock = cache.lock_path(DATE, HOUR)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(str(os.getpid()))  # our own (alive) pid
    old = lock.stat().st_mtime - 10_000
    os.utime(lock, (old, old))  # but aged well past the threshold

    fd = cache.acquire_lock(DATE, HOUR, stale_after=1.0)  # reclaims on age
    os.close(fd)
    lock.unlink()
