"""Rate limiting via slowapi, keyed by client IP — caps the expensive Azure download path
and the analysis endpoints so they can't be hammered (cost control)."""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from .settings import get_settings

limiter = Limiter(key_func=get_remote_address)


def download_limit() -> str:
    return get_settings().download_rate_limit


def query_limit() -> str:
    return get_settings().query_rate_limit
