"""GeoIP lookup endpoint: country resolution for client IPs seen in WAF logs.

Off unless ``GEOIP_ENABLED=true``: the client IPs in WAF logs are personal data, and the
only free lookup available without a key (ip-api.com) is plain HTTP and bars commercial
use, so sending them out is the operator's call to make, not a default.

When enabled, uses ip-api.com's batch JSON API (15 req/min for batch). Results are cached
in-process so repeated lookups cost nothing. Private / reserved addresses are resolved
locally without any outbound call, enabled or not.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.error
import urllib.request
from typing import Annotated

from fastapi import APIRouter, Body, Request

from ..ratelimit import limiter, query_limit
from ..settings import get_settings

log = logging.getLogger("lawless_waf")

router = APIRouter(prefix="/geoip", tags=["geoip"])

# Module-level cache: ip str → GeoResult dict
_cache: dict[str, dict] = {}

_PRIVATE_RESULT = {"country_code": "private", "country": "Private network", "flag": "🏠"}
_UNKNOWN_RESULT = {"country_code": "??", "country": "Unknown", "flag": "🏴"}

# ip-api.com batch endpoint — free, no key, up to 100 IPs per request, 15 req/min
_BATCH_URL = "http://ip-api.com/batch?fields=query,countryCode,country,status"


def _parse(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an untrusted string as an IP address, or None if it isn't one."""
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def _is_private(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _flag(country_code: str) -> str:
    """Convert ISO 3166-1 alpha-2 code to flag emoji, e.g. 'NO' → '🇳🇴'."""
    if len(country_code) != 2 or not country_code.isalpha():
        return "🏴"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


def _batch_lookup(ips: list[str]) -> dict[str, dict]:
    """Call ip-api.com batch endpoint for up to 100 public IPs at once."""
    payload = json.dumps([{"query": ip} for ip in ips]).encode()
    req = urllib.request.Request(
        _BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data: list[dict] = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
        log.warning("geoip batch lookup failed: %s", exc)
        return {}

    results: dict[str, dict] = {}
    for item in data:
        ip = item.get("query", "")
        if not ip:
            continue
        if item.get("status") == "success":
            cc = item.get("countryCode", "??")
            results[ip] = {
                "country_code": cc,
                "country": item.get("country", "Unknown"),
                "flag": _flag(cc),
            }
        else:
            results[ip] = _UNKNOWN_RESULT
    return results


def resolve(ips: list[str]) -> dict[str, dict]:
    """Resolve a list of IPs to country info, using the cache where possible.

    Public IPs resolve to unknown — with no outbound call — unless GEOIP_ENABLED is set.
    """
    enabled = get_settings().geoip_enabled
    out: dict[str, dict] = {}
    to_fetch: list[str] = []

    for ip in ips:
        if ip in _cache:
            out[ip] = _cache[ip]
            continue
        addr = _parse(ip)
        if addr is None:
            # Not an IP at all; never forward it to a third party.
            out[ip] = _UNKNOWN_RESULT
        elif _is_private(addr):
            _cache[ip] = _PRIVATE_RESULT
            out[ip] = _PRIVATE_RESULT
        elif not enabled:
            # Not cached: the answer depends on the flag, not on the address.
            out[ip] = _UNKNOWN_RESULT
        else:
            to_fetch.append(ip)

    # Batch public IPs in chunks of 100 (ip-api.com limit per request)
    for i in range(0, len(to_fetch), 100):
        chunk = to_fetch[i : i + 100]
        fetched = _batch_lookup(chunk)
        for ip in chunk:
            if ip in fetched:
                _cache[ip] = fetched[ip]  # a real answer from the provider, unknown or not
                out[ip] = fetched[ip]
            else:
                # No answer (the call failed): report unknown but don't cache it, or one network
                # blip would pin these IPs to "Unknown" until the process restarts.
                out[ip] = _UNKNOWN_RESULT

    return out


@router.post("")
@limiter.limit(query_limit)
def geoip_batch(
    request: Request,
    ips: Annotated[list[str], Body(embed=True, max_length=500)],
) -> dict:
    """Resolve up to 500 IPs to country info in one call."""
    # Deduplicate while preserving any that were sent
    unique = list(dict.fromkeys(ips))[:500]
    return {"results": resolve(unique)}
