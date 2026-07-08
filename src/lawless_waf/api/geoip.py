"""GeoIP lookup endpoint: country resolution for client IPs seen in WAF logs.

Uses ip-api.com's free batch JSON API (no key required, 15 req/min for batch).
Results are cached in-process so repeated lookups cost nothing.
Private / reserved addresses are resolved locally without any outbound call.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.error
import urllib.request
from typing import Annotated

from fastapi import APIRouter, Body

log = logging.getLogger("lawless_waf")

router = APIRouter(prefix="/geoip", tags=["geoip"])

# Module-level cache: ip str → GeoResult dict
_cache: dict[str, dict] = {}

_PRIVATE_RESULT = {"country_code": "private", "country": "Private network", "flag": "🏠"}
_UNKNOWN_RESULT = {"country_code": "??", "country": "Unknown", "flag": "🏴"}

# ip-api.com batch endpoint — free, no key, up to 100 IPs per request, 15 req/min
_BATCH_URL = "http://ip-api.com/batch?fields=query,countryCode,country,status"


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


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
    """Resolve a list of IPs to country info, using the cache where possible."""
    out: dict[str, dict] = {}
    to_fetch: list[str] = []

    for ip in ips:
        if ip in _cache:
            out[ip] = _cache[ip]
        elif _is_private(ip):
            _cache[ip] = _PRIVATE_RESULT
            out[ip] = _PRIVATE_RESULT
        else:
            to_fetch.append(ip)

    # Batch public IPs in chunks of 100 (ip-api.com limit per request)
    for i in range(0, len(to_fetch), 100):
        chunk = to_fetch[i : i + 100]
        fetched = _batch_lookup(chunk)
        for ip in chunk:
            result = fetched.get(ip, _UNKNOWN_RESULT)
            _cache[ip] = result
            out[ip] = result

    return out


@router.post("")
def geoip_batch(
    ips: Annotated[list[str], Body(embed=True, max_length=500)],
) -> dict:
    """Resolve up to 500 IPs to country info in one call."""
    # Deduplicate while preserving any that were sent
    unique = list(dict.fromkeys(ips))[:500]
    return {"results": resolve(unique)}
