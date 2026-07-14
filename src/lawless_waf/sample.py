"""Generate a small SYNTHETIC WAF-log dataset — no real or customer data.

Used by `make seed` (offline trial) and the test suite. It mirrors the real Azure Front
Door WAF NDJSON shape (one JSON record per line) and fabricates three scenarios:

- a vulnerability scanner sweeping many rules/URIs (should classify as a scanner),
- a genuine false positive (a UUID session cookie tripping a SQLI rule),
- a not-excludable match (multipart body contents).

Records are stamped with the date of the directory they're written to (datasets live at
DATA_DIR/<date>/merged.json) and spread across that day, so the activity timeline shows the
scanner burst against a trickle of real traffic instead of one bar.

Run: ``python -m lawless_waf.sample <output.ndjson> [--resolved]``. ``--resolved`` omits the
false-positive traffic, which is what a second day looks like once its exclusion is in place —
seeding one day of each makes the before/after diff show a resolved rule offline.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .cache import DATE_RE

DEFAULT_DATE = "2026-06-24"

HOST = "app.example.com"
SCANNER_IP = "203.0.113.7"  # TEST-NET-3, reserved for documentation/examples
FP_IP = "198.51.100.10"  # TEST-NET-2
NE_IP = "198.51.100.11"

BLOCK_RULE = "Microsoft_DefaultRuleSet-2.1-BLOCKING-EVALUATION-949110"
SQLI = "Microsoft_DefaultRuleSet-2.1-SQLI-942100"
# The blocking-evaluation rule records the combined anomaly score in its message.
SCORE_MSG = "Inbound Anomaly Score Exceeded (Total Score: 8)"

_SCAN_RULES = [
    (SQLI, "QueryParamValue:q", "1 UNION SELECT password FROM users", "SQL Injection"),
    ("Microsoft_DefaultRuleSet-2.1-XSS-941100", "QueryParamValue:q", "<script>alert(1)</script>", "XSS"),
    ("Microsoft_DefaultRuleSet-2.1-LFI-930100", "QueryParamValue:file", "../../../../etc/passwd", "Path Traversal"),
]


def _rec(ip, uri, action, rule, tref, mv=None, val=None, msg="", time=f"{DEFAULT_DATE}T09:00:00Z"):
    matches = [{"matchVariableName": mv, "matchVariableValue": val}] if mv else []
    return {
        "properties": {
            "clientIP": ip,
            "requestUri": uri,
            "action": action,
            "ruleName": rule,
            "policy": "SampleWafPolicy",
            "policyMode": "Prevention",
            "trackingReference": tref,
            "host": HOST,
            "details": {"msg": msg, "data": val or "", "matches": matches},
        },
        "time": time,
    }


def records(date: str = DEFAULT_DATE, false_positives: bool = True) -> list[dict]:
    """One day of synthetic logs. ``false_positives=False`` drops the FP traffic, i.e. the same
    day after its exclusion shipped — the "after" side of a diff."""

    def at(hour: int, minute: int) -> str:
        return f"{date}T{hour:02d}:{minute:02d}:00Z"

    recs: list[dict] = []
    # Scanner: 20 blocks across 3 rule groups and 20 distinct URIs, attack-shaped values. Swept
    # over one hour, so the timeline shows the burst that real scanners make.
    for i in range(20):
        rule, mv, val, msg = _SCAN_RULES[i % 3]
        uri = f"https://{HOST}/p{i}"
        t = at(9, i * 3)
        recs.append(_rec(SCANNER_IP, uri, "Block", BLOCK_RULE, f"scan-{i}", msg=SCORE_MSG, time=t))
        recs.append(_rec(SCANNER_IP, uri, "AnomalyScoring", rule, f"scan-{i}", mv, val, msg, time=t))
    if false_positives:
        # False positive: a UUID session cookie trips SQLI on 2 requests from one IP.
        for i, t in enumerate((at(11, 20), at(14, 5))):
            recs.append(
                _rec(FP_IP, f"https://{HOST}/account", "Block", BLOCK_RULE, f"fp-{i}",
                     msg=SCORE_MSG, time=t)
            )
            recs.append(
                _rec(FP_IP, f"https://{HOST}/account", "AnomalyScoring", SQLI, f"fp-{i}",
                     "CookieValue:sessionId", "123e4567-e89b-12d3-a456-426614174000",
                     "SQL Injection", time=t)
            )
    # Not excludable: multipart body contents trip SQLI on 1 request.
    recs.append(_rec(NE_IP, f"https://{HOST}/upload", "Block", BLOCK_RULE, "ne-0",
                     msg=SCORE_MSG, time=at(15, 40)))
    recs.append(
        _rec(NE_IP, f"https://{HOST}/upload", "AnomalyScoring", SQLI, "ne-0",
             "InitialBodyContents", "------boundary\r\nContent-Disposition: form-data",
             "SQL Injection", time=at(15, 40))
    )
    # A couple of Log-action rows.
    recs.append(_rec(FP_IP, f"https://{HOST}/", "Log", SQLI, "log-0", "QueryParamValue:q", "hello",
                     "log", time=at(10, 15)))
    recs.append(_rec(FP_IP, f"https://{HOST}/", "Log", _SCAN_RULES[1][0], "log-1",
                     "QueryParamValue:q", "world", "log", time=at(16, 30)))
    return recs


def _date_from_path(path: Path) -> str:
    """Datasets live at DATA_DIR/<date>/merged.json (or <date>/h<HH>/merged.json), so the
    directory says which day these records claim to be. Stamping them with anything else makes
    the timeline disagree with the dataset id."""
    for part in reversed(path.parts):
        if DATE_RE.match(part):
            return part
    return DEFAULT_DATE


def write_sample(path: str | Path, false_positives: bool = True) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records(_date_from_path(path), false_positives):
            f.write(json.dumps(r) + "\n")
    return path


if __name__ == "__main__":
    argv = sys.argv[1:]
    paths = [a for a in argv if not a.startswith("-")]
    out = write_sample(paths[0] if paths else "merged.json", false_positives="--resolved" not in argv)
    print(f"wrote {out}")
