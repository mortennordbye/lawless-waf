"""Generate a small SYNTHETIC WAF-log dataset — no real or customer data.

Used by `make seed` (offline trial) and the test suite. It mirrors the real Azure Front
Door WAF NDJSON shape (one JSON record per line) and fabricates three scenarios:

- a vulnerability scanner sweeping many rules/URIs (should classify as a scanner),
- a genuine false positive (a UUID session cookie tripping a SQLI rule),
- a not-excludable match (multipart body contents).

Run: ``python -m lawless_waf.sample <output.ndjson>``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

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


def _rec(ip, uri, action, rule, tref, mv=None, val=None, msg=""):
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
        "time": "2026-01-01T00:00:00Z",
    }


def records() -> list[dict]:
    recs: list[dict] = []
    # Scanner: 20 blocks across 3 rule groups and 20 distinct URIs, attack-shaped values.
    for i in range(20):
        rule, mv, val, msg = _SCAN_RULES[i % 3]
        uri = f"https://{HOST}/p{i}"
        recs.append(_rec(SCANNER_IP, uri, "Block", BLOCK_RULE, f"scan-{i}", msg=SCORE_MSG))
        recs.append(_rec(SCANNER_IP, uri, "AnomalyScoring", rule, f"scan-{i}", mv, val, msg))
    # False positive: a UUID session cookie trips SQLI on 2 requests from one IP.
    for i in range(2):
        recs.append(_rec(FP_IP, f"https://{HOST}/account", "Block", BLOCK_RULE, f"fp-{i}", msg=SCORE_MSG))
        recs.append(
            _rec(FP_IP, f"https://{HOST}/account", "AnomalyScoring", SQLI, f"fp-{i}",
                 "CookieValue:sessionId", "123e4567-e89b-12d3-a456-426614174000", "SQL Injection")
        )
    # Not excludable: multipart body contents trip SQLI on 1 request.
    recs.append(_rec(NE_IP, f"https://{HOST}/upload", "Block", BLOCK_RULE, "ne-0", msg=SCORE_MSG))
    recs.append(
        _rec(NE_IP, f"https://{HOST}/upload", "AnomalyScoring", SQLI, "ne-0",
             "InitialBodyContents", "------boundary\r\nContent-Disposition: form-data", "SQL Injection")
    )
    # A couple of Log-action rows.
    recs.append(_rec(FP_IP, f"https://{HOST}/", "Log", SQLI, "log-0", "QueryParamValue:q", "hello", "log"))
    recs.append(_rec(FP_IP, f"https://{HOST}/", "Log", _SCAN_RULES[1][0], "log-1", "QueryParamValue:q", "world", "log"))
    return recs


def write_sample(path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records():
            f.write(json.dumps(r) + "\n")
    return path


if __name__ == "__main__":
    out = write_sample(sys.argv[1] if len(sys.argv) > 1 else "merged.json")
    print(f"wrote {out}")
