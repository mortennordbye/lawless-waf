"""Heuristic: does a matched value look like a real attack or legitimate app data?

This is intentionally a *hint* with cited evidence, not a verdict — the runbook's rule is
"looks like attack => leave blocked; looks like app data => exclude", and the final call is
left to the human/Claude Code reading the evidence.
"""

from __future__ import annotations

import re

# Substrings / patterns that strongly indicate genuine attack traffic.
_ATTACK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("path-traversal", re.compile(r"\.\./|\.\.%2f|%2e%2e", re.I)),
    ("sensitive-file-probe", re.compile(r"/\.(env|git|htpasswd|aws)|/etc/passwd|web\.config", re.I)),
    ("sql-injection", re.compile(r"\bunion\s+select\b|;\s*(insert|update|delete|drop)\b|'\s*or\s+'?\d", re.I)),
    ("xss", re.compile(r"<script|onerror\s*=|javascript:|<img\b|<svg\b|<iframe\b", re.I)),
    ("template-ognl-injection", re.compile(r"\$\{|#\{|@org\.apache|@java\.lang|ognl", re.I)),
    ("java-deserialization", re.compile(r"sun\.misc\.base64decoder|java\.util\.|org\.slf4j|rO0AB", re.I)),
    ("rce-shell", re.compile(r"/bin/(sh|bash)|cmd\.exe|powershell|\(\)\s*\{", re.I)),
    ("php-injection", re.compile(r"php://|allow_url_include|<\?php", re.I)),
]

# Patterns that look like benign first-party application data.
_BENIGN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("jwt-or-token", re.compile(r"^ey[A-Za-z0-9_-]{10,}\.", re.I)),
    ("uuid", re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)),
    ("data-uri-image", re.compile(r"data:image/(png|jpe?g|gif);base64,", re.I)),
    ("json-object", re.compile(r"^\s*[\{\[]")),
]


def classify_value(value: str | None, trusted_domains: list[str] | tuple[str, ...] = ()) -> tuple[str, list[str]]:
    """Return (``attack`` | ``false_positive`` | ``unknown``, evidence labels).

    ``trusted_domains`` are the app's own domains; a URL pointing at one is a likely FP
    (e.g. an OAuth ``returnUrl``), not a remote-file-inclusion attack.
    """
    if not value:
        return "unknown", []
    attack_hits = [name for name, pat in _ATTACK_PATTERNS if pat.search(value)]
    if attack_hits:
        return "attack", attack_hits
    for d in trusted_domains:
        if re.search(r"https?://[\w.-]*" + re.escape(d), value, re.I):
            return "false_positive", ["own-domain-url"]
    benign_hits = [name for name, pat in _BENIGN_PATTERNS if pat.search(value)]
    if benign_hits:
        return "false_positive", benign_hits
    return "unknown", []


def classify_samples(
    values: list[str | None], trusted_domains: list[str] | tuple[str, ...] = ()
) -> tuple[str, list[str]]:
    """Aggregate per-value classifications across a match variable's sample values."""
    verdicts = [classify_value(v, trusted_domains) for v in values]
    labels = {v for v, _ in verdicts}
    evidence = sorted({e for _, ev in verdicts for e in ev})
    has_attack = "attack" in labels
    has_fp = "false_positive" in labels
    if has_attack and has_fp:
        return "mixed", evidence
    if has_attack:
        return "attack", evidence
    if has_fp:
        return "false_positive", evidence
    return "unknown", evidence
