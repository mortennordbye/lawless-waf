"""The 100-exclusion-slot guard + consolidation hints (runbook "Hard limit" section)."""

from __future__ import annotations

import re
from collections import defaultdict

LIMIT = 100

_SELECTOR_RE = re.compile(r'\bselector\b\s*=\s*"([^"]*)"')
_MATCHVAR_RE = re.compile(r'\bmatch_variable\b\s*=\s*"([^"]*)"')
_MIN_SHARED_PREFIX = 4

# Exclusion blocks are flat `{ ... }` with no nested braces; grab each and pull its attrs.
_BLOCK_RE = re.compile(r"\{([^{}]*)\}", re.S)


def _attr(body: str, name: str) -> str | None:
    m = re.search(rf'\b{name}\b\s*=\s*"([^"]*)"', body)
    return m.group(1) if m else None


def parse_exclusions(tf_text: str) -> list[dict]:
    """Parse exclusion blocks into ``{match_variable, operator, selector}`` triples.

    A block counts as an exclusion if it carries both ``match_variable`` and ``selector``
    (other Terraform blocks won't). The operator attribute is ``operator`` in the Front Door
    resource and ``selector_match_operator`` in the Application Gateway resource — accept either.
    ``operator`` defaults to ``Equals`` when omitted.
    """
    out: list[dict] = []
    for body in _BLOCK_RE.findall(tf_text):
        mv, sel = _attr(body, "match_variable"), _attr(body, "selector")
        if mv and sel:
            op = _attr(body, "operator") or _attr(body, "selector_match_operator") or "Equals"
            out.append({"match_variable": mv, "operator": op, "selector": sel})
    return out


def selector_matches(exclusion: dict, selector: str) -> bool:
    """Does ``exclusion`` cover the given selector, honouring its operator?"""
    op, sel = exclusion["operator"], exclusion["selector"]
    if op == "Equals":
        return selector == sel
    if op == "StartsWith":
        return selector.startswith(sel)
    if op == "EndsWith":
        return selector.endswith(sel)
    if op == "Contains":
        return sel in selector
    if op == "EqualsAny":  # Application Gateway wildcard (selector forced to "*")
        return True
    return selector == sel  # unknown operator: fall back to exact


def count_exclusions(tf_text: str) -> dict:
    """Count active exclusion slots and suggest consolidations to stay under the limit."""
    selectors = _SELECTOR_RE.findall(tf_text)
    match_vars = _MATCHVAR_RE.findall(tf_text)
    count = len(selectors)

    by_mv: dict[str, list[str]] = defaultdict(list)
    # Pair each match_variable with the selector that follows it (HCL writes them adjacent).
    for mv, sel in zip(match_vars, selectors, strict=False):
        by_mv[mv].append(sel)

    return {
        "count": count,
        "limit": LIMIT,
        "remaining": LIMIT - count,
        "by_match_variable": {mv: len(s) for mv, s in by_mv.items()},
        "consolidation_hints": _consolidation_hints(by_mv),
    }


def _consolidation_hints(by_mv: dict[str, list[str]]) -> list[dict]:
    hints: list[dict] = []
    for mv, selectors in by_mv.items():
        uniq = sorted(set(selectors))
        for i, a in enumerate(uniq):
            for b in uniq[i + 1 :]:
                shared = _common_prefix(a, b)
                if len(shared) >= _MIN_SHARED_PREFIX:
                    hints.append(
                        {
                            "match_variable": mv,
                            "selectors": [a, b],
                            "suggestion": f'consolidate into one StartsWith "{shared}" slot',
                            "slots_saved": 1,
                        }
                    )
    return hints


def _common_prefix(a: str, b: str) -> str:
    n = 0
    for ca, cb in zip(a, b, strict=False):
        if ca != cb:
            break
        n += 1
    return a[:n]
