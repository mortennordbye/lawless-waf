"""Per-IP block segmentation — separate vulnerability-scanner noise from genuine FPs.

This is the gate to read BEFORE proposing any exclusion: in the sample data a single
scanner produced 678 of 689 blocks, so excluding "the blocked rules" blindly would punch
~30 holes for one attacker. An IP that hits many distinct rule groups or many distinct URIs
is almost certainly scanning; a low-volume IP hitting one rule with app-shaped values is a
false-positive candidate. Thresholds are tunable; the report surfaces the evidence so the
final call stays with the human/Claude Code.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

# Defaults — surfaced in the report so callers can see what produced each verdict.
MIN_BLOCKS = 20
MIN_GROUPS = 3
MIN_URIS = 15


@dataclass(frozen=True)
class IpVerdict:
    ip: str
    blocks: int
    distinct_rule_groups: int
    distinct_rules: int
    distinct_uris: int
    verdict: str  # "scanner" | "fp_candidate"


@dataclass(frozen=True)
class ScannerReport:
    total_blocks: int
    scanner_ips: list[str]
    by_ip: list[IpVerdict]
    thresholds: dict[str, int]

    @property
    def genuine_fp_candidate_blocks(self) -> int:
        return sum(v.blocks for v in self.by_ip if v.verdict == "fp_candidate")

    def to_dict(self) -> dict:
        return {
            "total_blocks": self.total_blocks,
            "scanner_ips": self.scanner_ips,
            "genuine_fp_candidate_blocks": self.genuine_fp_candidate_blocks,
            "thresholds": self.thresholds,
            "by_ip": [asdict(v) for v in self.by_ip],
        }


def _is_scanner(blocks: int, groups: int, uris: int) -> bool:
    if blocks >= MIN_BLOCKS and groups >= MIN_GROUPS:
        return True
    return uris >= MIN_URIS


def build_report(block_events: list[dict]) -> ScannerReport:
    """``block_events`` rows: {ip, tracking_reference, rule_groups[], rule_ids[], uri}."""
    by_ip: dict[str, dict] = {}
    for ev in block_events:
        agg = by_ip.setdefault(
            ev["ip"], {"blocks": 0, "groups": set(), "rules": set(), "uris": set()}
        )
        agg["blocks"] += 1
        agg["groups"].update(g for g in (ev.get("rule_groups") or []) if g)
        agg["rules"].update(r for r in (ev.get("rule_ids") or []) if r)
        if ev.get("uri"):
            agg["uris"].add(ev["uri"])

    verdicts: list[IpVerdict] = []
    for ip, agg in by_ip.items():
        groups, rules, uris = len(agg["groups"]), len(agg["rules"]), len(agg["uris"])
        verdict = "scanner" if _is_scanner(agg["blocks"], groups, uris) else "fp_candidate"
        verdicts.append(
            IpVerdict(ip, agg["blocks"], groups, rules, uris, verdict)
        )

    verdicts.sort(key=lambda v: v.blocks, reverse=True)
    return ScannerReport(
        total_blocks=sum(v.blocks for v in verdicts),
        scanner_ips=[v.ip for v in verdicts if v.verdict == "scanner"],
        by_ip=verdicts,
        thresholds={"min_blocks": MIN_BLOCKS, "min_groups": MIN_GROUPS, "min_uris": MIN_URIS},
    )
