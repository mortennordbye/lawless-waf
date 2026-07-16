"""Pydantic request models + shared validation patterns (boundary validation)."""

from __future__ import annotations

from pydantic import BaseModel, Field

DATE_PATTERN = r"^\d{4}-\d{2}-\d{2}$"
# WAF product a dataset came from — namespaces the cache so Front Door and Application Gateway
# logs for the same date coexist. Keep in sync with duck.schema.WAF_TYPES.
WAF_TYPE_PATTERN = r"^(frontdoor|appgw)$"
# Dataset ids are "<waf_type>:<date>[-h<HH>]", e.g. "frontdoor:2026-06-24", "appgw:2026-06-24-h10".
DATASET_ID_PATTERN = r"^(?:frontdoor|appgw):\d{4}-\d{2}-\d{2}(-h\d{2})?$"
# Rule ids are usually 6–8 digits (e.g. 942100, 99031001) but managed rulesets also use
# alphanumeric ids like Bot300200 (BotManager) — accept both so every firing rule is drillable.
RULE_ID_PATTERN = r"^[A-Za-z0-9]{3,16}$"
MATCH_VARIABLE_PATTERN = r"^[A-Za-z0-9_.:\[\]-]{1,60}$"
IP_PATTERN = r"^[0-9a-fA-F:.]{3,45}$"
# Free-text search term (IP / URI / host substring). Printable ASCII, bounded length; the
# value is bound as a DuckDB parameter, so this only caps abuse, not injection.
SEARCH_PATTERN = r"^[\x20-\x7E]{1,200}$"
# WAF action filter for the Overview event drill — exactly the three firing actions.
ACTION_PATTERN = r"^(Block|AnomalyScoring|Log)$"
# WAF policy name (scopes analysis). Interpolated into the view literal, so keep it
# to a safe charset; quotes are escaped in the engine regardless.
POLICY_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"
# Azure tracking reference, e.g. 20260625T090015Z-1789c9dfffcd...
TRACKING_REF_PATTERN = r"^[A-Za-z0-9:_-]{1,128}$"


class DatasetCreate(BaseModel):
    date: str = Field(pattern=DATE_PATTERN, examples=["2026-06-24"])
    hour: int | None = Field(default=None, ge=0, le=23)
    force: bool = False
    # Live tailing: re-check Azure and pull only newly-appeared blobs (no overwrite), vs `force`
    # which re-downloads the whole window.
    incremental: bool = False


class EstimateRequest(BaseModel):
    date_from: str = Field(pattern=DATE_PATTERN, examples=["2026-06-20"])
    date_to: str = Field(pattern=DATE_PATTERN, examples=["2026-06-24"])
    hour: int | None = Field(default=None, ge=0, le=23)


# Ceiling on a pasted waf-exclusions.tf. A real one is a few KB; this only caps abuse.
MAX_TF_CONTENT = 1_000_000


class ExclusionsCountRequest(BaseModel):
    tf_content: str = Field(max_length=MAX_TF_CONTENT, description="Contents of waf-exclusions.tf")
