"""Analysis endpoints: firing rules, blocks-by-cause, scanner report, rule drill, search,
the exclusion-context deliverable, plus request detail, before/after diff, and coverage.

Every analysis route runs over a :class:`Scope` (one or more datasets + optional policy),
resolved from the path id and ``?dataset=`` / ``?policy=`` query params.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query, Request

from .. import service
from ..cache import Scope
from ..models import (
    DATASET_ID_PATTERN,
    IP_PATTERN,
    MATCH_VARIABLE_PATTERN,
    RULE_ID_PATTERN,
    SEARCH_PATTERN,
    TRACKING_REF_PATTERN,
    ExclusionsCountRequest,
)
from ..ratelimit import limiter, query_limit
from .deps import ScopeDep, get_existing_dataset

router = APIRouter(prefix="/datasets/{dataset_id}", tags=["analysis"])

RuleId = Annotated[str, Path(pattern=RULE_ID_PATTERN)]
MatchVar = Annotated[str | None, Query(pattern=MATCH_VARIABLE_PATTERN)]


@router.get("/summary")
@limiter.limit(query_limit)
def summary(request: Request, scope: ScopeDep) -> dict:
    return service.summary(scope)


@router.get("/policies")
@limiter.limit(query_limit)
def policies(request: Request, scope: ScopeDep) -> dict:
    return service.list_policies(scope)


@router.get("/firing-rules")
@limiter.limit(query_limit)
def firing_rules(request: Request, scope: ScopeDep) -> dict:
    return service.firing_rules(scope)


@router.get("/scanner-report")
@limiter.limit(query_limit)
def scanner_report(request: Request, scope: ScopeDep) -> dict:
    return service.scanner_report(scope)


@router.get("/blocks-by-cause")
@limiter.limit(query_limit)
def blocks_by_cause(
    request: Request,
    scope: ScopeDep,
    exclude_scanners: bool = True,
    ip: Annotated[str | None, Query(pattern=IP_PATTERN)] = None,
) -> dict:
    return service.blocks_by_cause(scope, exclude_scanners=exclude_scanners, ip=ip)


@router.get("/search")
@limiter.limit(query_limit)
def search(
    request: Request,
    scope: ScopeDep,
    q: Annotated[str, Query(pattern=SEARCH_PATTERN)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict:
    return service.search_events(scope, q, limit=limit)


@router.get("/requests/{tracking_reference}")
@limiter.limit(query_limit)
def request_detail(
    request: Request,
    scope: ScopeDep,
    tracking_reference: Annotated[str, Path(pattern=TRACKING_REF_PATTERN)],
) -> dict:
    return service.request_detail(scope, tracking_reference)


@router.get("/diff")
@limiter.limit(query_limit)
def diff(
    request: Request,
    scope: ScopeDep,
    against: Annotated[str, Query(pattern=DATASET_ID_PATTERN)],
) -> dict:
    after = Scope((get_existing_dataset(against),), scope.policy)
    return service.diff_firing(scope, after)


@router.get("/rules/{rule_id}")
@limiter.limit(query_limit)
def rule_drill(
    request: Request,
    scope: ScopeDep,
    rule_id: RuleId,
    exclude_scanners: bool = True,
    limit: Annotated[int, Query(ge=1, le=100)] = 15,
) -> dict:
    return service.rule_drill(scope, rule_id, exclude_scanners=exclude_scanners, limit=limit)


@router.get("/rules/{rule_id}/events")
@limiter.limit(query_limit)
def rule_events(
    request: Request,
    scope: ScopeDep,
    rule_id: RuleId,
    match_variable: MatchVar = None,
    exclude_scanners: bool = True,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> dict:
    return service.rule_events(
        scope, rule_id, match_variable=match_variable, exclude_scanners=exclude_scanners, limit=limit
    )


@router.get("/rules/{rule_id}/diff")
@limiter.limit(query_limit)
def rule_diff(
    request: Request,
    scope: ScopeDep,
    rule_id: RuleId,
    against: Annotated[str, Query(pattern=DATASET_ID_PATTERN)],
    match_variable: MatchVar = None,
) -> dict:
    after = Scope((get_existing_dataset(against),), scope.policy)
    return service.diff_rule(scope, after, rule_id, match_variable=match_variable)


@router.get("/rules/{rule_id}/exclusion-context")
@limiter.limit(query_limit)
def exclusion_context(
    request: Request,
    scope: ScopeDep,
    rule_id: RuleId,
    match_variable: MatchVar = None,
) -> dict:
    return service.exclusion_context(scope, rule_id, match_variable=match_variable)


@router.post("/exclusions/coverage")
@limiter.limit(query_limit)
def exclusion_coverage(request: Request, scope: ScopeDep, body: ExclusionsCountRequest) -> dict:
    return service.exclusion_coverage(scope, body.tf_content)
