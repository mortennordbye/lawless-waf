"""Exclusion-count endpoint: the 100-slot guard + consolidation hints.

Accepts the Terraform content directly (Claude Code posts ``waf-exclusions.tf``); this
avoids the app needing filesystem access to a path outside its tree."""

from __future__ import annotations

from fastapi import APIRouter, Request

from .. import service
from ..models import ExclusionsCountRequest
from ..ratelimit import limiter, query_limit

router = APIRouter(prefix="/exclusions", tags=["exclusions"])


@router.post("/count")
@limiter.limit(query_limit)
def count(request: Request, body: ExclusionsCountRequest) -> dict:
    return service.exclusions_count(body.tf_content)
