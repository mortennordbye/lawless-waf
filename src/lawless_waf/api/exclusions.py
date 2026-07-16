"""Exclusion endpoints: the 100-slot guard + consolidation hints, and reading a
``waf-exclusions.tf`` from a local file (e.g. your infra repo mounted into the container)
instead of pasting it.

The coverage/count endpoints accept the Terraform content directly (Claude Code posts
``waf-exclusions.tf``); the local-file endpoints read it from disk, confined to
``EXCLUSIONS_ROOT`` and optionally at a git ref — never an arbitrary host path."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status

from .. import service
from ..localrepo import REF_PATTERN, ExclusionsSource, LocalExclusionsError
from ..models import ExclusionsCountRequest
from ..ratelimit import limiter, query_limit
from ..settings import get_settings

router = APIRouter(prefix="/exclusions", tags=["exclusions"])


@router.post("/count")
@limiter.limit(query_limit)
def count(request: Request, body: ExclusionsCountRequest) -> dict:
    return service.exclusions_count(body.tf_content)


@router.get("/source")
@limiter.limit(query_limit)
def get_source(request: Request) -> dict:
    """The configured local exclusions-file pointer + whether the feature is available."""
    return service.get_exclusions_source(get_settings())


@router.put("/source")
@limiter.limit(query_limit)
def put_source(request: Request, body: ExclusionsSource) -> dict:
    return service.save_exclusions_source(get_settings(), body)


@router.get("/local")
@limiter.limit(query_limit)
def read_local(
    request: Request,
    path: Annotated[str | None, Query(max_length=1000)] = None,
    ref: Annotated[str | None, Query(pattern=REF_PATTERN, max_length=200)] = None,
) -> dict:
    """Read the configured local exclusions file (or the given ``path``/``ref``), confined to
    ``EXCLUSIONS_ROOT``. Returns the content + resolved git commit for the UI to load."""
    try:
        return service.read_local_exclusions(get_settings(), path=path, ref=ref)
    except LocalExclusionsError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
