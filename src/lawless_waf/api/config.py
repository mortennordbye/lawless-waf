"""Operator-editable Azure target config (storage account / container / subscription)."""

from __future__ import annotations

from fastapi import APIRouter, Request

from .. import appconfig
from ..appconfig import AzureTarget
from ..ratelimit import limiter, query_limit
from ..settings import get_settings

router = APIRouter(prefix="/config", tags=["config"])


@router.get("")
@limiter.limit(query_limit)
def get_config(request: Request) -> AzureTarget:
    return appconfig.load_target(get_settings())


@router.put("")
@limiter.limit(query_limit)
def put_config(request: Request, target: AzureTarget) -> AzureTarget:
    return appconfig.save_target(get_settings(), target)
