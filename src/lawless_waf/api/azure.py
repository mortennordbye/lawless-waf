"""Azure session status + resource discovery — the UI uses these for the sign-in badge and
the Settings dropdowns (subscription → storage account → container)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from ..azure import discovery
from ..azure.session import az_status
from ..ratelimit import limiter, query_limit

router = APIRouter(prefix="/azure", tags=["azure"])


@router.get("/status")
@limiter.limit(query_limit)
def status(request: Request) -> dict:
    return az_status().to_dict()


@router.get("/subscriptions")
@limiter.limit(query_limit)
def subscriptions(request: Request) -> dict:
    try:
        return {"subscriptions": discovery.list_subscriptions()}
    except discovery.AzureCliError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/storage-accounts")
@limiter.limit(query_limit)
def storage_accounts(request: Request, subscription: str = Query(min_length=1)) -> dict:
    try:
        return {"storage_accounts": discovery.list_storage_accounts(subscription)}
    except discovery.AzureCliError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.get("/containers")
@limiter.limit(query_limit)
def containers(
    request: Request,
    account: str = Query(min_length=1),
    subscription: str = Query(min_length=1),
) -> dict:
    try:
        return {"containers": discovery.list_containers(account, subscription)}
    except discovery.AzureCliError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
