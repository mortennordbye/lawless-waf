"""Dataset endpoints: trigger on-demand download (guarded) and list cached datasets."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .. import appconfig, service
from ..azure.discovery import AzureCliError
from ..cache import Dataset
from ..models import DatasetCreate, EstimateRequest
from ..ratelimit import download_limit, limiter, query_limit
from ..settings import get_settings
from .deps import get_cache, get_existing_dataset

router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.post("")
@limiter.limit(download_limit)
def create_dataset(request: Request, body: DatasetCreate) -> dict:
    s = get_settings()
    cfg = appconfig.to_azure_config(appconfig.load_target(s))
    try:
        return service.ensure_dataset(
            get_cache(), cfg, body.date, body.hour, body.force, s.offline
        )
    except service.OfflineError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except service.DownloadInProgress as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e


@router.post("/estimate")
@limiter.limit(query_limit)
def estimate_dataset(request: Request, body: EstimateRequest) -> dict:
    s = get_settings()
    cfg = appconfig.to_azure_config(appconfig.load_target(s))
    try:
        return service.estimate_range(
            get_cache(), cfg, body.date_from, body.date_to, body.hour, s.offline,
            s.download_blobs_per_sec,
        )
    except service.OfflineError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e
    except AzureCliError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e


@router.post("/speedtest")
@limiter.limit(download_limit)
def speedtest_dataset(request: Request) -> dict:
    s = get_settings()
    cfg = appconfig.to_azure_config(appconfig.load_target(s))
    try:
        return service.speedtest(cfg, s.offline)
    except service.OfflineError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except AzureCliError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e


@router.get("")
@limiter.limit(query_limit)
def list_datasets(request: Request) -> dict:
    return service.list_datasets(get_cache())


@router.delete("")
@limiter.limit(query_limit)
def clear_datasets(request: Request) -> dict:
    return service.clear_datasets(get_cache())


@router.delete("/{dataset_id}")
@limiter.limit(query_limit)
def delete_dataset(request: Request, ds: Annotated[Dataset, Depends(get_existing_dataset)]) -> dict:
    return service.delete_dataset(get_cache(), ds.id)
