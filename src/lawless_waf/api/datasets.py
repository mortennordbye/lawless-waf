"""Dataset endpoints: trigger on-demand download (guarded) and list cached datasets."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from .. import appconfig, service
from ..azure.discovery import AzureCliError
from ..models import DATE_PATTERN, DatasetCreate, EstimateRequest
from ..ratelimit import download_limit, limiter, query_limit
from ..settings import get_settings
from .deps import get_cache

router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.post("")
@limiter.limit(download_limit)
def create_dataset(request: Request, body: DatasetCreate) -> dict:
    s = get_settings()
    cfg = appconfig.to_azure_config(appconfig.load_target(s))
    try:
        return service.ensure_dataset(
            get_cache(), cfg, body.date, body.hour, body.force, s.offline, body.incremental
        )
    except service.OfflineError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except service.DownloadInProgress as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except AzureCliError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e


@router.get("/stream")
@limiter.limit(download_limit)
def stream_dataset(
    request: Request,
    date: Annotated[str, Query(pattern=DATE_PATTERN)],
    hour: Annotated[int | None, Query(ge=0, le=23)] = None,
    force: bool = False,
    total: Annotated[int | None, Query(ge=0)] = None,
) -> StreamingResponse:
    """Download a day/hour as Server-Sent Events, streaming live blob-level progress.

    GET (so the browser's EventSource/fetch streaming can consume it); the heavy work and the
    same guards as POST live in :func:`service.stream_dataset`, which emits a terminal
    ``done`` or ``error`` event rather than raising mid-stream.
    """
    s = get_settings()
    cfg = appconfig.to_azure_config(appconfig.load_target(s))
    cache = get_cache()

    def events() -> object:
        for ev in service.stream_dataset(cache, cfg, date, hour, force, s.offline, total):
            yield f"data: {json.dumps(ev)}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
def delete_dataset(request: Request, dataset_id: str) -> dict:
    # Not get_existing_dataset: that requires merged.json, but a failed download leaves only
    # partial raw/ blobs — those must be deletable too. cache.delete handles both; 404 only
    # when there was nothing at all.
    try:
        result = service.delete_dataset(get_cache(), dataset_id)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid dataset id") from e
    if not result["deleted"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"dataset {dataset_id} not found")
    return result
