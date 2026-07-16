"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Query, status

from ..cache import Dataset, DatasetCache, Scope
from ..models import POLICY_PATTERN
from ..settings import get_settings


def get_cache() -> DatasetCache:
    return DatasetCache(get_settings().data_dir)


def get_existing_dataset(dataset_id: str) -> Dataset:
    """Resolve a dataset id to a present dataset, or 404."""
    try:
        ds = get_cache().get(dataset_id)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid dataset id") from e
    if not ds.exists:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"dataset {dataset_id} not found")
    return ds


def get_scope(
    dataset_id: str,
    dataset: Annotated[list[str] | None, Query()] = None,
    policy: Annotated[str | None, Query(pattern=POLICY_PATTERN)] = None,
) -> Scope:
    """The analysis scope: the path dataset plus any extra ``?dataset=`` ids (to span several
    days), optionally filtered to one WAF ``policy``. Every id must exist (else 404); all must be
    the same WAF type (mixing Front Door and Application Gateway in one analysis is meaningless)."""
    ids = list(dict.fromkeys([dataset_id, *(dataset or [])]))
    datasets = tuple(get_existing_dataset(i) for i in ids)
    if len({d.waf_type for d in datasets}) > 1:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "a scope cannot mix WAF types (Front Door and Application Gateway)",
        )
    return Scope(datasets, policy)


ScopeDep = Annotated[Scope, Depends(get_scope)]
