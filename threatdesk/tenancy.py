"""Org-scoped data access. Every query for tenant data goes through these helpers."""
from __future__ import annotations

from typing import TypeVar

from fastapi import HTTPException
from sqlalchemy import Select, select
from sqlalchemy.orm import Session

T = TypeVar("T")


def scoped(model: type[T], org_id: int) -> Select:
    return select(model).where(model.org_id == org_id)  # type: ignore[attr-defined]


def get_owned(db: Session, model: type[T], obj_id: int, org_id: int) -> T:
    """Fetch by id within the org; another org's row is indistinguishable from a missing one (404)."""
    obj = db.scalar(select(model).where(model.id == obj_id, model.org_id == org_id))  # type: ignore[attr-defined]
    if obj is None:
        raise HTTPException(404, "Not found.")
    return obj
