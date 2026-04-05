from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from backend.dependencies import get_event_store
from backend.event_store import EventStore
from backend.routers.schemas import ThreatResponse, threat_to_response

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

DEFAULT_LIMIT: int = 100
MAX_LIMIT: int = 1000


def _cap_limit(limit: int, cap: int) -> int:
    """Clamp limit to safe bounds.

    Args:
        limit: Requested limit.
        cap: Maximum allowed.

    Returns:
        Sanitized limit.
    """
    return max(0, min(limit, cap))


@router.get("", response_model=list[ThreatResponse])
async def list_alerts(
    store: Annotated[EventStore, Depends(get_event_store)],
    limit: Annotated[int, Query(ge=0)] = DEFAULT_LIMIT,
) -> list[ThreatResponse]:
    """Return threat alerts from event store.

    Args:
        store: Event storage dependency.
        limit: Maximum number of alerts.

    Returns:
        Serialized alert list.
    """
    safe_limit = _cap_limit(limit, MAX_LIMIT)
    threats = await store.get_threats()
    return [threat_to_response(event) for event in threats[:safe_limit]]
