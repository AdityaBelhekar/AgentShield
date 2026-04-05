from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from agentshield.runtime import list_active_agents

router = APIRouter(tags=["agents"])


class ConnectedAgentResponse(BaseModel):
    """Connected wrapped-agent metadata returned by backend."""

    name: str
    framework: str
    policy: str
    status: str
    active: bool


@router.get("/agents", response_model=list[ConnectedAgentResponse])
async def get_connected_agents() -> list[ConnectedAgentResponse]:
    """Return active wrapped agent runtimes.

    Returns:
        List of connected agent metadata records.
    """
    records: list[dict[str, Any]] = list_active_agents()
    return [
        ConnectedAgentResponse(
            name=str(record.get("name", "unknown")),
            framework=str(record.get("framework", "unknown")),
            policy=str(record.get("policy", "unknown")),
            status=str(record.get("status", "disconnected")),
            active=bool(record.get("active", False)),
        )
        for record in records
    ]
