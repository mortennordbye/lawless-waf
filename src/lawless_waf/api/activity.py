"""MCP activity feed: tail the shared activity log to the web UI over SSE."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from .. import activity

router = APIRouter(prefix="/activity", tags=["activity"])


@router.get("/stream")
async def stream_activity(request: Request) -> StreamingResponse:
    """Server-Sent Events of MCP tool calls. Emits the recent backlog first, then new events as
    the MCP server appends them (it shares ``$DATA_DIR``). One long-lived connection per client."""

    async def events() -> object:
        last_ts = 0.0
        backlog = True
        while not await request.is_disconnected():
            for ev in activity.read(after=last_ts, limit=50 if backlog else None):
                last_ts = max(last_ts, ev.get("ts", 0.0))
                yield f"data: {json.dumps(ev)}\n\n"
            backlog = False
            yield ": ping\n\n"  # heartbeat so a stalled proxy/client notices a dead connection
            await asyncio.sleep(1.0)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
