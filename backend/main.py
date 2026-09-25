import asyncio
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from event_bus import event_bus
from schemas import SentraEvent


app = FastAPI(
    title="SENTRA Backend",
    version="0.1.0",
)


# Small in-memory history.
# This is intentionally temporary; SQLite will come later.
recent_events: List[SentraEvent] = []

MAX_RECENT_EVENTS = 100


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sentra-backend",
        "events_received": len(recent_events),
    }


@app.get("/events")
async def get_events():
    return {
        "count": len(recent_events),
        "events": recent_events,
    }


@app.post("/events")
async def ingest_event(event: SentraEvent):

    recent_events.append(event)

    if len(recent_events) > MAX_RECENT_EVENTS:
        recent_events.pop(0)

    await event_bus.publish(event)

    print(
        f"[SENTRA BACKEND] "
        f"{event.event_name} "
        f"({event.event_id}) "
        f"user={event.user.name}"
    )

    return {
        "accepted": True,
        "event_id": event.id,
    }


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):

    await websocket.accept()

    queue = event_bus.subscribe()

    print("[WebSocket] Client connected")

    try:

        # Send current history to the new client first.
        for event in recent_events:
            await websocket.send_json(
                event.model_dump()
            )

        # Then stream future events.
        while True:

            event = await queue.get()

            await websocket.send_json(
                event.model_dump()
            )

    except WebSocketDisconnect:

        print("[WebSocket] Client disconnected")

    finally:

        event_bus.unsubscribe(queue)