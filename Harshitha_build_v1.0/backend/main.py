from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from event_bus import event_bus
from intelligence import intelligence
from schemas import SentraEvent


app = FastAPI(
    title="SENTRA Backend",
    version="0.2.0",
)


recent_events: List[SentraEvent] = []

MAX_RECENT_EVENTS = 100


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sentra-backend",
        "events_received": len(recent_events),
        "incidents": len(
            intelligence.get_incidents()
        ),
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
        "[SENTRA BACKEND] "
        f"{event.event_name} "
        f"({event.event_id}) "
        f"source={event.source} "
        f"user={event.user.name}"
    )

    incident = intelligence.add_event(event)

    if incident:

        print(
            "[SENTRA INCIDENT] "
            f"{incident['title']} | "
            f"risk={incident['risk']} | "
            f"severity={incident['severity']}"
        )

    return {
        "accepted": True,
        "event_id": event.id,
        "incident": incident,
    }


@app.get("/incidents")
async def get_incidents():

    incidents = intelligence.get_incidents()

    return {
        "count": len(incidents),
        "incidents": incidents,
    }


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):

    incident = intelligence.get_incident(
        incident_id
    )

    if not incident:

        return {
            "found": False,
            "incident": None,
        }

    return {
        "found": True,
        "incident": incident,
    }


@app.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket
):

    await websocket.accept()

    queue = event_bus.subscribe()

    print(
        "[WebSocket] Client connected"
    )

    try:

        for event in recent_events:

            await websocket.send_json(
                event.model_dump()
            )

        while True:

            event = await queue.get()

            await websocket.send_json(
                event.model_dump()
            )

    except WebSocketDisconnect:

        print(
            "[WebSocket] Client disconnected"
        )

    finally:

        event_bus.unsubscribe(queue)
