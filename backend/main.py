from typing import List

from fastapi import (
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
)

from fastapi.middleware.cors import CORSMiddleware

from ai_analyst import (
    analyze_incident,
    get_analysis,
)

from event_bus import event_bus
from intelligence import intelligence
from schemas import SentraEvent


app = FastAPI(
    title="SENTRA Backend",
    version="0.3.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8100",
        "http://localhost:8100",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


recent_events: List[SentraEvent] = []
MAX_RECENT_EVENTS = 100


def build_ai_evidence_context(incident: dict) -> List[dict]:
    """
    Build AI context from the incident's actual evidence list.

    The incident evidence is the source of truth.
    Each evidence item is enriched with raw telemetry from
    intelligence.recent_events when available.

    This ensures the AI receives all evidence contributing
    to the incident, including Windows Security and Internal App
    telemetry.
    """

    # Index currently retained telemetry by event ID.
    event_lookup = {
        event.id: event
        for event in intelligence.recent_events
    }

    context = []

    # IMPORTANT:
    # Iterate directly over incident evidence.
    # Do not filter the evidence through recent_events.
    for evidence_item in incident.get("evidence", []):
        event_id = evidence_item.get("event_id")

        item = {
            "event_id": event_id,
            "timestamp": evidence_item.get("timestamp"),
            "source": evidence_item.get("source"),
            "event_name": evidence_item.get("event_name"),
            "user": evidence_item.get("user"),
            "host": evidence_item.get("host"),
            "severity": evidence_item.get("severity"),
            "observed_context": {},
        }

        # Try to enrich this evidence item with its original
        # telemetry event.
        event = event_lookup.get(event_id)

        if event:
            raw = event.raw or {}
            observed_context = {}

            # -----------------------------------------
            # Common network context
            # -----------------------------------------
            network = getattr(event, "network", None)

            if network:
                source_ip = getattr(
                    network,
                    "source_ip",
                    None,
                )

                source_port = getattr(
                    network,
                    "source_port",
                    None,
                )

                if source_ip not in {
                    None,
                    "",
                    "-",
                }:
                    observed_context["source_ip"] = source_ip

                if source_port is not None:
                    observed_context["source_port"] = source_port

            # -----------------------------------------
            # Windows authentication context
            # -----------------------------------------
            windows_keys = {
                "LogonType",
                "LogonProcessName",
                "AuthenticationPackageName",
                "IpAddress",
                "IpPort",
                "Status",
                "FailureReason",
                "SubStatus",
                "TargetUserName",
                "TargetServerName",
            }

            for key in windows_keys:
                if raw.get(key) not in {
                    None,
                    "",
                    "-",
                }:
                    observed_context[key] = raw[key]

            # -----------------------------------------
            # Internal application context
            # -----------------------------------------
            application_keys = {
                "application",
                "endpoint",
                "method",
                "status_code",
                "result",
                "role",
                "actual_role",
                "required_role",
                "operation",
                "reason",
                "authentication_method",
                "severity",
            }

            for key in application_keys:
                if raw.get(key) not in {
                    None,
                    "",
                    "-",
                }:
                    observed_context[key] = raw[key]

            item["observed_context"] = observed_context

            # Use canonical event values where available.
            item["timestamp"] = getattr(
                event,
                "timestamp",
                item["timestamp"],
            )

            item["source"] = getattr(
                event,
                "source",
                item["source"],
            )

            item["event_name"] = getattr(
                event,
                "event_name",
                item["event_name"],
            )

            event_user = getattr(
                event,
                "user",
                None,
            )

            if event_user:
                item["user"] = getattr(
                    event_user,
                    "name",
                    item["user"],
                )

            item["host"] = getattr(
                event,
                "host",
                item["host"],
            )

            # DO NOT access event.severity here.
            # SentraEvent does not contain a top-level severity field.
            # Severity remains the value stored in incident evidence.

        context.append(item)

    # Chronological order for AI analysis.
    context.sort(
        key=lambda item: item.get("timestamp") or ""
    )

    return context


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sentra-backend",
        "events_received": len(recent_events),
        "incidents": len(
            intelligence.get_incidents()
        ),
        "ai_model": "gemma2-2b-local:latest",
    }


@app.get("/events")
async def get_events():
    return {
        "count": len(recent_events),
        "events": recent_events,
    }


@app.post("/events")
async def ingest_event(
    event: SentraEvent,
):
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

    incident = intelligence.add_event(
        event
    )

    if incident:
        print(
            "[SENTRA INCIDENT] "
            f"{incident['title']} | "
            f"risk={incident['risk']} | "
            f"severity={incident['severity']} | "
            f"sources={','.join(incident['sources'])}"
        )

    return {
        "accepted": True,
        "event_id": event.id,
        "incident": incident,
    }


@app.get("/incidents")
async def get_incidents():
    incidents = []

    for incident in intelligence.get_incidents():
        incident_copy = dict(incident)

        incident_copy["ai_analysis"] = (
            get_analysis(
                incident["id"]
            )
        )

        incidents.append(
            incident_copy
        )

    return {
        "count": len(incidents),
        "incidents": incidents,
    }


@app.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
):
    incident = intelligence.get_incident(
        incident_id
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "found": True,
        "incident": incident,
        "ai_analysis": get_analysis(
            incident_id
        ),
    }


@app.post("/incidents/{incident_id}/analyze")
async def analyze_incident_endpoint(
    incident_id: str,
):
    incident = intelligence.get_incident(
        incident_id
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    print(
        "[AI ANALYST] "
        f"Analyzing incident {incident_id}"
    )

    evidence_context = build_ai_evidence_context(
        incident
    )

    print(
        "[AI ANALYST] "
        f"Evidence events supplied: "
        f"{len(evidence_context)}"
    )

    for item in evidence_context:
        print(
            "[AI EVIDENCE] "
            f"{item['event_id']} | "
            f"{item['timestamp']} | "
            f"{item['source']} | "
            f"{item['event_name']}"
        )

    try:
        analysis = await analyze_incident(
            incident,
            evidence_context,
        )

    except Exception as exc:
        print(
            "[AI ANALYST ERROR] "
            f"{type(exc).__name__}: {exc}"
        )

        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    print(
        "[AI ANALYST] "
        f"Completed incident {incident_id} "
        f"confidence={analysis['confidence']:.2f}"
    )

    return {
        "incident_id": incident_id,
        "analysis": analysis,
    }


@app.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
):
    await websocket.accept()

    queue = event_bus.subscribe()

    print(
        "[WebSocket] Client connected"
    )

    try:
        # Send currently buffered events first.
        for event in recent_events:
            await websocket.send_json(
                event.model_dump()
            )

        # Stream new events live.
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
        event_bus.unsubscribe(
            queue
        )