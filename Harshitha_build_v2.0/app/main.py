import asyncio
import json
import os
import secrets
import socket
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import Cookie, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel


APP_PORT = 8100
SENTRA_BACKEND_URL = os.getenv(
    "SENTRA_BACKEND_URL",
    "http://127.0.0.1:8000/events",
)

APP_HOSTNAME = socket.gethostname()
APP_PROCESS = "sentra_internal_app"

USERS = {
    "analyst": {
        "password": "analyst123",
        "role": "analyst",
    },
    "admin": {
        "password": "admin123",
        "role": "admin",
    },
}

sessions: Dict[str, Dict[str, str]] = {}


EVENT_IDS = {
    "authentication_success": 1001,
    "authentication_failure": 1002,
    "api_request": 1003,
    "authorization_failure": 1004,
    "restricted_resource_access": 1005,
}


class LoginRequest(BaseModel):
    username: str
    password: str


app = FastAPI(
    title="SENTRA Internal Application",
    version="0.1.0",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_event(
    *,
    request: Request,
    event_name: str,
    username: Optional[str],
    event_id: int,
    severity: str,
    result: str,
    status_code: int,
    extra_raw: Optional[dict] = None,
    session_id: Optional[str] = None,
) -> dict:

    client_ip = request.client.host if request.client else None
    client_port = request.client.port if request.client else None

    raw = {
        "application": "SENTRA Internal App",
        "endpoint": request.url.path,
        "method": request.method,
        "status_code": status_code,
        "result": result,
        "severity": severity,
        "request_id": str(uuid.uuid4()),
        "user_agent": request.headers.get("user-agent", "-"),
    }

    if extra_raw:
        raw.update(extra_raw)

    return {
        "id": f"internal-app-{uuid.uuid4().hex[:12]}",
        "timestamp": utc_now(),
        "source": "internal_app",
        "event_type": "application",
        "event_name": event_name,
        "event_id": event_id,
        "user": {
            "name": username or "anonymous",
            "target_name": username,
            "target_sid": None,
            "target_domain": "SENTRA-APP",
            "subject_name": username,
            "subject_sid": None,
            "subject_domain": "SENTRA-APP",
        },
        "host": {
            "name": APP_HOSTNAME,
            "workstation": APP_HOSTNAME,
        },
        "authentication": {
            "logon_type": None,
            "logon_type_name": "Application",
            "logon_process": "SENTRA-APP",
            "package": "session-cookie",
        },
        "network": {
            "source_ip": client_ip,
            "source_port": client_port,
        },
        "process": {
            "name": APP_PROCESS,
            "pid": str(os.getpid()),
        },
        "correlation": {
            "logon_id": session_id,
            "linked_logon_id": None,
        },
        "raw": raw,
    }


def post_to_sentra(event: dict) -> None:
    payload = json.dumps(event).encode("utf-8")

    request = urllib.request.Request(
        SENTRA_BACKEND_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=2) as response:
        response.read()


async def emit_event(event: dict) -> None:
    try:
        await asyncio.to_thread(post_to_sentra, event)
        print(
            f"[APP -> SENTRA] "
            f"{event['event_name']} "
            f"user={event['user']['name']} "
            f"status={event['raw']['status_code']}"
        )
    except Exception as exc:
        print(
            f"[APP -> SENTRA ERROR] "
            f"{event['event_name']} "
            f"{type(exc).__name__}: {exc}"
        )


def get_session(session_id: Optional[str]) -> Optional[dict]:
    if not session_id:
        return None

    return sessions.get(session_id)


@app.get("/")
async def home():
    return FileResponse("app/static/index.html")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sentra-internal-app",
        "active_sessions": len(sessions),
        "sentra_backend": SENTRA_BACKEND_URL,
    }


@app.post("/api/login")
async def login(payload: LoginRequest, request: Request, response: Response):

    username = payload.username.strip()

    user = USERS.get(username)

    if not user or payload.password != user["password"]:

        event = build_event(
            request=request,
            event_name="authentication_failure",
            username=username or "anonymous",
            event_id=EVENT_IDS["authentication_failure"],
            severity="medium",
            result="denied",
            status_code=401,
            extra_raw={
                "reason": "invalid_credentials",
                "role": user["role"] if user else "unknown",
            },
        )

        await emit_event(event)

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    session_id = secrets.token_urlsafe(24)

    sessions[session_id] = {
        "username": username,
        "role": user["role"],
        "created_at": utc_now(),
    }

    event = build_event(
        request=request,
        event_name="authentication_success",
        username=username,
        event_id=EVENT_IDS["authentication_success"],
        severity="low",
        result="allowed",
        status_code=200,
        extra_raw={
            "role": user["role"],
            "authentication_method": "application_login",
        },
        session_id=session_id,
    )

    await emit_event(event)

    response.set_cookie(
        key="sentra_session",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=3600,
    )

    return {
        "authenticated": True,
        "username": username,
        "role": user["role"],
    }


@app.post("/api/logout")
async def logout(
    request: Request,
    response: Response,
    sentra_session: Optional[str] = Cookie(default=None),
):

    session = get_session(sentra_session)

    if session:
        sessions.pop(sentra_session, None)

    response.delete_cookie("sentra_session")

    return {
        "logged_out": True,
    }


@app.get("/api/me")
async def me(
    request: Request,
    sentra_session: Optional[str] = Cookie(default=None),
):

    session = get_session(sentra_session)

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
        )

    event = build_event(
        request=request,
        event_name="api_request",
        username=session["username"],
        event_id=EVENT_IDS["api_request"],
        severity="low",
        result="allowed",
        status_code=200,
        extra_raw={
            "role": session["role"],
            "operation": "read_current_user",
        },
        session_id=sentra_session,
    )

    await emit_event(event)

    return {
        "username": session["username"],
        "role": session["role"],
    }


@app.get("/api/profile")
async def profile(
    request: Request,
    sentra_session: Optional[str] = Cookie(default=None),
):

    session = get_session(sentra_session)

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
        )

    event = build_event(
        request=request,
        event_name="api_request",
        username=session["username"],
        event_id=EVENT_IDS["api_request"],
        severity="low",
        result="allowed",
        status_code=200,
        extra_raw={
            "role": session["role"],
            "operation": "read_profile",
        },
        session_id=sentra_session,
    )

    await emit_event(event)

    return {
        "service": "SENTRA Internal Application",
        "account": session["username"],
        "role": session["role"],
        "message": "Protected application resource accessed.",
    }


@app.get("/api/admin")
async def admin_endpoint(
    request: Request,
    sentra_session: Optional[str] = Cookie(default=None),
):

    session = get_session(sentra_session)

    if not session:

        event = build_event(
            request=request,
            event_name="authentication_failure",
            username="anonymous",
            event_id=EVENT_IDS["authentication_failure"],
            severity="medium",
            result="denied",
            status_code=401,
            extra_raw={
                "reason": "authentication_required",
                "operation": "admin_endpoint",
            },
        )

        await emit_event(event)

        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    request_event = build_event(
        request=request,
        event_name="api_request",
        username=session["username"],
        event_id=EVENT_IDS["api_request"],
        severity="medium",
        result="requested",
        status_code=200,
        extra_raw={
            "role": session["role"],
            "operation": "admin_endpoint",
        },
        session_id=sentra_session,
    )

    await emit_event(request_event)

    if session["role"] != "admin":

        event = build_event(
            request=request,
            event_name="authorization_failure",
            username=session["username"],
            event_id=EVENT_IDS["authorization_failure"],
            severity="high",
            result="denied",
            status_code=403,
            extra_raw={
                "required_role": "admin",
                "actual_role": session["role"],
                "operation": "admin_endpoint",
            },
            session_id=sentra_session,
        )

        await emit_event(event)

        raise HTTPException(
            status_code=403,
            detail="Administrator privileges required",
        )

    event = build_event(
        request=request,
        event_name="restricted_resource_access",
        username=session["username"],
        event_id=EVENT_IDS["restricted_resource_access"],
        severity="high",
        result="allowed",
        status_code=200,
        extra_raw={
            "required_role": "admin",
            "actual_role": session["role"],
            "operation": "admin_endpoint",
        },
        session_id=sentra_session,
    )

    await emit_event(event)

    return {
        "access": "granted",
        "resource": "Security Operations Administration",
        "message": "Restricted resource accessed by authorized administrator.",
    }


