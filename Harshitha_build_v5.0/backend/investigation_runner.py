from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


AUTH_EVENTS = {
    "authentication_success",
    "authentication_failure",
    "logon_success",
    "logon_failure",
    "explicit_credentials",
}

RESTRICTED_EVENTS = {
    "restricted_resource_access",
    "authorization_failure",
}


def _parse_timestamp(value: Any):
    if not value:
        return None

    if isinstance(value, datetime):
        timestamp = value
    else:
        try:
            timestamp = datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            return None

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(
            tzinfo=timezone.utc
        )

    return timestamp


def run_investigation(
    incident: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run safe, deterministic, read-only investigation checks
    against the evidence already attached to the incident.

    No telemetry is generated.
    No system state is changed.
    No risk score is modified.
    """

    evidence: List[Dict[str, Any]] = incident.get(
        "evidence",
        []
    )

    now = datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(minutes=15)

    recent_authentication = []
    restricted_activity = []
    recent_authentication_ids = []
    restricted_activity_ids = []
    sources = set()

    for item in evidence:

        event_name = str(
            item.get("event_name") or ""
        ).lower()

        event_id = item.get("event_id")
        source = item.get("source")

        timestamp = _parse_timestamp(
            item.get("timestamp")
        )

        if source:
            sources.add(source)

        if event_name in AUTH_EVENTS:

            recent_authentication.append(
                item
            )

            if event_id:
                recent_authentication_ids.append(
                    event_id
                )

        if event_name in RESTRICTED_EVENTS:

            restricted_activity.append(
                item
            )

            if event_id:
                restricted_activity_ids.append(
                    event_id
                )

    recent_authentication_count = 0
    recent_authentication_recent_ids = []

    for item in recent_authentication:

        timestamp = _parse_timestamp(
            item.get("timestamp")
        )

        if (
            timestamp
            and timestamp >= recent_cutoff
        ):

            recent_authentication_count += 1

            event_id = item.get("event_id")

            if event_id:
                recent_authentication_recent_ids.append(
                    event_id
                )

    cross_source = len(sources) > 1

    return {
        "incident_id": incident.get("id"),

        "checked_at":
            now.isoformat(),

        "checks": {

            "recent_authentication_activity": {

                "status": (
                    "observed"
                    if recent_authentication_count > 0
                    else "none_observed"
                ),

                "event_count":
                    recent_authentication_count,

                "evidence_ids":
                    recent_authentication_recent_ids,
            },

            "cross_source_activity": {

                "status": (
                    "observed"
                    if cross_source
                    else "not_observed"
                ),

                "sources":
                    sorted(sources),

                "source_count":
                    len(sources),

            },

            "restricted_resource_activity": {

                "status": (
                    "observed"
                    if restricted_activity
                    else "none_observed"
                ),

                "event_count":
                    len(restricted_activity),

                "evidence_ids":
                    restricted_activity_ids,
            },

        },
    }