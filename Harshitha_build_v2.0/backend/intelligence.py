from datetime import datetime, timezone
from typing import Dict, List, Optional

from schemas import SentraEvent


WINDOW_SECONDS = 300
AUTH_SEQUENCE_SECONDS = 120
INCIDENT_THRESHOLD = 40
MAX_EVENTS = 500
MAX_INCIDENTS = 100


def parse_time(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        return datetime.now(timezone.utc)


def event_time(event: SentraEvent) -> datetime:
    return parse_time(event.timestamp)


def host_name(event: SentraEvent) -> str:
    return (
        event.host.name
        or event.host.workstation
        or "unknown-host"
    )


def user_name(event: SentraEvent) -> str:
    return (
        event.user.name
        or event.user.target_name
        or "unknown-user"
    )


def is_relevant(event: SentraEvent) -> bool:

    if event.source == "internal_app":
        return event.event_name in {
            "authentication_failure",
            "authentication_success",
            "authorization_failure",
            "restricted_resource_access",
        }

    if event.source == "windows_security":
        return event.event_name in {
            "logon_failure",
            "explicit_credentials",
        }

    return False


def base_weight(event: SentraEvent) -> int:

    weights = {
        "authentication_failure": 15,
        "authorization_failure": 25,
        "restricted_resource_access": 25,
        "explicit_credentials": 15,
        "logon_failure": 20,
        "authentication_success": 0,
    }

    return weights.get(event.event_name, 0)


class IntelligenceEngine:

    def __init__(self):
        self.recent_events: List[SentraEvent] = []
        self.incidents: Dict[str, dict] = {}

    def add_event(self, event: SentraEvent) -> Optional[dict]:

        self.recent_events.append(event)

        if len(self.recent_events) > MAX_EVENTS:
            self.recent_events.pop(0)

        if not is_relevant(event):
            return None

        host = host_name(event)

        incident_id = self._incident_id(host)

        incident = self._recompute_incident(
            incident_id,
            host,
        )

        if incident["risk"] >= INCIDENT_THRESHOLD:
            self.incidents[incident_id] = incident

            if len(self.incidents) > MAX_INCIDENTS:
                oldest_id = next(iter(self.incidents))
                self.incidents.pop(oldest_id)

            print(
                "[INTELLIGENCE] "
                f"incident={incident['id']} "
                f"risk={incident['risk']} "
                f"title={incident['title']}"
            )

            return incident

        return None

    def _incident_id(self, host: str) -> str:
        safe_host = (
            host
            .lower()
            .replace(" ", "-")
            .replace("\\", "-")
            .replace("/", "-")
        )

        return f"incident-{safe_host}"

    def _recent_for_host(
        self,
        host: str,
    ) -> List[SentraEvent]:

        now = datetime.now(timezone.utc)

        events = []

        for event in self.recent_events:

            if host_name(event) != host:
                continue

            if not is_relevant(event):
                continue

            age = (
                now - event_time(event)
            ).total_seconds()

            if 0 <= age <= WINDOW_SECONDS:
                events.append(event)

        events.sort(
            key=event_time,
        )

        return events

    def _recompute_incident(
        self,
        incident_id: str,
        host: str,
    ) -> dict:

        events = self._recent_for_host(host)

        risk = 0
        reasons = []

        for event in events:
            risk += base_weight(event)

        # ---------------------------------------------------------
        # RULE 1
        # Repeated authentication failures.
        # ---------------------------------------------------------

        users = {}

        for event in events:

            if event.event_name not in {
                "authentication_failure",
                "logon_failure",
            }:
                continue

            username = user_name(event)

            users.setdefault(
                username,
                [],
            ).append(event)

        repeated_failure_users = []

        for username, failures in users.items():

            if len(failures) < 2:
                continue

            first = event_time(failures[0])
            last = event_time(failures[-1])

            if (
                last - first
            ).total_seconds() <= AUTH_SEQUENCE_SECONDS:

                risk += 20

                repeated_failure_users.append(
                    username
                )

                reasons.append(
                    "Repeated authentication failures "
                    f"for {username}"
                )

        # ---------------------------------------------------------
        # RULE 2
        # Failure followed by successful authentication.
        # ---------------------------------------------------------

        for username in users:

            failures = users[username]

            matching_success = any(
                event.event_name
                == "authentication_success"
                and user_name(event) == username
                and 0
                <= (
                    event_time(event)
                    - event_time(failure)
                ).total_seconds()
                <= AUTH_SEQUENCE_SECONDS
                for failure in failures
                for event in events
            )

            if matching_success:

                risk += 15

                reasons.append(
                    "Authentication failure followed "
                    "by successful authentication "
                    f"for {username}"
                )

                break

        # ---------------------------------------------------------
        # RULE 3
        # Successful session followed by authorization failure.
        # ---------------------------------------------------------

        authorization_failures = [
            e for e in events
            if e.event_name
            == "authorization_failure"
        ]

        for authz_failure in authorization_failures:

            failure_user = user_name(authz_failure)

            prior_success = any(
                e.event_name
                == "authentication_success"
                and user_name(e) == failure_user
                and 0
                <= (
                    event_time(authz_failure)
                    - event_time(e)
                ).total_seconds()
                <= WINDOW_SECONDS
                for e in events
            )

            if prior_success:

                risk += 20

                reasons.append(
                    "Authenticated user attempted "
                    "a restricted action"
                )

                break

        # ---------------------------------------------------------
        # RULE 4
        # Multiple telemetry sources observed on one host.
        # ---------------------------------------------------------

        sources = sorted({
            e.source
            for e in events
        })

        if len(sources) >= 2:

            risk += 10

            reasons.append(
                "Related security activity observed "
                "across multiple telemetry sources"
            )

        risk = min(risk, 100)

        # ---------------------------------------------------------
        # Determine title.
        # ---------------------------------------------------------

        has_authz_failure = any(
            e.event_name == "authorization_failure"
            for e in events
        )

        has_repeated_failures = len(
            [
                e for e in events
                if e.event_name in {
                    "authentication_failure",
                    "logon_failure",
                }
            ]
        ) >= 2

        has_success = any(
            e.event_name
            == "authentication_success"
            for e in events
        )

        if (
            has_repeated_failures
            and has_success
            and has_authz_failure
        ):
            title = (
                "Suspicious authentication and "
                "privileged-access sequence"
            )

        elif has_repeated_failures and has_success:
            title = (
                "Repeated authentication failures "
                "followed by successful access"
            )

        elif has_authz_failure:
            title = (
                "Unauthorized privileged-access attempt"
            )

        else:
            title = "Authentication activity requires review"

        severity = (
            "critical"
            if risk >= 80
            else "high"
            if risk >= 60
            else "medium"
        )

        users_seen = sorted({
            user_name(e)
            for e in events
            if user_name(e) != "unknown-user"
        })

        evidence = []

        for event in events:

            evidence.append({
                "event_id": event.id,
                "timestamp": event.timestamp,
                "source": event.source,
                "event_name": event.event_name,
                "user": user_name(event),
                "host": host_name(event),
                "severity": (
                    "high"
                    if event.event_name
                    in {
                        "authorization_failure",
                        "restricted_resource_access",
                        "logon_failure",
                    }
                    else "medium"
                    if event.event_name
                    == "authentication_failure"
                    else "low"
                ),
            })

        evidence.sort(
            key=lambda item: (
                0
                if item["event_name"]
                in {
                    "authorization_failure",
                    "logon_failure",
                }
                else 1,
                item["timestamp"] or "",
            )
        )

        if has_authz_failure:
            next_check = (
                "Verify whether the privileged access attempt "
                "was expected and review the affected account."
            )
        elif has_repeated_failures:
            next_check = (
                "Review recent authentication activity "
                "for the affected account and source host."
            )
        else:
            next_check = (
                "Review the related telemetry events "
                "for additional context."
            )

        return {
            "id": incident_id,
            "title": title,
            "status": "open",
            "risk": risk,
            "severity": severity,
            "host": host,
            "users": users_seen,
            "sources": sources,
            "first_seen": (
                events[0].timestamp
                if events else None
            ),
            "last_seen": (
                events[-1].timestamp
                if events else None
            ),
            "event_count": len(events),
            "why_it_matters": (
                reasons
                if reasons
                else [
                    "Related security-relevant "
                    "events were observed."
                ]
            ),
            "next_check": next_check,
            "evidence": evidence,
        }

    def get_incidents(self) -> List[dict]:

        return sorted(
            self.incidents.values(),
            key=lambda incident: (
                -incident["risk"],
                incident["last_seen"] or "",
            ),
        )

    def get_incident(
        self,
        incident_id: str,
    ) -> Optional[dict]:

        return self.incidents.get(incident_id)


intelligence = IntelligenceEngine()
