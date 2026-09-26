from datetime import datetime, timezone
from typing import Dict, List, Optional

from schemas import SentraEvent


WINDOW_SECONDS = 300
AUTH_SEQUENCE_SECONDS = 120
CROSS_SOURCE_SECONDS = 120

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


def user_name(event: SentraEvent) -> str:
    return (
        event.user.name
        or event.user.target_name
        or "unknown-user"
    )


def host_name(event: SentraEvent) -> str:
    return (
        event.host.name
        or event.host.workstation
        or "unknown-host"
    )


def source_ip(event: SentraEvent) -> Optional[str]:
    value = event.network.source_ip

    if value in {None, "", "-"}:
        return None

    return value


def is_relevant(event: SentraEvent) -> bool:

    if event.source == "internal_app":
        return event.event_name in {
            "authentication_failure",
            "authentication_success",
            "api_request",
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
        "authentication_failure": 5,
        "authorization_failure": 0,
        "restricted_resource_access": 15,
        "explicit_credentials": 5,
        "logon_failure": 10,
        "authentication_success": 0,
        "api_request": 0,
    }

    return weights.get(event.event_name, 0)


def same_entity(
    first: SentraEvent,
    second: SentraEvent,
) -> bool:

    first_user = user_name(first).lower()
    second_user = user_name(second).lower()

    if (
        first_user != "unknown-user"
        and second_user != "unknown-user"
        and first_user == second_user
    ):
        return True

    first_ip = source_ip(first)
    second_ip = source_ip(second)

    if (
        first_ip
        and second_ip
        and first_ip == second_ip
    ):
        return True

    return False


def same_host(
    first: SentraEvent,
    second: SentraEvent,
) -> bool:

    return (
        host_name(first).lower()
        == host_name(second).lower()
    )


def close_in_time(
    first: SentraEvent,
    second: SentraEvent,
    seconds: int,
) -> bool:

    delta = abs(
        (
            event_time(first)
            - event_time(second)
        ).total_seconds()
    )

    return delta <= seconds


class IntelligenceEngine:

    def __init__(self):

        self.recent_events: List[SentraEvent] = []

        self.incidents: Dict[str, dict] = {}

        self.incident_context: Dict[str, dict] = {}

    def add_event(
        self,
        event: SentraEvent,
    ) -> Optional[dict]:

        self.recent_events.append(event)

        if len(self.recent_events) > MAX_EVENTS:
            self.recent_events.pop(0)

        if not is_relevant(event):
            return None

        incident_id = self._find_or_create_incident_id(
            event
        )

        context = self.incident_context.get(
            incident_id
        )

        if not context:

            context = {
                "host": host_name(event),
                "user": user_name(event),
            }

            self.incident_context[
                incident_id
            ] = context

        incident = self._recompute_incident(
            incident_id=incident_id,
            host=context["host"],
            user=context["user"],
        )

        if incident["risk"] >= INCIDENT_THRESHOLD:

            self.incidents[incident_id] = incident

            if len(self.incidents) > MAX_INCIDENTS:

                oldest_id = next(
                    iter(self.incidents)
                )

                self.incidents.pop(
                    oldest_id,
                    None,
                )

                self.incident_context.pop(
                    oldest_id,
                    None,
                )

            print(
                "[INTELLIGENCE] "
                f"incident={incident['id']} "
                f"risk={incident['risk']} "
                f"sources={','.join(incident['sources'])} "
                f"title={incident['title']}"
            )

            return incident

        return None

    def _find_or_create_incident_id(
        self,
        incoming: SentraEvent,
    ) -> str:

        incoming_host = host_name(
            incoming
        ).lower()

        incoming_user = user_name(
            incoming
        ).lower()

        # ---------------------------------------------------------
        # 1. Existing incident
        # ---------------------------------------------------------

        for incident_id, incident in self.incidents.items():

            incident_host = (
                incident.get("host")
                or ""
            ).lower()

            incident_users = {
                str(user).lower()
                for user in incident.get(
                    "users",
                    []
                )
            }

            if incident_host != incoming_host:
                continue

            if incoming_user not in incident_users:
                continue

            last_seen_value = incident.get(
                "last_seen"
            )

            if not last_seen_value:
                continue

            last_seen = parse_time(
                last_seen_value
            )

            if abs(
                (
                    event_time(incoming)
                    - last_seen
                ).total_seconds()
            ) <= CROSS_SOURCE_SECONDS:

                return incident_id

        # ---------------------------------------------------------
        # 2. Existing incident context that has not yet crossed
        #    the risk threshold.
        # ---------------------------------------------------------

        for incident_id, context in self.incident_context.items():

            context_host = (
                context.get("host")
                or ""
            ).lower()

            context_user = (
                context.get("user")
                or ""
            ).lower()

            if context_host != incoming_host:
                continue

            if context_user != incoming_user:
                continue

            context_events = [
                event
                for event in self.recent_events
                if is_relevant(event)
                and host_name(event).lower()
                == incoming_host
                and user_name(event).lower()
                == incoming_user
                and close_in_time(
                    event,
                    incoming,
                    CROSS_SOURCE_SECONDS,
                )
            ]

            if context_events:
                return incident_id

        # ---------------------------------------------------------
        # 3. Find a recent related event.
        # ---------------------------------------------------------

        candidates = []

        for event in self.recent_events:

            if event.id == incoming.id:
                continue

            if not is_relevant(event):
                continue

            if not same_host(
                event,
                incoming,
            ):
                continue

            if not same_entity(
                event,
                incoming,
            ):
                continue

            if not close_in_time(
                event,
                incoming,
                CROSS_SOURCE_SECONDS,
            ):
                continue

            candidates.append(event)

        if candidates:

            candidates.sort(
                key=event_time
            )

            anchor = candidates[0]

            incident_id = self._incident_id(
                host_name(anchor),
                user_name(anchor),
            )

            self.incident_context[
                incident_id
            ] = {
                "host": host_name(anchor),
                "user": user_name(anchor),
            }

            return incident_id

        # ---------------------------------------------------------
        # 4. No relationship: create a new identity.
        # ---------------------------------------------------------

        incident_id = self._incident_id(
            host_name(incoming),
            user_name(incoming),
        )

        self.incident_context[
            incident_id
        ] = {
            "host": host_name(incoming),
            "user": user_name(incoming),
        }

        return incident_id

    def _incident_id(
        self,
        host: str,
        user: str,
    ) -> str:

        safe_host = (
            host
            .strip()
            .lower()
            .replace(" ", "-")
            .replace("\\", "-")
            .replace("/", "-")
        )

        safe_user = (
            user
            .strip()
            .lower()
            .replace(" ", "-")
            .replace("\\", "-")
            .replace("/", "-")
        )

        return (
            f"incident-{safe_host}-{safe_user}"
        )

    def _events_for_identity(
        self,
        host: str,
        user: str,
    ) -> List[SentraEvent]:

        now = datetime.now(timezone.utc)

        matched = []

        for event in self.recent_events:

            if not is_relevant(event):
                continue

            if (
                host_name(event).lower()
                != host.lower()
            ):
                continue

            if (
                user_name(event).lower()
                != user.lower()
            ):
                continue

            age = (
                now - event_time(event)
            ).total_seconds()

            if (
                -5
                <= age
                <= WINDOW_SECONDS
            ):
                matched.append(event)

        matched.sort(
            key=event_time
        )

        return matched

    def _recompute_incident(
        self,
        incident_id: str,
        host: str,
        user: str,
    ) -> dict:

        events = sorted(
            self._events_for_identity(
                host,
                user,
            ),
            key=event_time,
        )

        risk = 0

        risk_factors = []

        # ---------------------------------------------------------
        # BASE EVENT WEIGHTS
        # ---------------------------------------------------------

        event_totals = {}

        for event in events:

            weight = base_weight(event)

            if weight <= 0:
                continue

            event_totals[event.event_name] = (
                event_totals.get(
                    event.event_name,
                    0,
                )
                + weight
            )

            risk += weight

        event_labels = {
            "authentication_failure":
                "Application authentication failures",

            "authorization_failure":
                "Authorization failure",

            "restricted_resource_access":
                "Restricted resource access",

            "explicit_credentials":
                "Explicit credentials used",

            "logon_failure":
                "Windows failed logon",
        }

        for event_name, points in event_totals.items():

            risk_factors.append({
                "label": event_labels.get(
                    event_name,
                    event_name,
                ),
                "points": points,
            })

        # ---------------------------------------------------------
        # RULE 1:
        # Repeated authentication failures
        # ---------------------------------------------------------

        failures = [
            event
            for event in events
            if event.event_name in {
                "authentication_failure",
                "logon_failure",
            }
        ]

        repeated_failures = False

        if len(failures) >= 2:

            first_failure = event_time(
                failures[0]
            )

            last_failure = event_time(
                failures[-1]
            )

            if (
                last_failure
                - first_failure
            ).total_seconds() <= AUTH_SEQUENCE_SECONDS:

                repeated_failures = True

                risk += 15

                risk_factors.append({
                    "label":
                        "Repeated authentication failures",
                    "points": 15,
                })

        # ---------------------------------------------------------
        # RULE 2:
        # Failure -> successful authentication
        # ---------------------------------------------------------

        failure_then_success = False

        successes = [
            event
            for event in events
            if event.event_name
            == "authentication_success"
        ]

        for failure in failures:

            for success in successes:

                if (
                    user_name(success).lower()
                    != user.lower()
                ):
                    continue

                delta = (
                    event_time(success)
                    - event_time(failure)
                ).total_seconds()

                if (
                    0
                    <= delta
                    <= AUTH_SEQUENCE_SECONDS
                ):

                    failure_then_success = True

                    break

            if failure_then_success:
                break

        if failure_then_success:

            risk += 15

            risk_factors.append({
                "label":
                    "Failure followed by successful authentication",
                "points": 15,
            })

        # ---------------------------------------------------------
        # RULE 3:
        # Authorization failure
        # ---------------------------------------------------------

        authorization_failures = [
            event
            for event in events
            if event.event_name
            == "authorization_failure"
        ]

        if authorization_failures:

            risk += 20

            risk_factors.append({
                "label":
                    "Authenticated user attempted a restricted action",
                "points": 20,
            })

        # ---------------------------------------------------------
        # RULE 4:
        # Restricted resource access
        # ---------------------------------------------------------

        restricted_access = [
            event
            for event in events
            if event.event_name
            == "restricted_resource_access"
        ]

        if restricted_access:

            risk += 15

            risk_factors.append({
                "label":
                    "Restricted resource accessed",
                "points": 15,
            })

        # ---------------------------------------------------------
        # RULE 5:
        # CROSS-SOURCE CORRELATION
        # ---------------------------------------------------------

        sources = sorted({
            event.source
            for event in events
        })

        cross_source_pairs = []

        if len(sources) >= 2:

            for index, first in enumerate(events):

                for second in events[index + 1:]:

                    if (
                        first.source
                        == second.source
                    ):
                        continue

                    if not same_host(
                        first,
                        second,
                    ):
                        continue

                    if not same_entity(
                        first,
                        second,
                    ):
                        continue

                    if not close_in_time(
                        first,
                        second,
                        CROSS_SOURCE_SECONDS,
                    ):
                        continue

                    cross_source_pairs.append(
                        (
                            first.id,
                            second.id,
                        )
                    )

            if cross_source_pairs:

                risk += 10

                risk_factors.append({
                    "label":
                        "Cross-source correlation",
                    "points": 10,
                })

        # ---------------------------------------------------------
        # Keep risk on a 0-100 scale.
        # ---------------------------------------------------------

        risk = min(
            risk,
            100,
        )

        # ---------------------------------------------------------
        # WHY IT MATTERS
        # ---------------------------------------------------------

        reasons = []

        if repeated_failures:

            reasons.append(
                "Repeated authentication "
                f"failures for {user}"
            )

        if failure_then_success:

            reasons.append(
                "Authentication failure followed "
                f"by successful authentication for {user}"
            )

        if authorization_failures:

            reasons.append(
                "Authenticated user attempted "
                "a restricted action"
            )

        if restricted_access:

            reasons.append(
                "Restricted resource was accessed"
            )

        if cross_source_pairs:

            reasons.append(
                "Related security activity observed "
                "across multiple telemetry sources"
            )

        # ---------------------------------------------------------
        # TITLE
        # ---------------------------------------------------------

        has_success = bool(
            successes
        )

        has_authorization_failure = bool(
            authorization_failures
        )

        if (
            repeated_failures
            and has_success
            and has_authorization_failure
            and cross_source_pairs
        ):

            title = (
                "Cross-source authentication "
                "and restricted-access sequence"
            )

        elif (
            repeated_failures
            and has_success
            and has_authorization_failure
        ):

            title = (
                "Authentication and restricted-access sequence"
            )

        elif (
            repeated_failures
            and has_success
        ):

            title = (
                "Repeated authentication failures "
                "followed by successful access"
            )

        elif has_authorization_failure:

            title = (
                "Unauthorized privileged-access attempt"
            )

        else:

            title = (
                "Authentication activity requires review"
            )

        # ---------------------------------------------------------
        # SEVERITY
        # ---------------------------------------------------------

        severity = (
            "critical"
            if risk >= 80
            else "high"
            if risk >= 60
            else "medium"
        )

        # ---------------------------------------------------------
        # USERS
        # ---------------------------------------------------------

        users_seen = sorted({
            user_name(event)
            for event in events
            if user_name(event)
            != "unknown-user"
        })

        if (
            user != "unknown-user"
            and user not in users_seen
        ):

            users_seen.append(user)

        users_seen = sorted(
            set(users_seen)
        )

        # ---------------------------------------------------------
        # EVIDENCE
        # ---------------------------------------------------------

        evidence = []

        for event in events:

            event_severity = "low"

            if event.event_name in {
                "authorization_failure",
                "restricted_resource_access",
                "logon_failure",
            }:

                event_severity = "high"

            elif event.event_name == "authentication_failure":

                event_severity = "medium"

            evidence.append({
                "event_id": event.id,
                "timestamp": event.timestamp,
                "source": event.source,
                "event_name": event.event_name,
                "user": user_name(event),
                "host": host_name(event),
                "severity": event_severity,
            })

        evidence.sort(
            key=lambda item: parse_time(
                item["timestamp"]
            )
        )

        # ---------------------------------------------------------
        # FIRST/LAST SEEN
        # ---------------------------------------------------------

        timestamps = [
            parse_time(event.timestamp)
            for event in events
            if event.timestamp
        ]

        if timestamps:

            first_seen = min(
                timestamps
            ).isoformat().replace(
                "+00:00",
                "Z",
            )

            last_seen = max(
                timestamps
            ).isoformat().replace(
                "+00:00",
                "Z",
            )

        else:

            first_seen = None
            last_seen = None

        # ---------------------------------------------------------
        # NEXT CHECK
        # ---------------------------------------------------------

        if has_authorization_failure:

            next_check = (
                "Verify whether the privileged access "
                "attempt was expected and review the affected account."
            )

        elif repeated_failures:

            next_check = (
                "Review recent authentication activity "
                "for the affected account and source host."
            )

        else:

            next_check = (
                "Review the related telemetry events "
                "for additional context."
            )

        # ---------------------------------------------------------
        # INCIDENT OBJECT
        # ---------------------------------------------------------

        return {
            "id": incident_id,
            "title": title,
            "status": "open",
            "risk": risk,
            "severity": severity,
            "host": host,
            "users": users_seen,
            "sources": sources,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_count": len(events),
            "why_it_matters": reasons or [
                "Related security-relevant "
                "events were observed."
            ],
            "risk_factors": risk_factors,
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

        return self.incidents.get(
            incident_id
        )


intelligence = IntelligenceEngine()






