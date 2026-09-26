from datetime import datetime, timezone
from math import sqrt
from typing import Any, Dict, List, Optional

from schemas import SentraEvent


MAX_HISTORY = 1000
HISTORY_SECONDS = 86400


def parse_time(value: Optional[str]) -> datetime:

    if not value:
        return datetime.now(timezone.utc)

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        return datetime.now(timezone.utc)


def event_time(
    event: SentraEvent,
) -> datetime:
    return parse_time(event.timestamp)


def user_name(
    event: SentraEvent,
) -> str:
    return (
        event.user.name
        or event.user.target_name
        or "unknown-user"
    ).strip().lower()


def host_name(
    event: SentraEvent,
) -> str:
    return (
        event.host.name
        or event.host.workstation
        or "unknown-host"
    ).strip().lower()


def action_name(
    event: SentraEvent,
) -> str:
    return str(
        event.event_name or "unknown"
    ).strip().lower()


def application_name(
    event: SentraEvent,
) -> str:

    raw = event.raw or {}

    for key in (
        "application",
        "app",
        "Application",
    ):
        value = raw.get(key)

        if value not in {
            None,
            "",
            "-",
        }:
            return str(value).strip().lower()

    return "unknown-application"


def resource_name(
    event: SentraEvent,
) -> str:

    raw = event.raw or {}

    for key in (
        "resource",
        "endpoint",
        "Resource",
        "Endpoint",
    ):
        value = raw.get(key)

        if value not in {
            None,
            "",
            "-",
        }:
            return str(value).strip().lower()

    return "unknown-resource"


def relationship_key(
    event: SentraEvent,
) -> str:

    return (
        f"{user_name(event)}|"
        f"{host_name(event)}|"
        f"{action_name(event)}|"
        f"{application_name(event)}|"
        f"{resource_name(event)}"
    )


def cosine_similarity(
    current: List[float],
    baseline: List[float],
) -> float:

    if not current or not baseline:
        return 0.0

    dot = sum(
        a * b
        for a, b in zip(
            current,
            baseline,
        )
    )

    current_norm = sqrt(
        sum(
            value * value
            for value in current
        )
    )

    baseline_norm = sqrt(
        sum(
            value * value
            for value in baseline
        )
    )

    if current_norm == 0 or baseline_norm == 0:
        return 0.0

    return max(
        0.0,
        min(
            1.0,
            dot / (
                current_norm
                * baseline_norm
            ),
        ),
    )


class ContextIntelligence:

    def __init__(self):

        # Independent contextual history.
        #
        # This intentionally remains separate from
        # the deterministic risk engine.
        self.history: List[SentraEvent] = []

    def observe(
        self,
        event: SentraEvent,
    ) -> None:

        self.history.append(
            event
        )

        if len(self.history) > MAX_HISTORY:

            self.history.pop(
                0
            )

    def _features(
        self,
        events: List[SentraEvent],
    ) -> List[float]:

        if not events:
            return [0.0] * 6

        total = len(events)

        failures = sum(
            1
            for event in events
            if event.event_name in {
                "authentication_failure",
                "logon_failure",
            }
        )

        privileged = sum(
            1
            for event in events
            if event.event_name in {
                "authorization_failure",
                "restricted_resource_access",
            }
        )

        source_count = len({
            event.source
            for event in events
        })

        action_count = len({
            action_name(event)
            for event in events
        })

        application_count = len({
            application_name(event)
            for event in events
        })

        resource_count = len({
            resource_name(event)
            for event in events
        })

        return [
            min(
                failures / max(total, 1),
                1.0,
            ),
            min(
                privileged / max(total, 1),
                1.0,
            ),
            min(
                source_count / 2,
                1.0,
            ),
            min(
                action_count / 5,
                1.0,
            ),
            min(
                application_count / 5,
                1.0,
            ),
            min(
                resource_count / 5,
                1.0,
            ),
        ]

    def analyze_incident(
        self,
        incident: Dict[str, Any],
        all_events: List[SentraEvent],
    ) -> Dict[str, Any]:

        evidence_ids = {
            item.get("event_id")
            for item in incident.get(
                "evidence",
                [],
            )
        }

        incident_events = [
            event
            for event in all_events
            if event.id in evidence_ids
        ]

        if not incident_events:

            return {
                "context_score": None,
                "context_label": "unknown",
                "sample_size": 0,
                "relationship_familiarity": "unknown",
                "signals": [
                    "No incident evidence available"
                ],
                "state_vector": [],
                "baseline_vector": [],
            }

        incident_events.sort(
            key=event_time
        )

        incident_start = event_time(
            incident_events[0]
        )

        incident_user = user_name(
            incident_events[0]
        )

        incident_host = host_name(
            incident_events[0]
        )

        # Historical context must occur BEFORE
        # the incident began. This prevents leakage.
        historical = []

        for event in self.history:

            if event.id in evidence_ids:
                continue

            if user_name(event) != incident_user:
                continue

            if host_name(event) != incident_host:
                continue

            event_timestamp = event_time(
                event
            )

            if event_timestamp >= incident_start:
                continue

            age = (
                incident_start
                - event_timestamp
            ).total_seconds()

            if age < 0 or age > HISTORY_SECONDS:
                continue

            historical.append(
                event
            )

        historical.sort(
            key=event_time
        )

        current_vector = self._features(
            incident_events
        )

        if not historical:

            return {
                "context_score": None,
                "context_label": "unknown",
                "sample_size": 0,
                "relationship_familiarity": "unknown",
                "signals": [
                    "No prior activity for this user-host pair"
                ],
                "state_vector": [
                    round(
                        value,
                        3,
                    )
                    for value in current_vector
                ],
                "baseline_vector": [],
            }

        baseline_vector = self._features(
            historical
        )

        similarity = cosine_similarity(
            current_vector,
            baseline_vector,
        )

        historical_relationships = {
            relationship_key(event)
            for event in historical
        }

        current_relationships = {
            relationship_key(event)
            for event in incident_events
        }

        first_seen_relationships = (
            current_relationships
            - historical_relationships
        )

        failures = sum(
            1
            for event in incident_events
            if event.event_name in {
                "authentication_failure",
                "logon_failure",
            }
        )

        privileged = sum(
            1
            for event in incident_events
            if event.event_name in {
                "authorization_failure",
                "restricted_resource_access",
            }
        )

        historical_privileged = sum(
            1
            for event in historical
            if event.event_name in {
                "authorization_failure",
                "restricted_resource_access",
            }
        )

        sources = {
            event.source
            for event in incident_events
        }

        signals = []

        if first_seen_relationships:

            signals.append(
                f"{len(first_seen_relationships)} "
                "first-seen relationship(s)"
            )

        else:

            signals.append(
                "Incident relationships were previously observed"
            )

        if historical_privileged == 0 and privileged > 0:

            signals.append(
                "Restricted activity was not present "
                "in the observed baseline"
            )

        if failures >= 2:

            signals.append(
                "Repeated authentication activity"
            )

        if len(sources) >= 2:

            signals.append(
                "Activity spans multiple telemetry sources"
            )

        if similarity >= 0.85:

            label = "expected"

        elif similarity >= 0.60:

            label = "mixed"

        else:

            label = "atypical"

        # First-seen privileged relationships are a
        # strong contextual signal even when the overall
        # feature-vector similarity is moderate.
        if (
            first_seen_relationships
            and privileged > 0
        ):

            label = "atypical"

        relationship_familiarity = (
            "first-seen"
            if first_seen_relationships
            else "known"
        )

        return {
            "context_score": round(
                similarity,
                3,
            ),
            "context_label": label,
            "sample_size": len(historical),
            "relationship_familiarity": (
                relationship_familiarity
            ),
            "signals": signals,
            "state_vector": [
                round(
                    value,
                    3,
                )
                for value in current_vector
            ],
            "baseline_vector": [
                round(
                    value,
                    3,
                )
                for value in baseline_vector
            ],
        }


context_intelligence = ContextIntelligence()