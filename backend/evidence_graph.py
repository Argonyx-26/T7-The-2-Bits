from typing import Dict, List


def build_evidence_graph(
    incident: dict,
) -> dict:

    nodes: Dict[str, dict] = {}
    edge_map: Dict[tuple, dict] = {}

    evidence = incident.get("evidence", [])

    incident_id = incident.get("id")

    if not incident_id:
        return {
            "nodes": [],
            "edges": [],
        }

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    def add_node(
        node_id: str,
        node_type: str,
        label: str,
    ) -> None:

        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label,
            }

    def add_edge(
        source: str,
        target: str,
        relationship: str,
        evidence_id: str,
    ) -> None:

        key = (
            source,
            target,
            relationship,
        )

        if key not in edge_map:
            edge_map[key] = {
                "source": source,
                "target": target,
                "relationship": relationship,
                "evidence_ids": [],
            }

        if evidence_id not in edge_map[key]["evidence_ids"]:
            edge_map[key]["evidence_ids"].append(
                evidence_id
            )

    # ---------------------------------------------------------
    # Incident node
    # ---------------------------------------------------------

    incident_node_id = f"incident:{incident_id}"

    add_node(
        incident_node_id,
        "incident",
        incident.get(
            "title",
            incident_id,
        ),
    )

    # ---------------------------------------------------------
    # Evidence-derived relationships
    # ---------------------------------------------------------

    for item in evidence:

        event_id = item.get("event_id")

        if not event_id:
            continue

        evidence_id = str(event_id)

        event_node_id = f"event:{evidence_id}"

        event_label = (
            item.get("event_name")
            or evidence_id
        )

        add_node(
            event_node_id,
            "event",
            event_label,
        )

        # incident -> event
        add_edge(
            incident_node_id,
            event_node_id,
            "contains_event",
            evidence_id,
        )

        # -----------------------------------------------------
        # User
        # -----------------------------------------------------

        user = item.get("user")

        if user:

            user_node_id = f"user:{user}"

            add_node(
                user_node_id,
                "user",
                user,
            )

            add_edge(
                user_node_id,
                event_node_id,
                "performed_event",
                evidence_id,
            )

        # -----------------------------------------------------
        # Host
        # -----------------------------------------------------

        host = item.get("host")

        if host:

            host_node_id = f"host:{host}"

            add_node(
                host_node_id,
                "host",
                host,
            )

            add_edge(
                host_node_id,
                event_node_id,
                "recorded_event",
                evidence_id,
            )

        # -----------------------------------------------------
        # Source
        # -----------------------------------------------------

        source = item.get("source")

        if source:

            source_node_id = f"source:{source}"

            add_node(
                source_node_id,
                "source",
                source,
            )

            add_edge(
                event_node_id,
                source_node_id,
                "came_from",
                evidence_id,
            )

        # -----------------------------------------------------
        # User -> Host
        # -----------------------------------------------------

        if user and host:

            add_edge(
                f"user:{user}",
                f"host:{host}",
                "associated_with",
                evidence_id,
            )

        # -----------------------------------------------------
        # Optional evidence fields
        #
        # These are supported only when the incident evidence
        # already contains them. Nothing is invented here.
        # -----------------------------------------------------

        application = item.get(
            "application"
        )

        if application:

            application_node_id = (
                f"application:{application}"
            )

            add_node(
                application_node_id,
                "application",
                application,
            )

            add_edge(
                event_node_id,
                application_node_id,
                "occurred_in",
                evidence_id,
            )

        resource = item.get(
            "resource"
        )

        if resource:

            resource_node_id = (
                f"resource:{resource}"
            )

            add_node(
                resource_node_id,
                "resource",
                resource,
            )

            add_edge(
                event_node_id,
                resource_node_id,
                "targeted",
                evidence_id,
            )

    return {
        "nodes": list(
            nodes.values()
        ),
        "edges": list(
            edge_map.values()
        ),
    }