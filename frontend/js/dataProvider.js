import {
    DATA_MODE
} from "./config.js";

import {
    MOCK_INCIDENTS,
    MOCK_EVENTS
} from "./mockData.js";

import {
    getHealth,
    getEvents,
    getIncidents,
    getIncident,
    analyzeIncident,
    getIncidentGraph,
    investigateIncident
} from "./api.js";


export async function loadHealth() {

    if (DATA_MODE === "mock") {
        return {
            status: "ok",
            service: "sentra-backend",
            events_received: MOCK_EVENTS.length,
            incidents: MOCK_INCIDENTS.length
        };
    }

    return getHealth();
}


export async function loadEvents() {

    if (DATA_MODE === "mock") {
        return {
            count: MOCK_EVENTS.length,
            events: MOCK_EVENTS
        };
    }

    return getEvents();
}


export async function loadIncidents() {

    if (DATA_MODE === "mock") {
        return {
            count: MOCK_INCIDENTS.length,
            incidents: MOCK_INCIDENTS
        };
    }

    return getIncidents();
}


export async function loadIncident(
    incidentId
) {

    if (DATA_MODE === "mock") {

        const incident =
            MOCK_INCIDENTS.find(
                item =>
                    item.id === incidentId
            );

        if (!incident) {
            throw new Error(
                `Mock incident not found: ${incidentId}`
            );
        }

        return incident;
    }

    const response = await getIncident(incidentId);

    // Backend GET /incidents/{id} returns:
    // { found, incident, ai_analysis }
    // Normalize that contract for the UI.
    const incident = response?.incident
        ? { ...response.incident }
        : { ...response };

    if (Object.prototype.hasOwnProperty.call(response || {}, "ai_analysis")) {
        incident.ai_analysis = response.ai_analysis;
    }

    return incident;
}


export async function analyzeIncidentForIncident(
    incidentId
) {
    if (DATA_MODE === "mock") {
        return {
            incident_id: incidentId,
            analysis: null
        };
    }

    return analyzeIncident(incidentId);
}

export async function loadIncidentGraph(
    incidentId
) {
    if (DATA_MODE === "mock") {
        return {
            incident_id: incidentId,
            graph: {
                nodes: [],
                edges: []
            }
        };
    }

    return getIncidentGraph(
        incidentId
    );
}


export async function investigateIncidentForIncident(
    incidentId
) {
    if (DATA_MODE === "mock") {
        return {
            incident_id: incidentId,
            investigation: {
                incident_id: incidentId,
                checked_at: new Date().toISOString(),
                checks: {
                    recent_authentication_activity: {
                        status: "none_observed",
                        event_count: 0
                    },
                    cross_source_activity: {
                        status: "not_observed",
                        sources: [],
                        source_count: 0
                    },
                    restricted_resource_activity: {
                        status: "none_observed",
                        event_count: 0
                    }
                }
            }
        };
    }

    return investigateIncident(
        incidentId
    );
}
