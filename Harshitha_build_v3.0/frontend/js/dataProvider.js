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
    getIncident
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

    return getIncident(incidentId);
}