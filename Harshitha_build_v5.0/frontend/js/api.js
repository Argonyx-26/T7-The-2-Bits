import {
    API_BASE_URL
} from "./config.js";


async function request(
    path,
    options = {}
) {
    const response = await fetch(
        `${API_BASE_URL}${path}`,
        {
            ...options,
            headers: {
                "Content-Type": "application/json",
                ...(options.headers || {})
            }
        }
    );

    if (!response.ok) {
        throw new Error(
            `API request failed: ${response.status} ${response.statusText}`
        );
    }

    return response.json();
}


export async function getHealth() {
    return request("/health");
}


export async function getEvents() {
    return request("/events");
}


export async function getIncidents() {
    return request("/incidents");
}


export async function getIncident(
    incidentId
) {
    return request(
        `/incidents/${encodeURIComponent(incidentId)}`
    );
}


export async function analyzeIncident(
    incidentId
) {
    return request(
        `/incidents/${encodeURIComponent(incidentId)}/analyze`,
        {
            method: "POST"
        }
    );
}


export async function getIncidentGraph(
    incidentId
) {
    return request(
        `/incidents/${encodeURIComponent(incidentId)}/graph`
    );
}

export async function investigateIncident(
    incidentId
) {
    return request(
        `/incidents/${encodeURIComponent(
            incidentId
        )}/investigate`,
        {
            method: "POST"
        }
    );
}
