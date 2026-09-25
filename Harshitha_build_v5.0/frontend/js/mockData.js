export const MOCK_INCIDENTS = [
    {
        id: "incident-vaishnav-g15",
        title: "Suspicious authentication and privileged-access sequence",
        status: "open",
        risk: 85,
        severity: "high",
        host: "Vaishnav-G15",
        users: ["analyst"],
        sources: ["internal_app"],
        first_seen: "2026-09-25T10:42:12",
        last_seen: "2026-09-25T10:42:16",
        event_count: 4,

        why_it_matters: [
            "Repeated authentication failures for analyst",
            "Authentication failure followed by successful authentication for analyst",
            "Authenticated user attempted a restricted action"
        ],

        next_check:
            "Verify whether the privileged access attempt was expected and review the affected account.",

        evidence: [
            {
                event_id: "internal-app-001",
                timestamp: "2026-09-25T10:42:12",
                source: "internal_app",
                event_name: "authentication_failure",
                user: "analyst",
                host: "Vaishnav-G15",
                severity: "high"
            },
            {
                event_id: "internal-app-002",
                timestamp: "2026-09-25T10:42:14",
                source: "internal_app",
                event_name: "authentication_failure",
                user: "analyst",
                host: "Vaishnav-G15",
                severity: "high"
            },
            {
                event_id: "internal-app-003",
                timestamp: "2026-09-25T10:42:15",
                source: "internal_app",
                event_name: "authentication_success",
                user: "analyst",
                host: "Vaishnav-G15",
                severity: "medium"
            },
            {
                event_id: "internal-app-004",
                timestamp: "2026-09-25T10:42:16",
                source: "internal_app",
                event_name: "authorization_failure",
                user: "analyst",
                host: "Vaishnav-G15",
                severity: "high"
            }
        ]
    }
];


export const MOCK_EVENTS = MOCK_INCIDENTS.flatMap(
    incident => incident.evidence
);