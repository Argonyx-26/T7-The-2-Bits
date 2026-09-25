import {
    DATA_MODE,
    WS_URL
} from "./config.js";

import {
    loadEvents,
    loadIncidents,
    loadIncident
} from "./dataProvider.js";


let incidents = [];
let events = [];

let selectedIncidentId = null;
let socket = null;


const $ = id =>
    document.getElementById(id);


/* =========================================================
   STATUS
========================================================= */

function setStatus(
    online,
    label
) {
    const statusDot =
        $("statusDot");

    const statusText =
        $("statusText");

    if (statusDot) {
        statusDot.classList.toggle(
            "live",
            online
        );
    }

    if (statusText) {
        statusText.textContent =
            label;
    }
}


/* =========================================================
   METRICS
========================================================= */

function renderMetrics() {

    const critical =
        incidents.filter(
            item =>
                String(item.severity).toLowerCase() ===
                "critical"
        ).length;

    const high =
        incidents.filter(
            item =>
                String(item.severity).toLowerCase() ===
                "high"
        ).length;

    const medium =
        incidents.filter(
            item =>
                String(item.severity).toLowerCase() ===
                "medium"
        ).length;

    const criticalElement =
        $("criticalCount");

    const highElement =
        $("highCount");

    const mediumElement =
        $("mediumCount");

    const eventElement =
        $("eventCount");

    if (criticalElement) {
        criticalElement.textContent =
            critical;
    }

    if (highElement) {
        highElement.textContent =
            high;
    }

    if (mediumElement) {
        mediumElement.textContent =
            medium;
    }

    if (eventElement) {
        eventElement.textContent =
            events.length;
    }
}


/* =========================================================
   INCIDENT QUEUE
========================================================= */

function renderQueue() {

    const queue =
        $("incidentQueue");

    if (!queue) {
        return;
    }

    queue.innerHTML =
        incidents.map(
            incident => `

                <button
                    type="button"
                    class="
                        incident-card
                        ${
                            incident.id ===
                            selectedIncidentId
                                ? "active"
                                : ""
                        }
                    "
                    data-id="${escapeHtml(
                        incident.id
                    )}"
                >

                    <div class="incident-top">

                        <span
                            class="
                                severity
                                severity-${escapeHtml(
                                    String(
                                        incident.severity ||
                                        "medium"
                                    ).toLowerCase()
                                )}
                            "
                        >
                            <span class="severity-dot"></span>

                            ${escapeHtml(
                                String(
                                    incident.severity ||
                                    "unknown"
                                )
                            )}
                        </span>

                        <span class="risk-pill">
                            ${escapeHtml(
                                String(
                                    incident.risk ??
                                    "—"
                                )
                            )}
                        </span>

                    </div>


                    <div class="incident-title">
                        ${escapeHtml(
                            incident.title ||
                            "Untitled incident"
                        )}
                    </div>


                    <div class="incident-meta">

                        <span>
                            ${escapeHtml(
                                incident.host ||
                                "Unknown host"
                            )}
                        </span>

                        <span>
                            ${escapeHtml(
                                String(
                                    incident.event_count ??
                                    0
                                )
                            )}
                            events
                        </span>

                    </div>

                </button>
            `
        ).join("");


    queue
        .querySelectorAll(
            ".incident-card"
        )
        .forEach(button => {

            button.addEventListener(
                "click",
                async () => {

                    selectedIncidentId =
                        button.dataset.id;

                    renderQueue();

                    await renderIncident();

                }
            );

        });
}


/* =========================================================
   INCIDENT DETAIL
========================================================= */

async function renderIncident() {

    if (!selectedIncidentId) {
        return;
    }

    let incident;

    try {
        incident =
            await loadIncident(
                selectedIncidentId
            );
    }

    catch (error) {

        console.error(
            "Unable to load incident:",
            error
        );

        return;
    }


    const title =
        $("detailTitle");

    const subtitle =
        $("detailSubtitle");

    const risk =
        $("detailRisk");

    const summary =
        $("detailSummary");

    if (title) {
        title.textContent =
            incident.title ||
            "Untitled incident";
    }

    if (subtitle) {

        const userText =
            Array.isArray(incident.users)
                ? incident.users.join(", ")
                : "unknown user";

        const sourceText =
            Array.isArray(incident.sources)
                ? incident.sources.join(", ")
                : "unknown source";

        subtitle.textContent =
            `Suspicious activity involving ${userText} `
            + `on ${incident.host || "unknown host"} `
            + `from ${sourceText}.`;
    }

    if (risk) {
        risk.textContent =
            incident.risk ??
            "—";
    }

    if (summary) {

        const firstSeen =
            incident.first_seen ||
            "unknown";

        const lastSeen =
            incident.last_seen ||
            "unknown";

        summary.textContent =
            `Observed from ${firstSeen} to ${lastSeen} `
            + `with ${incident.event_count ?? 0} `
            + `supporting event(s).`;
    }


    renderEvidence(
        incident
    );

    renderWhyFlagged(
        incident
    );

    renderNextCheck(
        incident
    );
}


/* =========================================================
   EVIDENCE / TIMELINE
========================================================= */

function renderEvidence(
    incident
) {

    const timeline =
        $("timeline");

    const chips =
        $("correlationChips");

    if (!timeline) {
        return;
    }


    const evidence =
        Array.isArray(
            incident.evidence
        )
            ? incident.evidence
            : [];


    if (evidence.length === 0) {

        timeline.innerHTML = `
            <div class="empty-telemetry">
                No evidence available.
            </div>
        `;

    }

    else {

        timeline.innerHTML =
            evidence.map(
                item => {

                    const time =
                        formatTimestamp(
                            item.timestamp
                        );

                    return `

                        <div class="evidence-item">

                            <div class="evidence-time">
                                ${escapeHtml(time)}
                            </div>

                            <div class="evidence-event">
                                ${escapeHtml(
                                    item.event_name ||
                                    "security event"
                                )}
                            </div>

                            <div class="evidence-sub">
                                User:
                                ${escapeHtml(
                                    item.user ||
                                    "unknown"
                                )}
                                · Host:
                                ${escapeHtml(
                                    item.host ||
                                    "unknown"
                                )}
                                · Source:
                                ${escapeHtml(
                                    item.source ||
                                    "unknown"
                                )}
                            </div>

                        </div>
                    `;
                }
            ).join("");

    }


    if (chips) {

        const values = [
            ...(incident.sources || []),
            ...(incident.users || [])
        ];

        chips.innerHTML =
            values.map(
                value =>
                    `<span class="chip">
                        ${escapeHtml(
                            String(value)
                        )}
                    </span>`
            ).join("");

    }
}


/* =========================================================
   WHY FLAGGED
========================================================= */

function renderWhyFlagged(
    incident
) {

    const container =
        $("riskFactors");

    if (!container) {
        return;
    }

    const reasons =
        Array.isArray(
            incident.why_it_matters
        )
            ? incident.why_it_matters
            : [];


    if (reasons.length === 0) {

        container.innerHTML = `
            <div class="section-description">
                No explanation is available yet.
            </div>
        `;

        return;
    }


    container.innerHTML =
        reasons.map(
            reason => `

                <div class="factor">

                    <div>

                        <div class="factor-name">
                            ${escapeHtml(
                                reason
                            )}
                        </div>

                    </div>

                </div>
            `
        ).join("");
}


/* =========================================================
   NEXT CHECK
========================================================= */

function renderNextCheck(
    incident
) {

    const container =
        $("nextChecks");

    if (!container) {
        return;
    }

    const nextCheck =
        incident.next_check ||
        "No next investigation step available.";


    container.innerHTML = `

        <div class="next-check">

            <span class="step-index">
                1
            </span>

            <span>
                ${escapeHtml(
                    nextCheck
                )}
            </span>

        </div>

    `;
}


/* =========================================================
   TELEMETRY
========================================================= */

function renderTelemetry() {

    const list =
        $("telemetryList");

    const liveCount =
        $("liveCount");

    if (!list) {
        return;
    }


    if (events.length === 0) {

        list.innerHTML = `
            <div class="empty-telemetry">
                No mock telemetry available.
            </div>
        `;

    }

    else {

        list.innerHTML =
            events.map(
                event => `

                    <div class="telemetry-row">

                        <span
                            class="telemetry-time"
                        >
                            ${escapeHtml(
                                formatTimestamp(
                                    event.timestamp
                                )
                            )}
                        </span>


                        <span
                            class="telemetry-source"
                        >
                            ${escapeHtml(
                                event.source ||
                                "unknown"
                            )}
                        </span>


                        <span
                            class="telemetry-event"
                        >
                            ${escapeHtml(
                                event.event_name ||
                                "security event"
                            )}
                        </span>


                        <span
                            class="telemetry-id"
                        >
                            ${escapeHtml(
                                event.event_id ||
                                "—"
                            )}
                        </span>

                    </div>

                `
            ).join("");

    }


    if (liveCount) {

        liveCount.textContent =
            DATA_MODE === "mock"
                ? `${events.length} mock event(s)`
                : `${events.length} event(s)`;

    }
}


/* =========================================================
   WEBSOCKET
========================================================= */

function connectWebSocket() {

    if (DATA_MODE === "mock") {

        setStatus(
            false,
            "Demo mode · mock incident data"
        );

        return;
    }


    try {

        socket =
            new WebSocket(
                WS_URL
            );


        socket.onopen =
            () => {

                setStatus(
                    true,
                    "System live · receiving telemetry"
                );

            };


        socket.onmessage =
            message => {

                try {

                    const event =
                        JSON.parse(
                            message.data
                        );

                    events.unshift(
                        event
                    );

                    renderMetrics();

                    renderTelemetry();

                }

                catch (error) {

                    console.error(
                        "Invalid WebSocket event:",
                        error
                    );

                }

            };


        socket.onerror =
            () => {

                setStatus(
                    false,
                    "Backend unavailable"
                );

            };


        socket.onclose =
            () => {

                setStatus(
                    false,
                    "Telemetry disconnected · retrying…"
                );

                window.setTimeout(
                    connectWebSocket,
                    2500
                );

            };

    }

    catch {

        setStatus(
            false,
            "Backend unavailable"
        );

    }
}


/* =========================================================
   INITIALIZE
========================================================= */

async function initialize() {

    try {

        const [
            incidentResponse,
            eventResponse
        ] =
            await Promise.all([
                loadIncidents(),
                loadEvents()
            ]);


        incidents =
            Array.isArray(
                incidentResponse.incidents
            )
                ? incidentResponse.incidents
                : [];


        events =
            Array.isArray(
                eventResponse.events
            )
                ? eventResponse.events
                : [];


        selectedIncidentId =
            incidents.length > 0
                ? incidents[0].id
                : null;


        renderMetrics();

        renderQueue();

        renderTelemetry();


        if (selectedIncidentId) {
            await renderIncident();
        }


        connectWebSocket();

    }

    catch (error) {

        console.error(
            "SENTRA frontend initialization failed:",
            error
        );

        incidents = [];
        events = [];

        renderMetrics();
        renderQueue();
        renderTelemetry();

        setStatus(
            false,
            "Demo data unavailable"
        );

    }

}


/* =========================================================
   UTILITIES
========================================================= */

function formatTimestamp(
    timestamp
) {

    if (!timestamp) {
        return "—";
    }

    const date =
        new Date(
            timestamp
        );

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(
            timestamp
        );
    }

    return date.toLocaleString(
        [],
        {
            hour12: false
        }
    );
}


function escapeHtml(
    value
) {

    return String(
        value
    ).replace(
        /[&<>'"]/g,
        char => ({

            "&":
                "&amp;",

            "<":
                "&lt;",

            ">":
                "&gt;",

            "'":
                "&#39;",

            '"':
                "&quot;"

        }[char])
    );
}


initialize();