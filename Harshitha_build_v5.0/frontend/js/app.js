// Source: uploaded app.js :contentReference[oaicite:0]{index=0}

import {
    DATA_MODE,
    WS_URL
} from "./config.js";

import {
    loadEvents,
    loadIncidents,
    loadIncident,
    loadIncidentGraph,
    analyzeIncidentForIncident,
    investigateIncidentForIncident
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
                String(
                    item.severity
                ).toLowerCase() ===
                "critical"
        ).length;


    const high =
        incidents.filter(
            item =>
                String(
                    item.severity
                ).toLowerCase() ===
                "high"
        ).length;


    const medium =
        incidents.filter(
            item =>
                String(
                    item.severity
                ).toLowerCase() ===
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

                            <span
                                class="severity-dot"
                            ></span>

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
        .forEach(
            button => {

                button.addEventListener(
                    "click",
                    async () => {

                        selectedIncidentId =
                            button.dataset.id;

                        renderQueue();

                        await renderIncident();
                    }
                );
            }
        );
}


async function refreshIncidents() {

    try {

        const response =
            await loadIncidents();


        incidents =
            Array.isArray(
                response.incidents
            )
                ? response.incidents
                : [];


        if (
            !incidents.some(
                incident =>
                    incident.id ===
                    selectedIncidentId
            )
        ) {

            selectedIncidentId =
                incidents.length > 0
                    ? incidents[0].id
                    : null;
        }


        renderMetrics();

        renderQueue();


        if (selectedIncidentId) {

            await renderIncident();
        }


    } catch (error) {

        console.error(
            "Unable to refresh incidents:",
            error
        );
    }
}


/* =========================================================
   INCIDENT DETAIL
========================================================= */

async function renderIncident() {

    if (!selectedIncidentId) {

        renderAIAnalysis(
            null
        );

        return;
    }


    let incident;


    try {

        incident =
            await loadIncident(
                selectedIncidentId
            );


    } catch (error) {

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
            Array.isArray(
                incident.users
            )
                ? incident.users.join(
                    ", "
                )
                : "unknown user";


        const sourceText =
            Array.isArray(
                incident.sources
            )
                ? incident.sources
                    .map(
                        formatSourceLabel
                    )
                    .join(", ")
                : "unknown source";


        subtitle.textContent =
            `Activity involving ${userText} on ` +
            `${incident.host || "unknown host"} ` +
            `across ${sourceText}.`;
    }


    if (risk) {

        risk.textContent =
            incident.risk ??
            "—";
    }


    if (summary) {

        summary.textContent =
            `Observed from ${formatTimestamp(
                incident.first_seen
            )} ` +
            `to ${formatTimestamp(
                incident.last_seen
            )} ` +
            `with ${incident.event_count ?? 0} ` +
            `supporting event(s).`;
    }


    renderEvidence(
    incident
);


const evidenceGraphLink =
    $("evidenceGraphLink");

if (evidenceGraphLink) {

    evidenceGraphLink.href =
        `./evidence-graph.html?incident_id=${encodeURIComponent(
            selectedIncidentId
        )}`;

    evidenceGraphLink.target =
        "_blank";
}


renderWhyFlagged(
    incident
);


    renderNextCheck(
        incident
    );


    renderAIAnalysis(
        incident.ai_analysis
    );
}


function formatSourceLabel(
    source
) {

    const labels = {

        windows_security:
            "Windows Security",

        internal_app:
            "Internal App"
    };


    return labels[source] ||
        String(
            source ||
            "unknown"
        );
}

/* =========================================================
   INVESTIGATION RUNNER
========================================================= */

async function runInvestigation() {

    if (!selectedIncidentId) {
        return;
    }


    const button =
        $("investigateButton");

    const result =
        $("investigationResult");


    if (!result) {
        return;
    }


    if (button) {
        button.disabled = true;
        button.textContent =
            "Investigating…";
    }


    result.innerHTML = `
        <div class="factor-evidence">
            Running deterministic investigation checks…
        </div>
    `;


    try {

        const response =
            await investigateIncidentForIncident(
                selectedIncidentId
            );


        const investigation =
            response?.investigation;


        const checks =
            investigation?.checks || {};


        const recentAuth =
            checks
                .recent_authentication_activity
                || {};


        const crossSource =
            checks
                .cross_source_activity
                || {};


        const restricted =
            checks
                .restricted_resource_activity
                || {};


        const recentAuthStatus =
            recentAuth.status === "observed"
                ? `Observed · ${recentAuth.event_count ?? 0} event(s)`
                : "None observed";


        const crossSourceStatus =
            crossSource.status === "observed"
                ? `Observed · ${crossSource.source_count ?? 0} source(s)`
                : "Not observed";


        const restrictedStatus =
            restricted.status === "observed"
                ? `Observed · ${restricted.event_count ?? 0} event(s)`
                : "None observed";


        const sources =
            Array.isArray(
                crossSource.sources
            )
                ? crossSource.sources
                    .map(formatSourceLabel)
                    .join(", ")
                : "—";


        const recentAuthEvidence =
            Array.isArray(
                recentAuth.evidence_ids
            )
                ? recentAuth.evidence_ids
                : [];


        const restrictedEvidence =
            Array.isArray(
                restricted.evidence_ids
            )
                ? restricted.evidence_ids
                : [];


        result.innerHTML = `

            <div class="factor">

                <div class="factor-name">
                    Recent authentication activity
                </div>

                <div class="factor-evidence">
                    ${escapeHtml(
                        recentAuthStatus
                    )}
                </div>

                ${
                    recentAuthEvidence.length
                        ? `
                            <div
                                class="factor-evidence"
                                style="margin-top: 6px;"
                            >
                                Evidence:
                                ${recentAuthEvidence
                                    .map(
                                        id => `
                                            <span
                                                style="
                                                    display: inline-block;
                                                    margin-right: 6px;
                                                    margin-top: 4px;
                                                    padding: 3px 6px;
                                                    border-radius: 6px;
                                                    border: 1px solid var(--line);
                                                "
                                            >
                                                ${escapeHtml(id)}
                                            </span>
                                        `
                                    )
                                    .join("")}
                            </div>
                        `
                        : ""
                }

            </div>


            <div
                class="factor"
                style="margin-top: 8px;"
            >

                <div class="factor-name">
                    Cross-source activity
                </div>

                <div class="factor-evidence">

                    ${escapeHtml(
                        crossSourceStatus
                    )}

                    ${
                        sources !== "—"
                            ? `
                                <br>
                                Sources:
                                ${escapeHtml(
                                    sources
                                )}
                            `
                            : ""
                    }

                </div>

            </div>


            <div
                class="factor"
                style="margin-top: 8px;"
            >

                <div class="factor-name">
                    Restricted-resource activity
                </div>

                <div class="factor-evidence">
                    ${escapeHtml(
                        restrictedStatus
                    )}
                </div>

                ${
                    restrictedEvidence.length
                        ? `
                            <div
                                class="factor-evidence"
                                style="margin-top: 6px;"
                            >
                                Evidence:
                                ${restrictedEvidence
                                    .map(
                                        id => `
                                            <span
                                                style="
                                                    display: inline-block;
                                                    margin-right: 6px;
                                                    margin-top: 4px;
                                                    padding: 3px 6px;
                                                    border-radius: 6px;
                                                    border: 1px solid var(--line);
                                                "
                                            >
                                                ${escapeHtml(id)}
                                            </span>
                                        `
                                    )
                                    .join("")}
                            </div>
                        `
                        : ""
                }

            </div>


            <div
                class="factor-evidence"
                style="margin-top: 10px;"
            >
                Checked at:
                ${escapeHtml(
                    formatTimestamp(
                        investigation?.checked_at
                    )
                )}
            </div>

        `;

    } catch (error) {

        console.error(
            "Investigation failed:",
            error
        );


        result.innerHTML = `
            <div class="factor-evidence">
                Investigation unavailable.
            </div>
        `;

    } finally {

        if (button) {

            button.disabled = false;

            button.textContent =
                "Run investigation";

        }

    }
}

/* =========================================================
   AI ANALYSIS
========================================================= */

async function runAIAnalysis() {

    if (!selectedIncidentId) {
        return;
    }


    const button =
        $("analyzeButton");

    const status =
        $("aiStatus");


    if (button) {

        button.disabled =
            true;

        button.textContent =
            "Analyzing…";
    }


    if (status) {

        status.textContent =
            "Running evidence-first analysis…";
    }


    try {

        const response =
            await analyzeIncidentForIncident(
                selectedIncidentId
            );


        renderAIAnalysis(
            response?.analysis ||
            null
        );


        await renderIncident();


    } catch (error) {

        console.error(
            "AI analysis failed:",
            error
        );


        if (status) {

            status.textContent =
                "AI analysis unavailable";
        }


    } finally {

        if (button) {

            button.disabled =
                false;

            button.textContent =
                "Analyze incident";
        }
    }
}


function renderAIAnalysis(
    analysis
) {

    const summary =
        $("aiSummary");

    const hypothesis =
        $("aiHypothesis");

    const confidence =
        $("aiConfidence");

    const confidenceFill =
        $("aiConfidenceFill");

    const evidenceBasis =
        $("aiEvidenceBasis");

    const status =
        $("aiStatus");

    const button =
        $("analyzeButton");


    if (!analysis) {

        if (summary) {

            summary.textContent =
                "No AI analysis generated for this incident yet.";
        }


        if (hypothesis) {

            hypothesis.textContent =
                "Run the evidence-first analyst to summarize the correlated incident.";
        }


        if (confidence) {

            confidence.textContent =
                "Not analyzed";
        }


        if (confidenceFill) {

            confidenceFill.style.width =
                "0%";
        }


        if (evidenceBasis) {

            evidenceBasis.innerHTML =
                "";
        }


        if (status) {

            status.textContent =
                "Ready";
        }


        if (button) {

            button.hidden =
                !selectedIncidentId;

            button.disabled =
                false;

            button.textContent =
                "Analyze incident";
        }


        return;
    }


    if (summary) {

        summary.textContent =
            analysis.summary ||
            "No summary available.";
    }


    if (hypothesis) {

        hypothesis.textContent =
            analysis.hypothesis ||
            "No grounded hypothesis available.";
    }


    const confidenceValue =
        Number(
            analysis.confidence
        );


    if (confidence) {

        confidence.textContent =
            Number.isFinite(
                confidenceValue
            )
                ? `${Math.round(
                    confidenceValue * 100
                )}%`
                : "—";
    }


    if (confidenceFill) {

        const percent =
            Number.isFinite(
                confidenceValue
            )
                ? Math.max(
                    0,
                    Math.min(
                        100,
                        confidenceValue * 100
                    )
                )
                : 0;


        confidenceFill.style.width =
            `${percent}%`;
    }


    if (evidenceBasis) {

        const items =
            Array.isArray(
                analysis.evidence_basis
            )
                ? analysis.evidence_basis
                : [];


        evidenceBasis.innerHTML =
            items.length
                ? `
                    <div class="factor-evidence">
                        Evidence basis
                    </div>

                    <ul class="list-clean">

                        ${items.map(
                            item =>
                                `<li>${escapeHtml(
                                    item
                                )}</li>`
                        ).join("")}

                    </ul>
                  `
                : "";
    }


    if (status) {

        status.textContent =
            analysis.analysis_mode ===
            "hybrid_evidence_first"

                ? "Hybrid evidence-first analysis"

                : "AI analysis ready";
    }


    if (button) {

        button.hidden =
            true;
    }
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
            ? [
                ...incident.evidence
            ].sort(
                (a, b) =>
                    new Date(
                        a.timestamp ||
                        0
                    ).getTime() -
                    new Date(
                        b.timestamp ||
                        0
                    ).getTime()
            )
            : [];


    if (
        evidence.length ===
        0
    ) {

        timeline.innerHTML = `
            <div class="empty-telemetry">
                No evidence available.
            </div>
        `;

    } else {

        timeline.innerHTML =
            evidence.map(
                item => {

                    const time =
                        formatTimestamp(
                            item.timestamp
                        );


                    return `

                        <div
                            class="evidence-item"
                        >

                            <div
                                class="evidence-time"
                            >
                                ${escapeHtml(
                                    time
                                )}
                            </div>


                            <div
                                class="evidence-event"
                            >
                                ${escapeHtml(
                                    item.event_name ||
                                    "security event"
                                )}
                            </div>


                            <div
                                class="evidence-sub"
                            >

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
                            String(
                                value
                            )
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

    const factors =
        Array.isArray(
            incident.risk_factors
        )
            ? incident.risk_factors
            : [];

    const evidence =
        Array.isArray(
            incident.evidence
        )
            ? incident.evidence
            : [];

    if (
        factors.length >
        0
    ) {

        container.innerHTML =
            factors.map(
                factor => {

                    const evidenceIds =
                        Array.isArray(
                            factor.evidence_ids
                        )
                            ? [
                                ...new Set(
                                    factor.evidence_ids
                                )
                            ]
                            : [];

                    const linkedEvidence =
                        evidenceIds
                            .map(
                                id =>
                                    evidence.find(
                                        item =>
                                            (
                                                item.event_id ||
                                                item.id
                                            ) === id
                                    )
                            )
                            .filter(Boolean);

                    const evidenceHtml =
                        linkedEvidence.length
                            ? `
                                <div
                                    class="factor-evidence"
                                    style="
                                        margin-top: 8px;
                                    "
                                >
                                    Evidence

                                    <div
                                        style="
                                            margin-top: 6px;
                                        "
                                    >
                                        ${linkedEvidence
                                            .map(
                                                item => `
                                                    <div
                                                        style="
                                                            margin-top: 5px;
                                                            padding: 6px 8px;
                                                            border: 1px solid var(--line);
                                                            border-radius: 6px;
                                                        "
                                                    >
                                                        <div>
                                                            ${escapeHtml(
                                                                item.event_name ||
                                                                "security event"
                                                            )}
                                                            ·
                                                            ${escapeHtml(
                                                                formatSourceLabel(
                                                                    item.source ||
                                                                    "unknown"
                                                                )
                                                            )}
                                                        </div>

                                                        <div
                                                            style="
                                                                margin-top: 3px;
                                                                opacity: 0.7;
                                                                font-size: 0.85em;
                                                            "
                                                        >
                                                            ${escapeHtml(
                                                                formatTimestamp(
                                                                    item.timestamp
                                                                )
                                                            )}
                                                            ·
                                                            ${escapeHtml(
                                                                item.event_id ||
                                                                item.id ||
                                                                "unknown"
                                                            )}
                                                        </div>
                                                    </div>
                                                `
                                            )
                                            .join("")
                                        }
                                    </div>
                                </div>
                            `
                            : "";

                    return `
                        <div
                            class="factor"
                        >

                            <div>

                                <div
                                    class="factor-name"
                                >
                                    ${escapeHtml(
                                        factor.label ||
                                        "Risk factor"
                                    )}
                                </div>

                                ${evidenceHtml}

                            </div>

                            <div
                                class="factor-score"
                            >
                                +${escapeHtml(
                                    String(
                                        factor.points ??
                                        0
                                    )
                                )}
                            </div>

                        </div>
                    `;
                }
            ).join("");

        return;
    }

    const reasons =
        Array.isArray(
            incident.why_it_matters
        )
            ? incident.why_it_matters
            : [];

    container.innerHTML =
        reasons.length
            ? reasons.map(
                reason => `
                    <div
                        class="factor"
                    >
                        <div
                            class="factor-name"
                        >
                            ${escapeHtml(
                                reason
                            )}
                        </div>
                    </div>
                `
            ).join("")

            : `
                <div
                    class="section-description"
                >
                    No explanation is available yet.
                </div>
            `;
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

        <div
            class="next-check"
        >

            <span
                class="step-index"
            >
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


    if (
        events.length ===
        0
    ) {

        list.innerHTML = `

            <div
                class="empty-telemetry"
            >
                No telemetry available.
            </div>

        `;

    } else {

        list.innerHTML =
            events.map(
                event => `

                    <div
                        class="telemetry-row"
                    >

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
                                formatSourceLabel(
                                    event.source ||
                                    "unknown"
                                )
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
                                event.id ||
                                "—"
                            )}

                        </span>

                    </div>

                `
            ).join("");
    }


    if (liveCount) {

        liveCount.textContent =
            DATA_MODE ===
            "mock"

                ? `${events.length} mock event(s)`

                : `${events.length} event(s)`;
    }
}


/* =========================================================
   WEBSOCKET
========================================================= */

function connectWebSocket() {

    if (
        DATA_MODE ===
        "mock"
    ) {

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
            async message => {

                try {

                    const event =
                        JSON.parse(
                            message.data
                        );


                    const eventId =
                        event.event_id ||
                        event.id;


                    if (eventId) {

                        events = [

                            event,

                            ...events.filter(
                                existing =>
                                    (
                                        existing.event_id ||
                                        existing.id
                                    ) !==
                                    eventId
                            )

                        ].slice(
                            0,
                            100
                        );

                    } else {

                        events.unshift(
                            event
                        );


                        events =
                            events.slice(
                                0,
                                100
                            );
                    }


                    renderMetrics();

                    renderTelemetry();

                    await refreshIncidents();


                } catch (error) {

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


    } catch {

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
            incidents.length >
            0

                ? incidents[0].id

                : null;


        renderMetrics();

        renderQueue();

        renderTelemetry();


        if (
            selectedIncidentId
        ) {

            await renderIncident();
        }


        connectWebSocket();


    } catch (error) {

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


/* =========================================================
   AI BUTTON
========================================================= */

const analyzeButton = $("analyzeButton");

if (analyzeButton) {
    analyzeButton.addEventListener(
        "click",
        runAIAnalysis
    );
}


/* =========================================================
   THEME TOGGLE
========================================================= */

const lightBtn = $("lightBtn");
const darkBtn = $("darkBtn");

const themeMeta =
    document.querySelector(
        'meta[name="theme-color"]'
    );


function applyTheme(theme) {

    const isDark =
        theme === "dark";

    document.body.classList.toggle(
        "dark",
        isDark
    );

    if (lightBtn) {
        lightBtn.classList.toggle(
            "active",
            !isDark
        );
    }

    if (darkBtn) {
        darkBtn.classList.toggle(
            "active",
            isDark
        );
    }

    if (themeMeta) {
        themeMeta.setAttribute(
            "content",
            isDark
                ? "#0B1230"
                : "#f4f8fc"
        );
    }

    localStorage.setItem(
        "sentra-theme",
        theme
    );
}


function initializeTheme() {

    const savedTheme =
        localStorage.getItem(
            "sentra-theme"
        );

    applyTheme(
        savedTheme === "light"
            ? "light"
            : "dark"
    );
}


if (lightBtn) {
    lightBtn.addEventListener(
        "click",
        () => {
            applyTheme("light");
        }
    );
}


if (darkBtn) {
    darkBtn.addEventListener(
        "click",
        () => {
            applyTheme("dark");
        }
    );
}


initializeTheme();

initialize();

const investigateButton =
    $("investigateButton");

if (investigateButton) {
    investigateButton.addEventListener(
        "click",
        runInvestigation
    );
}

/* =========================================================
   START
========================================================= */

initialize();