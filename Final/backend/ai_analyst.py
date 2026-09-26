import asyncio
import json
import urllib.error
import urllib.request
from typing import Dict, List, Optional


OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_MODEL = "dolphin-local:latest"

AI_ANALYSIS_CACHE: Dict[str, dict] = {}


# ---------------------------------------------------------
# AI OUTPUT SCHEMA
# ---------------------------------------------------------
#
# The model is intentionally responsible only for the
# human-readable summary.
#
# SENTRA itself constructs:
# - hypothesis
# - evidence_basis
# - missing_evidence
# - next_checks
# - confidence
#
# This prevents a small local model from inventing
# security conclusions.
# ---------------------------------------------------------

AI_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
        },
    },
    "required": [
        "summary",
    ],
}


# ---------------------------------------------------------
# SYSTEM PROMPT
# ---------------------------------------------------------

SYSTEM_PROMPT = """
You are SENTRA's AI incident summarizer.

SENTRA has already detected and scored the observed event sequence
using a deterministic evidence engine.

Your ONLY job is to write a concise factual summary of the
observed incident sequence.

STRICT RULES:

1. Use ONLY facts explicitly supplied.

2. Do NOT invent:
   - attackers
   - malware
   - compromise
   - breach
   - malicious intent
   - causes
   - configuration problems
   - network problems
   - authentication bugs
   - users
   - processes
   - events
   - locations

3. Do NOT interpret the event as confirmed malicious activity.

4. Do NOT change or reinterpret SENTRA's risk score.

5. Mention the important observed sequence.

6. When multiple telemetry sources are present, mention
   the cross-source nature of the evidence.

7. Describe observations, not explanations.

8. Keep the response to one concise paragraph.

9. Return ONLY valid JSON matching the requested schema.
"""


# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def _safe_str(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _event_context_map(
    evidence_context: Optional[List[dict]],
) -> Dict[str, dict]:
    return {
        item.get("event_id"): item
        for item in (evidence_context or [])
        if item.get("event_id")
    }


def _source_label(source: str) -> str:
    if source == "windows_security":
        return "Windows Security"

    if source == "internal_app":
        return "Internal App"

    return source.replace("_", " ").title()


def _build_grounded_hypothesis(
    incident: dict,
) -> str:
    """
    Deterministic hypothesis.

    This deliberately does NOT ask the LLM to invent a root cause.
    """

    sources = incident.get("sources", [])
    host = incident.get("host", "the affected host")
    users = incident.get("users", [])

    user = users[0] if users else "the affected user"

    if len(sources) >= 2:
        return (
            f"The observed telemetry shows an authentication "
            f"and access sequence involving {user} on {host} across "
            f"multiple telemetry sources. The evidence consists of "
            f"recorded authentication and authorization events from "
            f"the supplied telemetry."
        )

    return (
        f"The observed telemetry shows an authentication and access "
        f"sequence involving {user} on {host} that warrants further "
        f"investigation. The available evidence does not establish "
        f"malicious intent or compromise."
    )


def _build_evidence_basis(
    incident: dict,
    evidence_context: Optional[List[dict]],
) -> List[str]:
    """
    Build evidence_basis deterministically from the actual incident
    evidence and observed telemetry.
    """

    context_map = _event_context_map(
        evidence_context
    )

    basis: List[str] = []

    evidence = incident.get(
        "evidence",
        [],
    )

    # -----------------------------------------------------
    # Windows 4648
    # -----------------------------------------------------

    for item in evidence:
        if item.get("event_name") != "explicit_credentials":
            continue

        context = context_map.get(
            item.get("event_id"),
            {},
        )

        observed = context.get(
            "observed_context",
            {},
        )

        source_ip = observed.get(
            "source_ip"
        )

        if source_ip:
            basis.append(
                "Windows Security 4648 recorded explicit "
                f"credential use for {item.get('user', 'the user')} "
                f"from {source_ip}."
            )
        else:
            basis.append(
                "Windows Security 4648 recorded explicit "
                f"credential use for {item.get('user', 'the user')}."
            )

        break

    # -----------------------------------------------------
    # Windows 4625
    # -----------------------------------------------------

    for item in evidence:
        if item.get("event_name") != "logon_failure":
            continue

        context = context_map.get(
            item.get("event_id"),
            {},
        )

        observed = context.get(
            "observed_context",
            {},
        )

        source_ip = observed.get(
            "source_ip"
        )

        package = observed.get(
            "AuthenticationPackageName"
        )

        status = observed.get(
            "Status"
        )

        sub_status = observed.get(
            "SubStatus"
        )

        description = (
            "Windows Security 4625 recorded a failed "
            f"logon for {item.get('user', 'the user')}"
        )

        if source_ip:
            description += (
                f" from {source_ip}"
            )

        if package:
            description += (
                f" using {package}"
            )

        if status:
            description += (
                f" (status {status}"
            )

            if sub_status:
                description += (
                    f", substatus {sub_status}"
                )

            description += ")"

        description += "."

        basis.append(description)

        break

    # -----------------------------------------------------
    # Application authentication failures
    # -----------------------------------------------------

    app_auth_failures = [
        item
        for item in evidence
        if (
            item.get("source") == "internal_app"
            and item.get("event_name")
            == "authentication_failure"
        )
    ]

    if app_auth_failures:
        count = len(
            app_auth_failures
        )

        basis.append(
            f"The Internal App recorded {count} "
            f"authentication failure"
            f"{'s' if count != 1 else ''} for "
            f"{app_auth_failures[0].get('user', 'the user')}."
        )

    # -----------------------------------------------------
    # Successful authentication
    # -----------------------------------------------------

    if any(
        item.get("event_name")
        == "authentication_success"
        for item in evidence
    ):
        basis.append(
            "The Internal App subsequently recorded a "
            "successful authentication for the same user."
        )

    # -----------------------------------------------------
    # Restricted action
    # -----------------------------------------------------

    if any(
        item.get("event_name")
        in {
            "authorization_failure",
            "restricted_resource_access",
        }
        for item in evidence
    ):
        basis.append(
            "The Internal App recorded an attempted "
            "restricted action that was not authorized."
        )

    # -----------------------------------------------------
    # Cross-source correlation
    # -----------------------------------------------------

    sources = incident.get(
        "sources",
        [],
    )

    if len(sources) >= 2:
        source_names = [
            _source_label(source)
            for source in sources
        ]

        basis.append(
            "Related activity was correlated across "
            + " and ".join(source_names)
            + " telemetry for the same incident."
        )

    # Keep the dashboard concise.
    return basis[:5]


def _build_missing_evidence(
    incident: dict,
    evidence_context: Optional[List[dict]],
) -> List[str]:
    """
    Only identify information that is genuinely not established
    by the supplied evidence.
    """

    evidence = incident.get(
        "evidence",
        []
    )

    context_map = _event_context_map(
        evidence_context
    )

    missing: List[str] = []

    # -----------------------------------------------------
    # Authorization / business context
    # -----------------------------------------------------

    has_authorization_failure = any(
        item.get("event_name")
        in {
            "authorization_failure",
            "restricted_resource_access",
        }
        for item in evidence
    )

    if has_authorization_failure:
        missing.append(
            "Whether the restricted access attempt was expected "
            "and authorized for the user at that time."
        )

    # -----------------------------------------------------
    # Cause of authentication failures
    # -----------------------------------------------------

    auth_failures = [
        item
        for item in evidence
        if item.get("event_name")
        == "authentication_failure"
    ]

    if auth_failures:
        has_detailed_reason = False

        for item in auth_failures:
            context = context_map.get(
                item.get("event_id"),
                {},
            )

            observed = context.get(
                "observed_context",
                {},
            )

            if any(
                observed.get(key)
                for key in {
                    "reason",
                    "FailureReason",
                    "SubStatus",
                    "Status",
                }
            ):
                has_detailed_reason = True
                break

        if not has_detailed_reason:
            missing.append(
                "The specific reason for the observed "
                "authentication failures."
            )

    # -----------------------------------------------------
    # Broader corroborating telemetry
    # -----------------------------------------------------

    missing.append(
        "Additional endpoint or network telemetry that could "
        "corroborate activity beyond the supplied authentication "
        "and authorization events."
    )

    return missing[:3]


def _build_next_checks(
    incident: dict,
    evidence_context: Optional[List[dict]],
) -> List[str]:
    """
    Deterministic defensive investigation steps.
    """

    checks: List[str] = []

    evidence = incident.get(
        "evidence",
        []
    )

    # -----------------------------------------------------
    # Expected/authorized activity
    # -----------------------------------------------------

    if any(
        item.get("event_name")
        in {
            "authorization_failure",
            "restricted_resource_access",
        }
        for item in evidence
    ):
        checks.append(
            "Verify whether the user was expected to attempt "
            "the restricted action and review the affected resource."
        )

    # -----------------------------------------------------
    # Account investigation
    # -----------------------------------------------------

    if any(
        item.get("event_name")
        in {
            "authentication_failure",
            "authentication_success",
            "logon_failure",
            "explicit_credentials",
        }
        for item in evidence
    ):
        checks.append(
            "Review the affected account and confirm that the "
            "authentication activity was expected."
        )

    # -----------------------------------------------------
    # Windows evidence
    # -----------------------------------------------------

    if any(
        item.get("source")
        == "windows_security"
        for item in evidence
    ):
        checks.append(
            "Review the corresponding Windows Security events "
            "and correlate additional telemetry for the same user "
            "and host."
        )

    # -----------------------------------------------------
    # Keep compact.
    # -----------------------------------------------------

    return checks[:3]


def _build_grounding_confidence(
    incident: dict,
    evidence_context: Optional[List[dict]],
) -> float:
    """
    Confidence reflects evidence completeness for the generated
    analysis, not confidence that an attack occurred.

    This is deliberately separate from SENTRA's risk score.
    """

    evidence_count = len(
        incident.get(
            "evidence",
            [],
        )
    )

    source_count = len(
        incident.get(
            "sources",
            [],
        )
    )

    score = 0.70

    if evidence_count >= 5:
        score += 0.08

    if evidence_count >= 8:
        score += 0.05

    if source_count >= 2:
        score += 0.10

    if evidence_context:
        score += 0.05

    return round(
        min(
            score,
            0.95,
        ),
        2,
    )


# ---------------------------------------------------------
# VALIDATION
# ---------------------------------------------------------

FORBIDDEN_PHRASES = (
    "possible attacker",
    "potential attacker",
    "attacker activity",
    "malware",
    "compromised",
    "compromise",
    "breach",
    "data exfiltration",
    "malicious actor",
    "malicious user",
    "configuration issue",
    "configuration problem",
    "network problem",
    "network issue",
    "authentication bug",
    "temporary authentication issue",
    "temporary authentication problem",
    "suspicious",
        "suspicious authentication",
    "suspicion",
    "suspicious activity",
    "security incident",
        "indicating",
        "indicates",
    "indicate a critical",
    "indicates a critical",
    "suggests",
    "suggest",
)


def _contains_unsupported_claim(
    text: str,
) -> bool:

    lowered = text.lower()

    return any(
        phrase in lowered
        for phrase in FORBIDDEN_PHRASES
    )


def _validate_summary(
    summary: str,
) -> bool:

    if not summary:
        return False

    if _contains_unsupported_claim(summary):
        return False

    # We want the model to describe evidence rather than invent
    # a cause. Requiring at least one evidence-oriented term keeps
    # the output grounded.
    evidence_terms = (
        "observed",
        "recorded",
        "authentication",
        "authorization",
        "telemetry",
        "event",
        "activity",
    )

    lowered = summary.lower()

    if not any(
        term in lowered
        for term in evidence_terms
    ):
        return False

    return True


# ---------------------------------------------------------
# PROMPT
# ---------------------------------------------------------

def _build_prompt(
    incident: dict,
    evidence_context: Optional[List[dict]] = None,
) -> str:

    evidence_lines: List[str] = []

    for item in incident.get(
        "evidence",
        [],
    ):
        evidence_lines.append(
            "- "
            f"event_id={item.get('event_id', 'unknown')} | "
            f"time={item.get('timestamp', 'unknown')} | "
            f"source={item.get('source', 'unknown')} | "
            f"event={item.get('event_name', 'unknown')} | "
            f"user={item.get('user', 'unknown')} | "
            f"host={item.get('host', 'unknown')} | "
            f"severity={item.get('severity', 'unknown')}"
        )

    context_lines: List[str] = []

    for context in (
        evidence_context or []
    ):
        raw = context.get(
            "observed_context",
            {},
        )

        context_lines.append(
            "- "
            f"event_id={context.get('event_id', 'unknown')} | "
            f"source={context.get('source', 'unknown')} | "
            f"event={context.get('event_name', 'unknown')} | "
            f"observed_context="
            f"{json.dumps(raw, ensure_ascii=False)}"
        )

    prompt = f"""
Write a concise factual summary for this SENTRA incident.

INCIDENT
--------
Title: {incident.get('title', 'Unknown')}
Risk: {incident.get('risk', 0)}
Severity: {incident.get('severity', 'unknown')}
Host: {incident.get('host', 'unknown')}
Users: {json.dumps(incident.get('users', []))}
Sources: {json.dumps(incident.get('sources', []))}
Event count: {incident.get('event_count', 0)}

WHY SENTRA FLAGGED IT
---------------------
{chr(10).join(
    '- ' + str(item)
    for item in incident.get("why_it_matters", [])
) or '- None provided'}

CHRONOLOGICAL EVIDENCE
----------------------
{chr(10).join(evidence_lines) or '- None provided'}

RELEVANT OBSERVED CONTEXT
-------------------------
{chr(10).join(context_lines) or '- None provided'}

WRITING REQUIREMENTS
--------------------
- State only what was observed.
- Describe events without evaluative labels such as suspicious or malicious.
- Do not say the observations indicate, suggest, imply, or prove a security incident.
- Mention the important sequence.
- Mention multiple telemetry sources when present.
- Do not explain a root cause.
- Do not mention attackers, malware, compromise, breach,
  malicious intent, configuration issues, or network problems.
- Do not speculate.
- Do not change the supplied risk or severity.
- Keep the result concise.
"""

    return prompt.strip()


# ---------------------------------------------------------
# OLLAMA CALL
# ---------------------------------------------------------

def _call_ollama(
    incident: dict,
    evidence_context: Optional[List[dict]] = None,
) -> dict:

    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT.strip(),
            },
            {
                "role": "user",
                "content": _build_prompt(
                    incident,
                    evidence_context,
                ),
            },
        ],
        "stream": False,
        "format": AI_SCHEMA,
        "options": {
            "temperature": 0.0,
        },
    }

    body = json.dumps(
        payload
    ).encode(
        "utf-8"
    )

    request = urllib.request.Request(
        OLLAMA_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=90,
        ) as response:

            raw_response = response.read().decode(
                "utf-8"
            )

    except urllib.error.HTTPError as exc:

        detail = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            f"Ollama HTTP {exc.code}: {detail}"
        ) from exc

    except urllib.error.URLError as exc:

        raise RuntimeError(
            f"Could not reach Ollama: {exc.reason}"
        ) from exc

    except TimeoutError as exc:

        raise RuntimeError(
            "Ollama analysis timed out."
        ) from exc

    try:

        outer = json.loads(
            raw_response
        )

        message = outer.get(
            "message",
            {},
        )

        content = message.get(
            "content"
        )

        if not content:
            raise ValueError(
                "Ollama returned no message content."
            )

        analysis = json.loads(
            content
        )

    except (
        json.JSONDecodeError,
        ValueError,
    ) as exc:

        raise RuntimeError(
            "Ollama returned invalid analysis JSON."
        ) from exc

    summary = analysis.get(
        "summary"
    )

    if not isinstance(
        summary,
        str,
    ):
        raise RuntimeError(
            "AI summary is missing or invalid."
        )

    summary = summary.strip()

    return {
        "summary": summary,
    }


# ---------------------------------------------------------
# PUBLIC ANALYSIS FUNCTION
# ---------------------------------------------------------

async def analyze_incident(
    incident: dict,
    evidence_context: Optional[List[dict]] = None,
) -> dict:

    incident_id = incident.get(
        "id"
    )

    if not incident_id:
        raise ValueError(
            "Incident has no ID."
        )

    ai_result = await asyncio.to_thread(
        _call_ollama,
        incident,
        evidence_context,
    )

    ai_summary = ai_result.get(
        "summary",
        "",
    )

    # -----------------------------------------------------
    # Validate AI-generated summary.
    # -----------------------------------------------------

    if not _validate_summary(
        ai_summary
    ):
        ai_summary = (
            "SENTRA correlated the supplied telemetry into "
            "a single incident involving the observed "
            "authentication and access sequence. The "
            "available evidence is being presented for "
            "further investigation."
        )

    # -----------------------------------------------------
    # Deterministic analytical fields.
    # -----------------------------------------------------

    result = {
        "summary": ai_summary,

        "hypothesis": _build_grounded_hypothesis(
            incident
        ),

        "confidence": _build_grounding_confidence(
            incident,
            evidence_context,
        ),

        "evidence_basis": _build_evidence_basis(
            incident,
            evidence_context,
        ),

        "missing_evidence": _build_missing_evidence(
            incident,
            evidence_context,
        ),

        "next_checks": _build_next_checks(
            incident,
            evidence_context,
        ),

        "model": OLLAMA_MODEL,

        "generated_for_incident": incident_id,

        "analysis_mode": "hybrid_evidence_first",
    }

    AI_ANALYSIS_CACHE[
        incident_id
    ] = result

    return result


# ---------------------------------------------------------
# CACHE
# ---------------------------------------------------------

def get_analysis(
    incident_id: str,
) -> Optional[dict]:

    return AI_ANALYSIS_CACHE.get(
        incident_id
    )


def clear_analysis(
    incident_id: str,
) -> None:

    AI_ANALYSIS_CACHE.pop(
        incident_id,
        None,
    )