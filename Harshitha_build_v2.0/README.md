# SENTRA

## Intelligent Threat Detection & Situational Awareness

SENTRA is an evidence-first security incident intelligence system designed for lean IT teams without a dedicated Security Operations Center (SOC).

It ingests real-time security telemetry, normalizes events into a common model, correlates related activity across entities and time, prioritizes incidents, exposes the evidence behind those incidents, and uses structured AI analysis to guide the next investigation step.

## Problem Statement

ARGONYX '26 — Problem Statement #5:

> Develop an intelligent situational-awareness system capable of analyzing multiple real-time data streams to detect anomalous activities, identify potential security threats, prioritize critical alerts, and support faster and more informed decision-making by authorized personnel.

## Current Architecture

Real Telemetry
    ↓
Telemetry Adapters
    ↓
Event Normalization
    ↓
Correlation
    ↓
Risk / Incident Engine
    ↓
Evidence
    ↓
AI Analysis
    ↓
Live Dashboard

## Current Working Base

The prototype currently includes a real-time Windows Security Event Log collector using Windows Event Log subscriptions.

Supported authentication-related events include:

- 4624 — Successful logon
- 4625 — Failed logon
- 4648 — Explicit credentials
- 4634 — Logoff
- 4647 — User-initiated logoff

The collector normalizes events and sends them to a FastAPI backend, which exposes them to the frontend through WebSockets.

## MVP Telemetry Sources

The MVP is designed around two real and controllable telemetry sources:

1. Windows Security telemetry
2. A self-controlled internal web application producing structured application/security telemetry

These sources feed the same event pipeline.

## Core Product Flow

Authentication + Application Telemetry
    ↓
Correlation
    ↓
Risk Score
    ↓
Incident
    ↓
Evidence / Timeline
    ↓
AI Analysis
    ↓
Next Investigation Step

## Design Principles

- Real telemetry first
- Deterministic evidence before AI
- Common event schema across sources
- Explainable correlation and risk
- Investigation-first workflow
- Live demo over simulated data
- Replay only as an emergency fallback

## Technology

### Backend
- Python
- FastAPI
- asyncio
- WebSockets

### Telemetry
- Windows Security Event Log
- Application telemetry

### Frontend
- React
- Vite
- Tailwind CSS

### AI
- Structured LLM output

## Team

### The 2 Bits

**Harshitha M** — Team Lead / Frontend & Product

**Vaishnav S** — Backend / Telemetry / Intelligence

## Project Status

ARGONYX '26 — Round 2

The real-time telemetry and event-streaming foundation has been implemented and validated.

The correlation, risk, incident, evidence, and AI layers are being developed during the 24-hour hackathon build.

---

Built for ARGONYX '26 — RV University
