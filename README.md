# SolidTrace SOC Platform

SolidTrace is a next‑generation **Security Operations Center (SOC)
platform** designed for endpoint telemetry collection, threat detection,
and behavioral analytics.

The platform combines **endpoint agents**, **detection engines**, and a
**SOC dashboard** to provide advanced threat visibility.

------------------------------------------------------------------------

# Architecture

    Endpoint Agent
         ↓
    Signed API
         ↓
    Detection Queue
         ↓
    Detection Engines
         ↓
    Alerts
         ↓
    SOC Dashboard

### Technology Stack

Backend - FastAPI - Python - WebSockets

Frontend - Next.js - React - TailwindCSS

Database - PostgreSQL

Detection Engines - Sigma detection engine - Correlation engine - UEBA
behavioral analytics

------------------------------------------------------------------------

# Core Features

## Agent Security

SolidTrace agents communicate with the backend using **cryptographically
signed requests**.

Security protections:

-   HMAC‑SHA256 request signatures
-   Nonce replay protection
-   Timestamp validation
-   Encrypted agent secrets
-   Agent revoke lifecycle

Agent headers:

    X-Agent-Id
    X-Agent-Timestamp
    X-Agent-Nonce
    X-Agent-Signature

These protections prevent:

-   replay attacks
-   request tampering
-   agent impersonation

------------------------------------------------------------------------

# Detection Pipeline

Telemetry processing pipeline:

    Agent
       ↓
    Signed API
       ↓
    Detection Queue
       ↓
    Queue Worker
       ↓
    Sigma Engine
       ↓
    Correlation Engine
       ↓
    UEBA Engine
       ↓
    Alerts

The queue architecture ensures the ingestion API remains responsive even
under heavy load.

------------------------------------------------------------------------

# Detection Engines

## Sigma Engine

Detects known attacker techniques.

Example detections:

-   Mimikatz execution
-   PowerShell download cradle
-   WMIC remote command execution

------------------------------------------------------------------------

## Correlation Engine

Detects behavioral attack chains.

Example detection:

    PROCESS_ANOMALY_STORM

Triggered when multiple suspicious processes occur within a short time
window.

------------------------------------------------------------------------

## UEBA Engine

User and Entity Behavior Analytics.

Tracks:

-   user process patterns
-   anomaly frequency
-   behavioral deviation

------------------------------------------------------------------------

# Agent Lifecycle

1.  Enrollment token generated
2.  Agent registers
3.  Agent receives credentials
4.  Agent sends telemetry

Endpoints:

    POST /api/agents/enrollment-token
    POST /api/agents/register
    POST /api/v1/agent/heartbeat
    POST /api/v1/ingest
    POST /api/agents/{agent_id}/revoke

------------------------------------------------------------------------

# Queue Architecture

Events are processed asynchronously.

Queue table:

    detection_queue

Worker processes events and sends them to detection engines.

Benefits:

-   scalable ingestion
-   prevents API overload
-   supports distributed workers

------------------------------------------------------------------------

# Automated Test Scripts

### agent_signed_test.py

Validates:

-   signed heartbeat
-   signed ingest
-   replay protection

### solidtrace_queue_alert_test.py

End‑to‑end validation:

-   admin login
-   agent enrollment
-   agent registration
-   signed heartbeat
-   signed ingest
-   alert generation
-   agent revoke lifecycle

------------------------------------------------------------------------

# Current System Status

Validated working components:

    Admin auth ✔
    Agent enrollment ✔
    Agent registration ✔
    Signed heartbeat ✔
    Signed ingest ✔
    Detection queue ✔
    Alert generation ✔
    Replay protection ✔
    Agent revoke ✔

System state: **Operational prototype**

------------------------------------------------------------------------

# Development Roadmap

### Sprint 1

Dashboard authentication stabilization

### Sprint 2

Agent online/offline visibility

### Sprint 3

Asset inventory

### Sprint 4

Alert enrichment

### Sprint 5

Advanced correlation detection

### Sprint 6

SOC case management

### Sprint 7

Multi‑tenant hardening

------------------------------------------------------------------------

# Development

Clone repository

    git clone https://github.com/YOUR_USERNAME/solidtrace.git

Backend

    cd backend
    pip install -r requirements.txt
    uvicorn app.main:app --reload

Frontend

    cd frontend
    npm install
    npm run dev

------------------------------------------------------------------------

# Environment Variables

Required variables:

    DATABASE_URL
    JWT_SECRET_KEY
    AGENT_SECRET_KEK
    ACCESS_TOKEN_EXPIRE_MINUTES
    REFRESH_TOKEN_EXPIRE_DAYS

------------------------------------------------------------------------

# Security Model

SolidTrace follows **security‑first architecture principles**:

-   signed agent communication
-   encrypted secrets
-   replay protection
-   strict token lifecycle
-   audit logging

------------------------------------------------------------------------

# Project Context

Development context is documented in:

    PROJECT_CONTEXT.md

This file contains:

-   architecture overview
-   completed milestones
-   roadmap
-   security model

------------------------------------------------------------------------

# License

MIT License
