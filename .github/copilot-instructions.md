<!-- Short, focused instructions for AI coding copilots working in this repository -->
# Copilot Instructions — SolidTrace Ultimate

Purpose: give an AI coding agent the essential, actionable knowledge
to be productive immediately in this repository (architecture, run
commands, integration points, and repo-specific conventions).

High-level architecture
- **Agent (Rust)**: located in `agent_rust/` — a Windows system agent
  that monitors processes, files, USB, registry and sends events to
  the backend. Entry: `agent_rust/src/main.rs`. Build/run with `cargo`.
- **Backend (Python/FastAPI)**: located in `backend/` — FastAPI app
  (entry: `backend/api_advanced.py`) accepts ingest POSTs and exposes
  a websocket at `/ws/alerts` for commands. Uses SQLAlchemy to write
  alerts to Postgres table `alerts_final`.
- **Frontend (Next.js)**: located in `frontend/` — React/Next UI that
  consumes backend APIs (`/api/alerts`, `/api/stats`) and the websocket.

Key integration points (must preserve these names/paths)
- Agent -> Backend: POST to `http://127.0.0.1:8000/api/v1/ingest`
  (see `agent_rust/src/api_client.rs` where `SERVER_BASE` and endpoint
  are defined).
- Backend WebSocket: `ws://127.0.0.1:8000/ws/alerts` (clients listen
  for COMMAND messages; see `backend/api_advanced.py`).
- DB table: `alerts_final` (created/used in `backend/api_advanced.py`).

Common workflows / commands
- Build & run Rust agent (Windows):
  - Open PowerShell in `agent_rust/` and run:
    ```powershell
    cargo run
    ```
  - The agent requires administrative privileges and writes a
    registry Run key for persistence (see `enable_persistence()` in `main.rs`).
- Start backend (development):
  - Create a venv, install requirements, then run:
    ```bash
    python -m venv .venv
    .venv\Scripts\activate   # Windows
    pip install -r backend/requirements.txt
    python backend/api_advanced.py
    # or for reload/explicit app: uvicorn api_advanced:app --reload --host 0.0.0.0 --port 8000
    ```
- Start frontend (dev):
  - From `frontend/`:
    ```bash
    npm install
    npm run dev
    ```

Project-specific conventions & gotchas
- Many source files use Turkish comments and emoji-based console
  logging. Match the existing logging style when adding instrumentation.
- The backend hardcodes `SQLALCHEMY_DATABASE_URL` in `api_advanced.py`.
  Look for this string when modifying DB behavior — the table name
  `alerts_final` is expected by the frontend and agent flows.
- Websocket message types use a `type` field with values like
  `COMMAND` and `ACTION_LOG`. `COMMAND` messages may include
  `action` and `target_hostname` fields (see `api_client.rs`).
- Agent runs extremely frequently (200ms process scan). Be careful
  when modifying monitoring loops — efficiency and non-blocking
  behavior (Tokio) matter.
- The Rust agent uses `whoami`, `sysinfo` and `reqwest` and expects
  local `http://127.0.0.1:8000` during development.

Files to inspect for most tasks
- Agent: `agent_rust/src/main.rs`, `agent_rust/src/api_client.rs`,
  `agent_rust/src/registry_monitor.rs` (current file), `agent_rust/Cargo.toml`.
- Backend: `backend/api_advanced.py`, `backend/requirements.txt`.
- Frontend: `frontend/package.json`, `frontend/src/app` (pages/components).

Testing & development tips
- Backend tests (pytest) are listed in `requirements.txt` — run from
  `backend/` with an activated venv: `pytest -q`.
- Use `uvicorn` with `--reload` for faster backend iteration.
- When changing the agent, build and run locally on a Windows VM or
  Windows host (the agent requests elevation and modifies registry keys).

What to avoid changing without full verification
- Do not rename `alerts_final` or change the `/api/v1/ingest` path
  without updating both agent and frontend; these are hardwired.
- Avoid removing admin-elevation code in the Rust agent; it's required
  for registry and process-killing features.

If you need clarification
- Ask for the intended runtime environment (Windows VM vs local host),
  database connection details, and whether it's safe to run the agent
  on your machine (it requests elevation and modifies registry keys).

Next step after edits
- Run the backend and agent locally and confirm the agent posts to
  `/api/v1/ingest` and the frontend receives websocket alerts.
