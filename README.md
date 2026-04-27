It goes beyond traditional log monitoring by enabling **real-time detection, correlation, investigation, and automated response**.

---

## 🚀 Key Capabilities

### 🔍 Detection & Analytics
- Real-time agent-based event ingestion
- Sigma rule engine with **risk promotion**
- Detection queue with scoring & prioritization
- UEBA (User & Entity Behavior Analytics) foundation

### ⚠️ Incident & Campaign Engine
- Alert → Incident transformation
- Campaign detection (multi-host / multi-event correlation)
- Risk-based prioritization
- Incident lifecycle management (open → acknowledged → resolved)

### 🧠 Investigation Intelligence
- Interactive investigation graph (hosts, users, processes, rules)
- Attack chain visualization (MITRE ATT&CK aligned)
- Timeline-based incident analysis
- AI-assisted analysis (planned/partial)

### 🖥️ SOC Operations UI
- Real-time dashboard
- Incident queue (analyst workflow)
- Asset inventory with risk context
- Live alert stream
- Command & response tracking

### ⚡ Response & Control
- Host isolation
- Command execution
- Analyst actions (assign, note, status update)
- Response logging & tracking

---

## 🧱 Architecture Overview


 Agent (Rust)
     ↓
 Ingestion Layer
     ↓
 Detection Engine (Sigma + Correlation)
     ↓
 Incident Engine
     ↓
 Investigation Layer (Graph + Timeline)
     ↓
 SOC Frontend (Next.js)


---

## 🛠️ Tech Stack

### Backend
- Python (FastAPI)
- PostgreSQL (or SQLite for dev)
- Alembic (migrations)
- Async processing (queues)

### Frontend
- Next.js (App Router)
- TypeScript
- Tailwind CSS

### Agent
- Rust (high-performance endpoint telemetry)

---

## 📦 Project Structure


backend/
app/
api/
services/
detection/
schemas/
core/

frontend/
src/
app/
components/
lib/

agent_rust/


---

## ⚙️ Getting Started

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload

Backend runs on:

http://127.0.0.1:8000

Swagger:

http://127.0.0.1:8000/docs
2. Frontend
cd frontend
npm install
npm run dev

Frontend runs on:

http://localhost:3000
3. Agent (Optional)
cd agent_rust
cargo build
🔐 Authentication
JWT-based authentication
Frontend proxy protection
Planned: httpOnly cookie-based secure session
📊 Example Use Case
Agent sends suspicious process execution
Sigma rule matches → high risk score
Alert is promoted to Incident
Incident grouped into Campaign
Analyst investigates via graph + timeline
Host is isolated & response executed
🧭 Roadmap
 Detection engine (Sigma + scoring)
 Incident engine
 Investigation graph
 SOC UI
 AI-assisted analysis
 Full enterprise auth (httpOnly sessions)
 Multi-tenant isolation
 Advanced response orchestration
🎯 Vision

SolidTrace aims to evolve from:

➡️ "Log monitoring tool"
➡️ to
➡️ "Autonomous SOC intelligence platform"

Where the system not only detects threats, but also:

understands attack behavior
guides analysts
accelerates response
⚠️ Disclaimer

This project is under active development.
Not production-ready yet.

👨‍💻 Author

Developed by a cybersecurity-focused engineer building next-generation SOC tooling.

⭐ If you like this project

Give it a star and follow development 🚀
