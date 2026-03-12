# 🛡️ SolidTrace

SolidTrace modern bir **Security Operations Center (SOC) / SIEM
platformu** geliştirme projesidir.

Amaç; endpoint telemetry, detection rules, UEBA analizleri ve
investigation araçlarını tek bir platformda toplayarak SOC analistleri
için **gerçek zamanlı güvenlik görünürlüğü** sağlamaktır.

Bu README aynı zamanda proje için **kalıcı teknik hafıza** görevi görür.
İleride projeye tekrar dönüldüğünde mimariyi, yapılan işleri ve
roadmap'i hızlıca hatırlamak için hazırlanmıştır.

------------------------------------------------------------------------

# 🎯 Proje Amacı

SolidTrace aşağıdaki problemleri çözmek için geliştirilmektedir:

-   Endpoint güvenlik telemetrisini merkezi toplamak\
-   Anormal davranışları tespit etmek\
-   SOC analistlerinin investigation süreçlerini hızlandırmak\
-   Güvenlik olaylarını görselleştirmek\
-   Otomatik detection pipeline oluşturmak

------------------------------------------------------------------------

# 🧠 Platform Mimari

    Endpoint Agent
          ↓
    Ingest API
          ↓
    Event Queue
          ↓
    Detection Engine
          ↓
    Alert Engine
          ↓
    Analytics / UEBA
          ↓
    SOC Dashboard

Platform katmanları:

    Agent Layer
    API Layer
    Detection Layer
    Analytics Layer
    SOC Visualization Layer

------------------------------------------------------------------------

# 🏗️ Kullanılan Teknolojiler

## Backend

-   FastAPI
-   SQLAlchemy
-   PostgreSQL
-   WebSocket
-   Pydantic

## Frontend

-   Next.js
-   React
-   TailwindCSS
-   Lucide Icons

## Security / Detection

-   Sigma-like rule engine
-   UEBA behavioral analysis
-   Risk scoring engine
-   Alert correlation

------------------------------------------------------------------------

# 📦 Repository Yapısı

    solidtrace/

    backend/
     ├── app/
     │   ├── api/
     │   │   ├── routes_agents.py
     │   │   ├── routes_alerts.py
     │   │   ├── routes_actions.py
     │   │   ├── routes_dashboard.py
     │   │   ├── routes_sigma.py
     │   │   └── routes_ueba.py
     │   │
     │   ├── core/
     │   ├── database/
     │   ├── schemas/
     │   └── main.py
     │
    frontend/
     ├── src/
     │   ├── app/
     │   │   └── (soc)
     │   │        ├── dashboard
     │   │        ├── alerts
     │   │        ├── assets
     │   │        ├── activity
     │   │        └── investigations
     │   │
     │   ├── components/
     │   │   └── soc/
     │   │        ├── layout
     │   │        ├── providers
     │   │        └── ui
     │   │
     │   └── lib/api

------------------------------------------------------------------------

# 🚀 Şu Ana Kadar Yapılan Geliştirmeler

## Backend

### Agent System

✔ Agent enrollment token sistemi\
✔ Agent register endpoint\
✔ Signed ingest sistemi\
✔ Replay attack protection\
✔ Agent revoke sistemi

### Event Pipeline

✔ Telemetry ingest API\
✔ Queue worker\
✔ Detection engine injection

### Alerts

✔ Alert lifecycle

    open
    acknowledged
    resolved
    reopened

✔ Alert assignment\
✔ Analyst notes\
✔ Alert search / filtering

### Analytics

✔ Alert statistics\
✔ Activity analytics\
✔ Monthly security report (PDF)

### Security

✔ Role based access\
✔ Audit log system\
✔ Request ID tracking\
✔ Signed telemetry ingest

------------------------------------------------------------------------

# 🖥️ Frontend (SOC Dashboard)

SolidTrace v2 ile birlikte yeni SOC arayüzü geliştirilmiştir.

### Dashboard

✔ Metrics overview\
✔ Alert statistics\
✔ Risk scoring

### Visualization

✔ Global Threat Map\
✔ Live Alert Stream

### Analytics

✔ UEBA profiles\
✔ Sigma detection stats\
✔ Risky assets

### Investigation

✔ Investigation graph\
✔ Case based investigation\
✔ Alert correlation view

### UI Architecture

✔ SOC AppShell layout\
✔ Dark / Light theme\
✔ Tailwind UI system\
✔ Panel + MetricCard components

------------------------------------------------------------------------

# 📊 SOC Dashboard Bileşenleri

Dashboard şu modüllerden oluşur:

-   Threat Map
-   Live Alert Stream
-   Risky Assets
-   UEBA Spotlight
-   Sigma Stats
-   Alert Analytics
-   Recent Activity

------------------------------------------------------------------------

# 🔎 Investigation Platform

SOC analistleri için investigation ekranı geliştirilmiştir.

Investigation Graph aşağıdaki node tiplerini gösterir:

    Host
    User
    Process
    Rule
    Alert

Graph ilişkileri:

    User → Process
    Process → Host
    Process → Detection Rule
    Rule → Alert
    Host → Alert

------------------------------------------------------------------------

# 🔐 Güvenlik Özellikleri

SolidTrace aşağıdaki güvenlik mekanizmalarını içerir:

-   Agent authentication\
-   Signed telemetry ingest\
-   Replay attack detection\
-   Audit logging\
-   Role based access

------------------------------------------------------------------------

# 🧪 Testler

Smoke test scriptleri:

    agent_signed_test.py
    solidtrace_queue_alert_test.py
    alert_assignment_smoke_test.py
    dashboard_visibility_smoke_test.py

Bu testler doğrular:

-   Agent ingest pipeline
-   Alert creation
-   Alert lifecycle
-   Dashboard data endpoints

------------------------------------------------------------------------

# 📈 Gelecek Geliştirmeler (Roadmap)

## Detection Engine

-   Correlation engine
-   MITRE ATT&CK mapping
-   Sigma rule import

## Analytics

-   UEBA anomaly scoring
-   Behavior baselines
-   Risk heatmaps

## Investigation

-   Timeline investigation
-   Evidence collection
-   Case management

## Threat Intelligence

-   IOC feeds
-   reputation lookups
-   automatic enrichment

## SOC Automation

-   automated response
-   containment workflows
-   SOAR style playbooks

------------------------------------------------------------------------

# 🧭 Projenin Nihai Hedefi

SolidTrace şu seviyeye ulaşmayı hedeflemektedir:

    SIEM
    +
    UEBA
    +
    XDR
    +
    SOC Platform

Referans ürünler:

-   Splunk
-   Microsoft Sentinel
-   Elastic Security
-   Wazuh

------------------------------------------------------------------------

# 👨‍💻 Proje Sahibi

Yunus Yıldız\
https://github.com/yyunusyildizz/solidtrace

------------------------------------------------------------------------

# 📄 License

MIT License
