# 🛡️ SolidTrace EDR & SOC Platform

![Version](https://img.shields.io/badge/Version-6.1-blue.svg)
![Rust](https://img.shields.io/badge/Agent-Rust-orange.svg)
![Python](https://img.shields.io/badge/Backend-FastAPI-green.svg)
![Next.js](https://img.shields.io/badge/Frontend-Next.js-black.svg)
![AI](https://img.shields.io/badge/AI-Groq_Powered-purple.svg)

SolidTrace; endpoint telemetrisi toplayan, güvenlik olaylarını korele eden ve SOC ekipleri için canlı görünürlük sağlayan bir **EDR + SOC platformudur**.

## 🌟 Öne Çıkan Özellikler

- **Rust Agent:** Süreç, ağ, dosya (FIM), USB ve registry izleme.
- **FastAPI Backend:** Alarm toplama, korelasyon, Sigma ve UEBA işleme.
- **Next.js Frontend:** Canlı SOC paneli ve operasyon ekranları.
- **Threat Intel / AI Entegrasyonu:** OTX + Groq tabanlı analiz akışları.

## 🧱 Mimari

1. **Agent (Rust):** Endpoint üzerinde telemetri üretir.
2. **Backend (FastAPI):** Veriyi işler, alarm üretir, WebSocket ile yayınlar.
3. **Frontend (Next.js):** Analist ekranında alarm ve metrikleri gösterir.

## 📁 Proje Yapısı (özet)

```text
solidtrace/
├── agent_rust/         # Endpoint agent
├── backend/            # FastAPI + detection engines
├── frontend/           # Next.js SOC UI
├── ANALIZ_RAPORU.md    # Teknik analiz raporu
└── docs/               # İyileştirme planları / teknik dokümanlar
```

## ⚙️ Gereksinimler

- **Python 3.10+**
- **Node.js 20+**
- **Rust stable toolchain**

## 🚀 Hızlı Başlangıç

### 1) Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # ihtiyaca göre düzenleyin
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 2) Frontend

```bash
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```

### 3) Rust Agent

```bash
cd agent_rust/src
cargo run --release
```

## 🔐 Ortam Değişkenleri

- Backend için örnek dosya: `backend/.env.example`
- Frontend için örnek dosya: `frontend/.env.local.example`

## 🧭 İleriye Taşıma Planı

`ANALIZ_RAPORU.md` içindeki bulguları aksiyona çevirmek için detaylı plan:

- `docs/ILERI_TASIMA_PLANI.md`

## ⚠️ Notlar

- Bu repo geliştirme aşamasındadır; bazı frontend sayfalarında lint hataları bulunabilir.
- Üretim kullanımı için kimlik doğrulama/secret yönetimi ve CI kalite kapıları sıkılaştırılmalıdır.
