# 🛡️ SolidTrace EDR & SOC Platform

![Version](https://img.shields.io/badge/Version-6.1-blue.svg)
![Rust](https://img.shields.io/badge/Agent-Rust-orange.svg)
![Python](https://img.shields.io/badge/Backend-FastAPI-green.svg)
![Next.js](https://img.shields.io/badge/Frontend-Next.js-black.svg)
![AI](https://img.shields.io/badge/AI-Groq_Powered-purple.svg)

SolidTrace, uç noktaları (endpoint) gerçek zamanlı olarak izleyen, gelişmiş tehditleri yapay zeka (AI) ve küresel siber istihbarat kurallarıyla tespit eden kurumsal düzeyde bir **EDR (Endpoint Detection and Response)** ve **SOC (Security Operations Center)** platformudur.

## 🌟 Öne Çıkan Özellikler

* **🦀 Rust Tabanlı Ultra Hızlı Agent:** Düşük CPU/RAM tüketimi ile süreç, ağ, dosya (FIM), USB ve Registry izleme.
* **🧠 Yapay Zeka Destekli Analiz (Groq AI):** Tespit edilen alarmların Groq AI ile otomatik incelenmesi ve SOC analistlerine Türkçe/İngilizce çözüm önerileri sunulması.
* **🎯 SIGMA & YARA Motorları:** Dünyaca kabul görmüş SIGMA kuralları ile davranışsal analiz ve YARA ile bellek/dosya tabanlı zararlı yazılım tespiti.
* **👤 UEBA (Kullanıcı Davranış Analizi):** Makine öğrenmesi algoritmaları ile normal kullanıcı davranışlarından sapmaların (anormalliklerin) anında tespiti.
* **🕸️ Honeypot (Canary):** Fidye yazılımlarını (Ransomware) anında tespit edip izole etmek için tuzak dosyalar.
* **⚡ Gerçek Zamanlı Dashboard:** WebSockets üzerinden milisaniyelik gecikmeyle akan SOC ekranı (Next.js).

## 🏗️ Mimari

1. **Agent (Rust):** Uç noktalara kurulur, telemetri toplar ve YARA taramaları yapar.
2. **Backend (Python/FastAPI):** Gelen verileri alır, Korelasyon, SIGMA ve UEBA motorlarından geçirir. Veritabanına (PostgreSQL) yazar.
3. **Frontend (Next.js):** Güvenlik analistleri için karanlık mod (Dark Mode) destekli, canlı izleme ve raporlama arayüzü.

## 🚀 Kurulum ve Çalıştırma

### 1. Backend (Python Sunucusu)
```bash
cd backend
python -m venv .venv
# Windows için: .venv\Scripts\activate
# Linux/Mac için: source .venv/bin/activate
pip install -r requirements.txt
python api_advanced.py
2. Frontend (SOC Arayüzü)
Bash
cd frontend
npm install
npm run dev
3. Agent (Rust Kalkanı)
Bash
cd agent_rust
cargo run --release