# 🛡️ SolidTrace EDR (Endpoint Detection & Response)

![Status](https://img.shields.io/badge/Status-Beta_v6.2-blue)
![Security](https://img.shields.io/badge/Security-Rust_Powered-orange)
![Dashboard](https://img.shields.io/badge/Dashboard-Next.js-black)

**SolidTrace**, modern tehditlere karşı geliştirilmiş, hafif, hızlı ve yapay zeka destekli bir EDR (Uç Nokta Tehdit Algılama ve Yanıt) çözümüdür. Rust tabanlı ajanı ile sistem kaynaklarını tüketmeden izleme yapar, Python/FastAPI backend'i ile verileri işler ve React tabanlı modern arayüzü ile operatöre sunar.

## 🚀 Özellikler

-   **👁️ Gerçek Zamanlı Süreç İzleme (Process Monitor):** Bellekte çalışan her süreci analiz eder, *Masquerading* (svchost taklidi yapan virüsler) saldırılarını yakalar.
-   **📁 FIM (File Integrity Monitoring):** Kritik sistem dosyalarını (hosts vb.) ve kullanıcı alanlarını (Desktop, Downloads) anlık izler.
-   **🔥 Ransomware Koruması (Heuristic):** Saniyede belirli sayıda dosya değişimi olursa (şifreleme saldırısı) işlemi tespit eder ve alarm verir.
-   **🔌 USB & Donanım Takibi:** Sisteme takılan USB cihazları anında raporlar.
-   **🧬 YARA Tarama Motoru:** Dosyaları imza tabanlı (YARA kuralları) tarayarak bilinen tehditleri engeller.
-   **🧠 Yapay Zeka Destekli Analiz:** Logları analiz ederek operatöre risk skoru sunar.
-   **🔐 Güvenli İletişim:** Ajan ve Sunucu arasında Token tabanlı ve Key korumalı iletişim.

## 🏗️ Mimari

Proje 3 ana bileşenden oluşur:

1.  **Agent (Rust):** Uç noktada çalışan, veriyi toplayan ve emirleri uygulayan motor.
2.  **Core (Python/FastAPI):** Veritabanı, API yönetimi ve AI analiz merkezi.
3.  **SOC Dashboard (Next.js/React):** Güvenlik analistleri için canlı izleme ekranı.

## 🛠️ Kurulum

### Gereksinimler
-   Rust (Cargo)
-   Python 3.9+
-   Node.js & npm

### 1. Backend (Sunucu) Kurulumu
```bash
cd backend
pip install -r requirements.txt
python api_advanced.py