# 🛡️ SolidTrace: Advanced EDR & Heuristic Defense System

![Status](https://img.shields.io/badge/Status-Beta_v6.2-blue)
![Security](https://img.shields.io/badge/Security-Rust_Powered-orange)
![Dashboard](https://img.shields.io/badge/Dashboard-Next.js-black)

**SolidTrace**, modern siber tehditlere karşı uç noktaları (endpoint) korumak amacıyla geliştirilmiş, düşük kaynak tüketimli ve yüksek görünürlüklü bir **EDR (Endpoint Detection & Response)** çözümüdür. 

Geleneksel imza tabanlı sistemlerin ötesine geçerek; süreç doğrulama (Path Verification), davranışsal analiz (Heuristics) ve dosya bütünlük denetimi (FIM) yeteneklerini tek bir çatıda birleştirir.



---

## 🏗️ Mimari ve Mühendislik Kararları

Proje, performans ve güvenliği optimize etmek için üç ana katmanda kurgulanmıştır:

### 1. 🦀 Sentinel Agent (Rust)
Ajan tarafında Rust seçimi, bellek güvenliği ve "Zero-cost Abstractions" ilkesine dayanır.
- **Asenkron Event Loop:** `tokio` kütüphanesi ile log toplama, tarama ve ağ iletişimi birbirini bloklamadan yürütülür.
- **Düşük Kaynak Tüketimi:** Geleneksel güvenlik yazılımlarının aksine, sistem kaynaklarını (CPU/RAM) minimize ederek arka planda görünmez bir koruma sağlar.
- **Kernel-Level Notification:** `notify` kütüphanesi kullanılarak dosya sistemi değişiklikleri "polling" yerine işletim sistemi olayları seviyesinde dinlenir.

### 2. 🧠 Core Engine (Python / FastAPI)
- **Real-time Pipeline:** WebSocket protokolü üzerinden ajanlardan gelen ham verileri milisaniyeler içinde işler.
- **Rule Engine & Scoring:** Gelen her olay, SQL ve YARA tabanlı kural motorundan geçirilerek dinamik bir risk skoru (0-100) atanır.

### 3. 🎮 Command Center (Next.js & TypeScript)
- **SOC Optimized UI:** Analistlerin "Log Yorgunluğu" (Alert Fatigue) yaşamaması için gelişmiş gürültü filtreleme algoritmaları içerir.
- **Client-Side Data Slicing:** Arama ve filtreleme işlemleri tarayıcı tarafında yapılarak devasa log yığınları içinde anlık arama imkanı sunar.

---

## 🔥 Öne Çıkan Güvenlik Yetenekleri

### 👁️ Akıllı Süreç Doğrulama (Anti-Masquerading)
SolidTrace, sadece süreç ismine bakarak karar vermez. Malware yazarlarının en çok kullandığı `svchost.exe`, `explorer.exe` gibi sistem dosyası taklitlerini yakalar.
- **Mantık:** Eğer süreç ismi kritik bir sistem dosyası ise, bu dosyanın **yasal dizini** (örneğin `C:\Windows\System32`) kontrol edilir. Dizini tutarsız olan tüm süreçler **CRITICAL** olarak raporlanır.

### 📁 Davranışsal Ransomware Tespiti (Heuristics)
İmza tabanlı korumanın yetersiz kaldığı 0-day (sıfırıncı gün) saldırılarına karşı hız odaklı bir savunma yapar.
- **Mantık:** Kullanıcı klasörlerindeki (Masaüstü, Belgeler) dosya değişim frekansını ölçer. 
- **Tespit:** 2 saniye içinde 20'den fazla "Modify" işlemi tespit edildiğinde sistem otomatik olarak fidye yazılımı alarmı üretir.

### 🧬 Hibrit Tarama Motoru
- **Signature Based:** YARA kuralları ile bilinen zararlı yazılım imzalarını yakalar.
- **Integrity Monitor (FIM):** Kritik sistem dosyalarının (hosts, drivers vb.) yetkisiz değiştirilmesini anlık izler.



---

## 🛠️ Teknoloji Yığını

| Katman | Teknoloji | Amaç |
| :--- | :--- | :--- |
| **Agent** | Rust, Tokio, Sysinfo, Notify | Performance & System Level Monitoring |
| **Backend** | Python, FastAPI, SQLite | Data Orchestration & WebSockets |
| **Frontend** | Next.js, TailwindCSS, Lucide | SOC Visualization & Real-time Dash |
| **Analysis** | YARA Engine, AI Heuristics | Threat Intelligence |

---

## 🚀 Kurulum

### 1. Backend (The Brain)
```bash
cd backend
pip install -r requirements.txt
python api_advanced.py
