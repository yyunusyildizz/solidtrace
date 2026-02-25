# 🛡️ SolidTrace: Advanced EDR & Heuristic Defense System

**SolidTrace**, modern siber tehditlere karşı uç noktaları (endpoint) korumak amacıyla geliştirilmiş, düşük kaynak tüketimli ve yüksek görünürlüklü bir **EDR (Endpoint Detection & Response)** çözümüdür. 

<<<<<<< HEAD
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


=======
Sadece bir log toplama aracı değil; davranışsal analiz (heuristics), dosya bütünlük denetimi (FIM) ve süreç doğrulama yeteneklerine sahip entegre bir güvenlik motorudur.



---

## 🏗️ Mimari ve Mühendislik Kararları

Proje, performans ve ölçeklenebilirlik dengesini sağlamak için üç katmanlı bir yapıda kurgulanmıştır:

### 1. 🦀 Agent (Rust - The Sentinel)
Neden Rust? Düşük seviyeli sistem erişimi ve bellek güvenliği (memory safety) nedeniyle seçildi.
- **Düşük Kaynak Tüketimi:** Geleneksel antivirüslerin aksine CPU'yu %1'in altında tutar.
- **Asenkron Motor:** `tokio` kütüphanesi ile log toplama ve tarama işlemlerini birbirini engellemeden (non-blocking) yürütür.
- **Notify tabanlı FIM:** Dosya değişikliklerini sürekli taramak (polling) yerine işletim sistemi seviyesinde (kernel events) dinler.

### 2. 🐍 Backend (FastAPI - The Brain)
- **WebSocket Gateway:** Ajanlardan gelen binlerce veriyi dashboard'a anlık (real-time) akıtır.
- **Rule Engine:** Gelen ham verileri, tanımlı güvenlik kurallarıyla (YARA & SQL) süzerek risk skorlaması yapar.

### 3. ⚛️ Dashboard (Next.js/TS - The Command Center)
- **SOC Focus UI:** Analistlerin "Log Yorgunluğu" (Alert Fatigue) yaşamaması için gelişmiş gürültü filtreleri (Noise Filtering) içerir.
- **Client-Side Slicing:** Arama ve filtreleme işlemleri tarayıcı tarafında yapılarak milisaniyelik hız sunar.

---

## 🔥 Temel Güvenlik Özellikleri (Teknik Derinlik)

### 👁️ Akıllı Süreç Doğrulama (Anti-Masquerading)
Sadece süreç ismine güvenmek en büyük güvenlik açığıdır. SolidTrace, "Masquerading" saldırılarını şu mantıkla engeller:
- **Mantık:** Eğer `svchost.exe` çalışıyorsa, bu dosyanın yolu mutlaka `C:\Windows\System32` olmalıdır. 
- **Tespit:** Eğer bu isimdeki dosya kullanıcı masaüstünden çalıştırılıyorsa, sistem bunu otomatik olarak **CRITICAL** risk olarak işaretler.

### 📁 Davranışsal Ransomware Tespiti (Heuristic Analysis)
İmza tabanlı taramalar sıfırıncı gün (0-day) saldırılarında başarısız olur. 
- **Mantık:** SolidTrace, kritik klasörlerdeki (Desktop, Documents) dosya değişim hızını ölçer.
- **Tespit:** Eğer 2 saniye içinde 20'den fazla dosya üzerinde "Modify" işlemi yapılırsa, bu bir şifreleme saldırısı olarak algılanır ve alarm üretilir.

### 🔍 Akıllı Gürültü Filtreleme (Signal over Noise)
EDR'lerin en büyük sorunu olan gereksiz log kalabalığı, mühendislik seviyesinde çözülmüştür:
- İşletim sisteminin kendi rutinleri (Chrome temp dosyaları, Windows Update logları vb.) ajan seviyesinde elenerek backend trafiği optimize edilir.
>>>>>>> b0baf95 (🚀 EDR Ajanı, Yapay Zeka (Groq) ve Güvenlik Modülleri hatasız olarak ayağa kaldırıldı!)

---

## 🛠️ Teknoloji Yığını

<<<<<<< HEAD
| Katman | Teknoloji | Amaç |
| :--- | :--- | :--- |
| **Agent** | Rust, Tokio, Sysinfo, Notify | Performance & System Level Monitoring |
| **Backend** | Python, FastAPI, SQLite | Data Orchestration & WebSockets |
| **Frontend** | Next.js, TailwindCSS, Lucide | SOC Visualization & Real-time Dash |
| **Analysis** | YARA Engine, AI Heuristics | Threat Intelligence |

---

## 🚀 Kurulum

### 1. Backend (The Brain)
=======
| Bileşen | Teknoloji | Görev |
| :--- | :--- | :--- |
| **Agent Core** | Rust (sysinfo, notify, tokio) | System Monitoring |
| **Scanner** | YARA Engine | Signature Based Detection |
| **Backend** | Python, FastAPI | API & WebSocket Hub |
| **Frontend** | React, Next.js, TailwindCSS | SOC Dashboard |
| **Data Flow** | WebSocket | Real-time Streaming |

---

## 🚀 Kurulum ve Çalıştırma

### 1. Backend
>>>>>>> b0baf95 (🚀 EDR Ajanı, Yapay Zeka (Groq) ve Güvenlik Modülleri hatasız olarak ayağa kaldırıldı!)
```bash
cd backend
pip install -r requirements.txt
python api_advanced.py
