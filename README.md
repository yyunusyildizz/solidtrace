# 🛡️ SolidTrace Ultimate SOC

SolidTrace Ultimate SOC, modern SOC ekipleri için geliştirilen **algılama + analiz + müdahale** odaklı birleşik bir güvenlik operasyon platformudur.

Bu proje yalnızca log toplayan veya yalnızca dashboard gösteren bir sistem olmayı hedeflemez. Amaç; **endpoint telemetry**, **detection**, **Sigma/UEBA analizi**, **investigation workflow** ve **host response** kabiliyetlerini tek ürün omurgasında birleştirmektir.

Bu README, projeyi ilk kez gören birinin:
- projenin ne olduğunu,
- bugün neyin gerçekten çalıştığını,
- hangi mimariyle kurulduğunu,
- hangi noktaya gelindiğini,
- sırada hangi geliştirmelerin olduğunu,
- ürünün neden anlamlı olduğunu

tek yerden anlayabilmesi için hazırlanmıştır.

---

# 🎯 Proje Amacı

SolidTrace aşağıdaki problem alanlarını çözmek için geliştirilmektedir:

- Endpoint güvenlik telemetrisini merkezi toplamak
- Şüpheli davranışları tespit etmek
- SOC analistlerine gerçek zamanlı görünürlük sağlamak
- Alert’leri anlamlandırmak ve önceliklendirmek
- Analyst workflow’ünü hızlandırmak
- Gerekli durumlarda host üzerinde doğrudan müdahale edebilmek
- Tüm müdahale akışını görünür, denetlenebilir ve raporlanabilir hale getirmek

Kısaca:

**Detect + Investigate + Respond**

---

# 🧠 Ürün Vizyonu

SolidTrace’in nihai hedefi:

- SIEM görünürlüğü
- UEBA davranış analizi
- EDR/XDR benzeri host response
- Analyst workflow ve investigation deneyimi
- Host-centric operasyon görünürlüğü
- Ticari ürün kalitesinde demo ve operasyon kabiliyeti

bir araya getiren, **ticari olarak pazarlanabilir** bir SOC platformu oluşturmaktır.

Hedef ürün sınıfı:
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- Cortex XDR
- SentinelOne
- Splunk / Logsign / QRadar benzeri SOC operasyon ürünleri

Amaç, ilk günden bu ürünlerle aynı olgunlukta olmak değil; aynı problem alanına **rekabetçi ve satılabilir** bir ürün olarak girebilmektir.

---

# 🏗️ Yüksek Seviye Mimari

```text
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
Analytics / UEBA / Sigma
      ↓
SOC Dashboard
      ↓
Response Actions
      ↓
Agent Command Execution
```

Platform katmanları:

- **Agent Layer**
- **API Layer**
- **Detection Layer**
- **Analytics Layer**
- **SOC Visualization Layer**
- **Response / Command Layer**

---

# 🧰 Kullanılan Teknolojiler

## Backend
- FastAPI
- SQLAlchemy
- PostgreSQL
- WebSocket
- Pydantic

## Frontend
- Next.js
- React
- TailwindCSS
- Lucide Icons

## Agent / Endpoint
- Rust
- WebSocket command listener
- Host telemetry collectors
- Isolation / USB control modülleri
- YARA / monitoring / event log bileşenleri

## Detection / Security
- Static risk scoring
- Sigma-like rule engine
- UEBA behavioral analysis
- Correlation yaklaşımı
- Audit logging
- Role based access
- Agent authentication

---

# 📦 Repository Yapısı

```text
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
 │   ├── core/
 │   ├── database/
 │   ├── schemas/
 │   └── main.py

frontend/
 ├── src/
 │   ├── app/
 │   │   └── (soc)
 │   │        ├── dashboard
 │   │        ├── alerts
 │   │        ├── assets
 │   │        ├── activity
 │   │        └── investigations
 │   ├── components/
 │   │   └── soc/
 │   │        ├── layout
 │   │        ├── providers
 │   │        └── ui
 │   └── lib/api

agent_rust/
 ├── src/
 ├── rules/
 └── Cargo.toml
```

---

# ✅ Şu Anda Gerçekten Çalışan Kısımlar

Bu bölüm özellikle önemlidir. Projede bugün doğrulanmış çalışan çekirdek kabiliyetler aşağıdadır.

## 1. Agent → Backend Ingest
- Agent telemetry backend’e gönderilebiliyor
- HTTP ingest auth çalışıyor
- Detection queue tarafından işleniyor
- Legacy agent auth fallback ile geliştirme ortamı kararlı hale getirildi

## 2. Detection Pipeline
- Static rule tabanlı risk üretimi çalışıyor
- Sigma eşleşmeleri risk promotion yapıyor
- UEBA başlangıç seviyesi profil üretimi çalışıyor
- Alert veritabanına yazılıyor
- Detection queue ile asenkron işleme çalışıyor

## 3. Alert Lifecycle
- `open`
- `acknowledged`
- `resolved`
- `reopen`

Alert assignment, analyst notes ve filtering akışı mevcut.

## 4. Command / Response Plane
- Analyst aksiyonları command olarak üretiliyor
- `command_executions` tablosuna kalıcı yazılıyor
- Agent komutu WebSocket üzerinden alıyor
- ACK / RESULT akışı çalışıyor
- Command durumu aşağıdaki yaşam döngüsünde tutuluyor:

```text
queued → received → completed / failed / expired
```

## 5. Host Response
Doğrulanmış çalışan host response kabiliyetleri:

- `ISOLATE_HOST`
- `UNISOLATE_HOST`
- `USB_DISABLE`
- `USB_ENABLE`

Ek olarak:
- Process kill akışı için temel backend/agent hattı hazır
- Host hedefli action gönderimi çalışıyor
- Command persistence ve sonuç görünürlüğü mevcut

## 6. Cleanup / Hygiene
- Duplicate event dedup mekanizması var
- Stale command cleanup worker var
- Final-state idempotency var
- Eski / broken komutlar `expired` olarak kapanabiliyor

## 7. Frontend SOC UX
- Dashboard canlı alert akışı
- Dashboard command history paneli
- Assets ekranında host response actions
- Assets ekranında host bazlı son response geçmişi
- Alerts detail ekranında host response actions
- Alerts detail ekranında last response actions
- Command durum rozetleri (`queued / received / completed / failed / expired`) görünür

---

# 🚀 Bu Zamana Kadar Yapılan Önemli Geliştirmeler

## Backend
- Agent WebSocket endpoint akışı düzeltildi
- Agent’ın yanlış endpoint’e bağlanma sorunu giderildi
- Memory tabanlı command state yerine DB tabanlı persistence kuruldu
- `command_executions` yaşam döngüsü oturtuldu
- ACK / RESULT akışı backend’e işlendi
- Legacy agent auth fallback ile ingest kararlı hale getirildi
- Event dedup eklendi
- Command stale expiration eklendi
- Command update idempotency eklendi
- Sigma eşleşmelerinin gerçek risk promotion üretmesi sağlandı
- Tenant fallback normalizasyonu güçlendirildi

## Agent (Rust)
- `/ws/agent` command kanalı doğrulandı
- Komut parse akışı sağlamlaştırıldı
- Register / ACK / RESULT akışı doğrulandı
- Host isolation çalışır hale getirildi
- USB control çalışır hale getirildi
- WebSocket register ve command alma sorunları düzeltildi
- API client tarafında action’sız mesajların akışı bozmaması sağlandı

## Frontend
- Dashboard operasyon görünürlüğü genişletildi
- Command history paneli eklendi
- Live operations stream command event gösterecek şekilde genişletildi
- Assets ekranına response actions eklendi
- Assets ekranına last response actions eklendi
- Alerts detail response görünürlüğü güçlendirildi
- Alerts queue ve asset kartları analyst odaklı hale getirildi
- Status badge’lere command lifecycle desteği eklendi
- Light/dark mode ve panel premium hissi üzerinde ciddi iyileştirmeler yapıldı

---

# 🖥️ Frontend / SOC Dashboard

SolidTrace arayüzü yalnızca gösterim odaklı değildir; analyst workflow’ü desteklemek üzere evrilmektedir.

## Dashboard
- Metrics overview
- Alert statistics
- Risk scoring
- Live Alert Stream
- Command History
- Risky Assets
- UEBA görünürlüğü

## Alerts
- Alert queue
- Severity / status / search filtreleri
- Assignment
- Notes
- Workflow actions
- Host response actions
- Last host response actions
- Quick response deneyimi için altyapı hazır

## Assets
- Asset inventory
- Heartbeat / status görünürlüğü
- Risk summary
- Host response actions
- Last response actions
- Host-centric analyst operasyon yüzeyi

## Investigations
- Investigation graph
- İleride timeline ve case odaklı daha güçlü hale getirilecek

---

# 🔐 Güvenlik Özellikleri

SolidTrace aşağıdaki güvenlik mekanizmalarını içerir:

- Agent authentication
- Signed / controlled ingest yaklaşımı için temel yapı
- Replay attack protection altyapısı
- Audit logging
- Role based access
- Request ID tracking
- Tenant-aware data model hazırlığı
- Command/action audit görünürlüğü

---

# 📊 Önemli Teknik Bileşenler

## Alert üretimi
Event’ler:
- normalize edilir
- static rules ile skorlanır
- Sigma ile zenginleştirilir
- gerekiyorsa UEBA ve correlation ile daha anlamlı hale gelir
- sonra alert’e dönüşür

## Response modeli
Analyst aksiyonu:
- command üretir
- DB’ye yazılır
- agent’e gider
- sonuç geri döner
- UI ve DB tarafında izlenir

## Asset-centric response
Her host için:
- risk
- alert sayısı
- response actions
- son response history
- last analyst actions

görünürlüğü sağlanmaya başlanmıştır.

---

# 🧪 Test / Doğrulama Mantığı

Bu proje için en önemli doğrulama yaklaşımı, gerçek workflow zincirini uçtan uca test etmektir.

## Doğrulanmış senaryo
1. Agent event gönderir
2. Backend ingest eder
3. Detection çalışır
4. Alert oluşur
5. Analyst ilgili hostu seçer
6. `ISOLATE_HOST` verir
7. Agent uygular
8. Command `completed` olur
9. Analyst `UNISOLATE_HOST` ile geri alır
10. Sonuç DB/UI üzerinde görünür

## Doğrulanmış response örnekleri
- `ISOLATE_HOST` → `completed`
- `UNISOLATE_HOST` → `completed`
- `USB_DISABLE` / `USB_ENABLE` temel akışı çalışır
- Eski bozuk komutlar `expired` olur
- Alert queue ve host kartları üzerinde response görünürlüğü vardır

Bu senaryo projedeki en kritik dönüm noktalarından biridir.

---

# 📈 Yol Haritası

## Faz 1 — Stabil Çekirdek
**Durum:** Büyük ölçüde tamamlandı

- Ingest
- Detection
- Alert üretimi
- Response komut modeli
- Host isolation
- USB control
- Command persistence
- Dashboard / Assets / Alerts response görünürlüğü

## Faz 2 — Host-Centric Operations
**Durum:** Devam ediyor

Hedefler:
- Host detail drawer / page
- Host timeline
- Host bazlı alert + response korelasyonu
- Daha güçlü asset inventory UX
- Analyst için host başına tek ekranda operasyon görünürlüğü

## Faz 3 — Investigation & Case Management
**Durum:** Sıradaki ana geliştirme alanı

Hedefler:
- Investigation timeline
- Case entity
- Case owner / assignee
- Related alerts
- Evidence tracking
- Investigation notes
- Timeline tabanlı analyst deneyimi

## Faz 4 — Noise Reduction & Analyst Quality
**Durum:** Başlangıç seviyesinde

Hedefler:
- Suppression rules
- False positive işaretleme
- Duplicate alert grouping
- Analyst feedback loop
- Risk confidence / prioritization

## Faz 5 — Response Expansion
**Durum:** Kısmen başladı

Hedefler:
- Process kill UI
- Process explorer
- Host process tree
- Forensic package collection
- Gelecekte live response / remote shell benzeri kontrollü kabiliyetler
- USB politikasını daha rafine hale getirme (ör. sadece storage block, HID whitelist)

## Faz 6 — Commercial Hardening
**Durum:** Gelecek aşama

Hedefler:
- Güçlü tenant isolation
- Sıkı role model
- Reporting / export
- Audit surface
- Installer / onboarding polish
- Release discipline
- Demo / empty-state quality
- Git/GitHub release akışı ve sürüm disiplini

---

# 🧭 Bugünkü Ürün Pozisyonu

SolidTrace bugün:
- yalnızca log toplayan bir araç değildir
- yalnızca dashboard değildir
- yalnızca detection motoru değildir

Bugün geldiği noktada SolidTrace:
**algılayabilen, analyst’e görünür kılan ve host üzerinde müdahale edebilen** bir SOC ürün çekirdeğidir.

Bu, projeyi “gelişigüzel güvenlik paneli” seviyesinden çıkarır.

---

# ✅ Rakiplere Göre Konum

Bugün SolidTrace’in rakiplere yaklaşan tarafları:

- Host isolation
- USB control
- Command/result lifecycle
- Analyst-facing response visibility
- Alert-to-response zinciri
- Asset-centric action surface

Rakip ürünlerde de bu tip özellikler beklenen temel response kabiliyetleridir. Bu nedenle bu özellikler “gereksiz kuruntu” değil; tam tersine ürünün rekabetçi olabilmesi için zorunlu tabandır.

---

# 👨‍💻 Geliştirme Yaklaşımı

Bu projede izlenen temel prensipler:

## 1. Önce çalışan çekirdek
İlk hedef, detection + response omurgasını gerçekten çalışır hale getirmekti.

## 2. Sonra görünür ürün yüzeyi
Backend’de çalışan kabiliyetler dashboard, assets ve alerts yüzeyine taşındı.

## 3. Küçük ama anlamlı iterasyonlar
Her geliştirme:
- test edilebilir,
- görünür fayda üreten,
- analyst deneyimini artıran,
- geri dönüşü mümkün olan

küçük parçalar halinde ele alındı.

## 4. “Fancy” özelliklerden önce operasyon kalitesi
Öncelik sırası:
- response visibility
- host action UX
- alert workflow
- command reliability
- suppression / case / investigation

şeklinde tutuldu.

---

# 🧪 Kurulum Mantığı (Yüksek Seviye)

## Backend
- Python virtual environment
- FastAPI / Uvicorn
- PostgreSQL bağlantısı
- `.env` ile auth / db / rate limit / threat intel ayarları

## Frontend
- Node.js
- Next.js dev server
- backend API adresiyle entegrasyon

## Agent
- Rust toolchain
- `.env` ile backend server / ws / agent key ayarı
- agent çalıştırıldığında:
  - host telemetry üretir
  - WebSocket ile komut dinler
  - aksiyonları uygular

---

# ⚠️ Güvenlik ve Operasyon Notları

Bu proje güvenlik ürünü olduğu için aşağıdaki konular kritik önemdedir:

- `.env` içindeki gerçek anahtarlar sızmış kabul edilirse rotate edilmelidir
- Dev fallback (`X-Agent-Key`) production final modeli değildir
- Production hedefinde signed agent auth tercih edilmelidir
- Tenant, role ve audit modeli daha da sıkılaştırılmalıdır
- Live response gibi gelecekteki özellikler çok dikkatli tasarlanmalıdır
- USB control şu an fazla geniş davranıyorsa daha rafine politika modeline taşınmalıdır

---

# 🏁 Bugün İtibarıyla En Önemli Başarı

Bugün itibarıyla projenin en önemli teknik başarısı şudur:

**SolidTrace artık gerçek bir “alert-to-response” zincirine sahiptir.**

Bu şu demektir:
- olay alır
- anlamlandırır
- analyst’e gösterir
- host üzerinde aksiyon alır
- sonucu kaydeder
- bu sonucu UI üzerinden görünür kılar

Bu eşik, projeyi “gelişigüzel güvenlik paneli” seviyesinden çıkarır.

---

# 🔭 Bir Sonraki En Mantıklı Adımlar

Yakın vadede önerilen sıradaki geliştirmeler:

1. **Host Detail Drawer / Page**
2. **Investigation Timeline**
3. **Case Management**
4. **Suppression / False Positive Control**
5. **Process kill / process explorer UI**
6. **Reporting / Export**
7. **Commercial onboarding polish**

---

# 👤 Proje Sahibi

**Yunus Yıldız**  
GitHub: `yyunusyildizz`

---

# 📄 License

MIT License
