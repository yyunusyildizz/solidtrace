# SolidTrace İleriye Taşıma Planı

Bu doküman, `ANALIZ_RAPORU.md` içindeki bulguları uygulanabilir backlog'a dönüştürür.

## Hedef

- Kod tabanını **daha modüler**, **daha test edilebilir** ve **operasyonel olarak daha güvenli** hale getmek.

---

## P0 (1-2 hafta) — Hemen Etki

### 1) Çalıştırma deneyimini standardize et
- [x] README hızlı başlangıç adımlarını düzelt.
- [x] Backend/Frontend için örnek env dosyaları ekle.
- [ ] Tek komutlu dev başlangıç scripti ekle (`make dev` veya `scripts/dev.sh`).

### 2) Frontend SOC ekranını parçala
- [ ] `src/app/soc/page.tsx` dosyasını aşağıdaki şekilde böl:
  - `src/features/soc/components/*`
  - `src/features/soc/hooks/*`
  - `src/features/soc/services/api.ts`
  - `src/features/soc/types.ts`
- [ ] İlk adımda sadece API çağrı katmanını ayır (davranış değişikliği olmadan).

### 3) Backend bootstrap sorumluluklarını ayır
- [ ] `backend/app/main.py` içindeki motor init akışını `app/bootstrap/engines.py` dosyasına taşı.
- [ ] Bildirim kanalını `app/bootstrap/notifications.py` içine al.
- [ ] Startup hatalarında tek formatlı log + metrik üret.

---

## P1 (2-4 hafta) — Kalite Kapıları

### 1) CI kalite kapıları
- [ ] Backend: `pytest`, `ruff`, `mypy` job'ları.
- [ ] Frontend: `npm run lint` + `npm run build`.
- [ ] Agent: `cargo fmt --check`, `cargo clippy`, `cargo test`.

### 2) Test stratejisi
- [ ] Korelasyon kuralları için tablo tabanlı birim testleri.
- [ ] Threat intel için timeout/error path testleri.
- [ ] SOC API client katmanı için mock tabanlı testler.

### 3) Konfigürasyon doğrulama
- [ ] Uygulama açılışında kritik env değişkenlerini doğrulayan bir config modülü ekle.
- [ ] Eksik konfigürasyonda anlamlı hata mesajı üret.

---

## P2 (4+ hafta) — Ölçek ve Gözlemlenebilirlik

### 1) Gözlemlenebilirlik
- [ ] Structured logging (json format) + correlation id.
- [ ] Alarm üretim hattı için temel metrikler (saniyedeki event, queue depth, publish latency).

### 2) Performans
- [ ] WebSocket yayınlarında backpressure ve yavaş istemci koruması.
- [ ] Yoğun event akışında kuyruklama stratejisi (Redis stream veya benzeri).

### 3) Güvenlik sertleştirme
- [ ] Frontend API route'ları için rate limit.
- [ ] LLM route'ları için input boyutu limiti + prompt guardrail.
- [ ] Secret yönetimi için environment yerine secret manager planı.

---

## Önerilen Sprint Sırası

1. **Sprint-1:** P0-1 + P0-2 (dokümantasyon + frontend API katmanı ayrıştırma)
2. **Sprint-2:** P0-3 + P1-1 (backend bootstrap ayrımı + CI)
3. **Sprint-3:** P1-2 + P1-3 (testler + config validation)
4. **Sprint-4:** P2 başlıkları (gözlemlenebilirlik ve ölçek)

---

## Başarı Ölçütleri (KPI)

- Yeni geliştirici setup süresi: **< 20 dakika**
- Frontend lint hatası: **0 kritik error**
- Korelasyon motoru test kapsamı: **>%70**
- Alarm yayın gecikmesi (p95): **< 1 saniye**
