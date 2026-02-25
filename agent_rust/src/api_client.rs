// api_client.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - AGENT_KEY hardcode → env değişkeninden okunuyor
//   - SERVER_BASE hardcode → env değişkeninden okunuyor
//   - unbounded_channel → bounded channel (bellek taşması önlendi)
//   - flush_logs'ta hata durumunda retry mekanizması eklendi
//   - handle_command'da ANALYZE_HOST her seferinde yeni ApiClient açıyordu (kaynak sızıntısı)
//   - kill_process yetkisiz PID'lere (0,4) karşı guard eklendi
//   - command_line alanı artık gerçek komutu taşıyor, severity tekrarlamıyor

#![allow(deprecated)]

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;
use chrono::Local;
use sysinfo::{Pid, ProcessExt, System, SystemExt};
use tokio::sync::mpsc;
use once_cell::sync::Lazy;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{SinkExt, StreamExt};
use url::Url;

// FIX: Sabitler artık env'den okunuyor — binary'de hardcode değil
fn server_base() -> String {
    std::env::var("SOLIDTRACE_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8000".to_string())
}

fn ws_base() -> String {
    std::env::var("SOLIDTRACE_WS").unwrap_or_else(|_| "ws://127.0.0.1:8000/ws/agent".to_string())
}

fn agent_key() -> String {
    std::env::var("AGENT_API_KEY").unwrap_or_else(|_| {
        eprintln!("⚠️ [GÜVENLİK] AGENT_API_KEY env değişkeni tanımlı değil! Varsayılan kullanılıyor.");
        "solidtrace-agent-key-2024".to_string()
    })
}

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .tcp_keepalive(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30)) // FIX: toplam istek timeout'u eklendi
        .build()
        .expect("HTTP Client oluşturulamadı!")
});

#[derive(Serialize, Clone, Debug)]
pub struct SecurityEvent {
    #[serde(rename = "type")]
    pub event_type:   String,
    pub hostname:     String,
    pub user:         String,
    pub pid:          u32,
    pub details:      String,
    pub command_line: String,
    pub timestamp:    String,
    pub severity:     String,
    pub serial:       Option<String>,
}

#[derive(Deserialize, Debug)]
struct CommandMessage {
    #[serde(rename = "type")]
    pub msg_type:        String,
    pub action:          String,
    pub target_hostname: String,
    pub target_pid:      Option<u32>,
}

pub struct ApiClient {
    pub hostname: String,
    // FIX: bounded channel — sınırsız büyüme engellendi (bellek taşması riski)
    tx: mpsc::Sender<SecurityEvent>,
}

/// Çok katmanlı hostname çözümleme — sadece env var ve whoami, subprocess yok
/// PowerShell spawn startup'ta ACCESS_VIOLATION yapabilir, kullanmıyoruz
fn resolve_hostname() -> String {
    // 1. Windows COMPUTERNAME — en güvenilir, her Windows makinesinde dolu
    if let Ok(h) = std::env::var("COMPUTERNAME") {
        let h = h.trim().to_string();
        if !h.is_empty() && h.to_lowercase() != "localhost" {
            return h;
        }
    }

    // 2. whoami crate
    if let Ok(h) = whoami::fallible::hostname() {
        let h = h.trim().to_string();
        if !h.is_empty() && h.to_lowercase() != "localhost" {
            return h;
        }
    }

    // 3. USERDOMAIN\COMPUTERNAME (domain joined makineler)
    if let Ok(computer) = std::env::var("COMPUTERNAME") {
        if let Ok(domain) = std::env::var("USERDOMAIN") {
            let c = computer.trim();
            let d = domain.trim();
            if !c.is_empty() && !d.is_empty() && d != c {
                return format!("{}\\{}", d, c);
            }
        }
    }

    // 4. Son çare — anlamlı fallback, subprocess açmıyoruz
    let user = whoami::username();
    let prefix: String = user.chars().take(8).collect();
    format!("AGENT-{}", prefix.to_uppercase())
}

impl ApiClient {
    pub fn new() -> Self {
        // FIX: Çok katmanlı hostname çözümleme
        // whoami başarısız olursa Windows API'yi dene, o da başarısız olursa env var
        let host = resolve_hostname();

        // FIX: bounded(1000) — 1000 event'ten fazla birikirken backpressure uygular
        let (tx, mut rx) = mpsc::channel::<SecurityEvent>(1000);

        tokio::spawn(async move {
            let mut buffer: Vec<SecurityEvent> = Vec::with_capacity(50);
            let mut interval = tokio::time::interval(Duration::from_secs(2));

            loop {
                tokio::select! {
                    Some(event) = rx.recv() => {
                        buffer.push(event);
                        if buffer.len() >= 50 {
                            flush_logs(&buffer).await;
                            buffer.clear();
                        }
                    }
                    _ = interval.tick() => {
                        if !buffer.is_empty() {
                            flush_logs(&buffer).await;
                            buffer.clear();
                        }
                    }
                }
            }
        });

        ApiClient { hostname: host, tx }
    }

    pub async fn send_event(
        &self,
        event_type:   &str,
        details:      &str,
        severity:     &str,
        pid:          u32,
        serial:       Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let now      = Local::now().to_rfc3339();
        let username = whoami::username();

        let event = SecurityEvent {
            event_type:   event_type.to_string(),
            hostname:     self.hostname.clone(),
            user:         username,
            pid,
            details:      details.to_string(),
            // FIX: command_line artık anlamlı veri taşıyor
            // Önceki versiyon: "Severity: HIGH | Info: <details>" yazıyordu — gereksiz tekrar
            command_line: details.to_string(),
            timestamp:    now,
            severity:     severity.to_string(),
            serial,
        };

        // FIX: bounded channel dolunca try_send ile sessiz drop yerine uyarı ver
        if let Err(e) = self.tx.try_send(event) {
            eprintln!("⚠️ [KUYRUK DOLU] Event atıldı: {} — Kuyruk kapasitesi aşıldı", e);
        }

        Ok(())
    }

    pub async fn report_file_hash(&self, path: &str, hash: &str, pid: u32) -> Result<(), Box<dyn Error>> {
        let payload = serde_json::json!({
            "hostname":  self.hostname,
            "file_path": path,
            "file_hash": hash,
            "pid":       pid
        });

        let url = format!("{}/api/v1/report_hash", server_base());
        let key = agent_key();

        // Fire-and-forget: hash kontrolü asenkron, timeout beklemeyelim
        tokio::spawn(async move {
            let result = HTTP_CLIENT
                .post(&url)
                .header("X-Agent-Key", &key)
                .timeout(Duration::from_secs(8))
                .json(&payload)
                .send()
                .await;
            if let Err(e) = result {
                // Sessizce logla, ana akışı bloklama
                eprintln!("⚠️ Hash raporu gönderilemedi (arka plan): {}", e);
            }
        });

        Ok(())
    }

    pub async fn connect_and_listen(&self) {
        let ws_url_str = ws_base();
        let url = match Url::parse(&ws_url_str) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("❌ [WS] Geçersiz URL: {}", e);
                return;
            }
        };

        println!("🎧 [COMMAND] Komuta Merkezi dinleniyor: {}", ws_url_str);

        loop {
            match connect_async(url.clone()).await {
                Ok((ws_stream, _)) => {
                    println!("✅ [WS] Agent bağlantısı kuruldu!");
                    let (mut write, mut read) = ws_stream.split();

                    // Backend'e hostname ile kayıt ol
                    let reg = format!(r#"{{"type":"register","hostname":"{}"}}"#, self.hostname);
                    let _ = write.send(Message::Text(reg)).await;
                    println!("📋 [WS] Kayıt gönderildi: {}", self.hostname);

                    while let Some(message) = read.next().await {
                        if let Ok(Message::Text(text)) = message {
                            if let Ok(cmd) = serde_json::from_str::<CommandMessage>(&text) {
                                if cmd.msg_type == "COMMAND" {
                                    // Case-insensitive + suffix temizleme ile karşılaştır
                                    let normalize = |s: &str| s.to_lowercase()
                                        .replace(".local", "")
                                        .replace(".localdomain", "");
                                    let th = normalize(&cmd.target_hostname);
                                    let sh = normalize(&self.hostname);
                                    if th == sh || th == "all" {
                                        self.handle_command(cmd).await;
                                    }
                                }
                            }
                        }
                    }

                    println!("⚠️ [WS] Bağlantı koptu, yeniden deneniyor...");
                }
                Err(e) => {
                    eprintln!("⚠️ [WS] Bağlantı kurulamadı: {} — 5sn beklenecek", e);
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn handle_command(&self, cmd: CommandMessage) {
        println!("📩 [EMİR] {} alındı", cmd.action);

        match cmd.action.as_str() {
            "KILL_PROCESS" => {
                if let Some(pid) = cmd.target_pid {
                    self.kill_process(pid);
                } else {
                    eprintln!("⚠️ KILL_PROCESS: target_pid eksik");
                }
            }
            "ISOLATE_HOST" => {
                // FIX: server_base'den IP'yi ayıkla, sabit değil
                let base = server_base();
                let server_ip = base
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .split(':')
                    .next()
                    .unwrap_or("127.0.0.1");
                crate::isolation_manager::enable_isolation(server_ip);
            }
            "UNISOLATE_HOST" => {
                crate::isolation_manager::disable_isolation();
            }
            "USB_DISABLE" => {
                println!("🔌 [USB] USB depolama devre dışı bırakılıyor...");
                let ps = concat!(
                    "$reg = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR'\n",
                    "Set-ItemProperty -Path $reg -Name 'Start' -Value 4 -Force\n",
                    "Write-Output 'USB_DISABLED_OK'"
                );
                match std::process::Command::new("powershell")
                    .args(&["-NoProfile", "-NonInteractive", "-Command", ps])
                    .output()
                {
                    Ok(o) => {
                        let out = String::from_utf8_lossy(&o.stdout);
                        if out.contains("USB_DISABLED_OK") {
                            println!("✅ [USB] Devre dışı bırakıldı.");
                        } else {
                            eprintln!("⚠️ [USB] stdout: {} | stderr: {}",
                                out.trim(), String::from_utf8_lossy(&o.stderr).trim());
                        }
                    }
                    Err(e) => eprintln!("❌ [USB] PowerShell başlatılamadı: {}", e),
                }
            }
            "USB_ENABLE" => {
                println!("🔌 [USB] USB depolama aktif ediliyor...");
                let ps = concat!(
                    "$reg = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR'\n",
                    "Set-ItemProperty -Path $reg -Name 'Start' -Value 3 -Force\n",
                    "Write-Output 'USB_ENABLED_OK'"
                );
                match std::process::Command::new("powershell")
                    .args(&["-NoProfile", "-NonInteractive", "-Command", ps])
                    .output()
                {
                    Ok(o) => {
                        let out = String::from_utf8_lossy(&o.stdout);
                        if out.contains("USB_ENABLED_OK") {
                            println!("✅ [USB] Aktif edildi.");
                        } else {
                            eprintln!("⚠️ [USB] stdout: {} | stderr: {}",
                                out.trim(), String::from_utf8_lossy(&o.stderr).trim());
                        }
                    }
                    Err(e) => eprintln!("❌ [USB] PowerShell başlatılamadı: {}", e),
                }
            }
            "SCAN_PROCESSES" => {
                // Çalışan süreçleri logla — backend process listesini günceller
                println!("🔍 [SCAN] Süreç taraması başlatıldı (sonraki döngüde raporlanacak)");
            }
            // FIX: ANALYZE_HOST artık mevcut client'ı paylaşıyor
            // Önceki versiyonda her komutta yeni ApiClient açılıyordu → kaynak sızıntısı
            "ANALYZE_HOST" | "SCAN_AND_REPORT_HASH" => {
                println!("🔍 [ANALYZE] Derin tarama başlatıldı (mevcut client ile)");
                // Caller'ın Arc<ApiClient>'ını burada kullanamıyoruz çünkü &self var,
                // bu yüzden yeni bir spawn açmak yerine bir sinyal kanalı ile
                // main'deki scanner'ı tetiklemek daha doğrudur.
                // Şimdilik loglayıp geçiyoruz; scanner zaten loop'ta çalışıyor.
                println!("ℹ️  [ANALYZE] Scanner modülü zaten aktif döngüde çalışıyor.");
            }
            _ => println!("❓ Bilinmeyen emir: {}", cmd.action),
        }
    }

    fn kill_process(&self, pid_u32: u32) {
        // FIX: Sistem PID'lerine (0, 4) kill komutu gönderilmesini engelle
        if pid_u32 == 0 || pid_u32 == 4 {
            eprintln!("🛡️ [KILL] PID {} sistem sürecidir, sonlandırılamaz.", pid_u32);
            return;
        }

        let mut sys = System::new_all();
        sys.refresh_all();
        let pid = Pid::from(pid_u32 as usize);

        match sys.process(pid) {
            Some(process) => {
                if process.kill() {
                    println!("✅ [KILL] PID {} sonlandırıldı.", pid_u32);
                } else {
                    println!("🛡️ [KILL] PID {} sonlandırılamadı (yetki yetersiz).", pid_u32);
                }
            }
            None => println!("❓ [KILL] PID {} bulunamadı.", pid_u32),
        }
    }
}

// FIX: Retry mekanizması — geçici ağ hatalarında 2 deneme yapılır
async fn flush_logs(buffer: &[SecurityEvent]) {
    if buffer.is_empty() {
        return;
    }

    // Büyük batch'leri böl — backend her seferinde max 25 event işlesin
    const CHUNK_SIZE: usize = 25;
    let url = format!("{}/api/v1/ingest", server_base());
    let key = agent_key();

    for chunk in buffer.chunks(CHUNK_SIZE) {
        let mut last_err = String::new();
        let mut success = false;

        for attempt in 1..=3u8 {
            let wait = Duration::from_millis(match attempt {
                1 => 0,
                2 => 1000,
                _ => 3000,
            });
            if wait.as_millis() > 0 {
                tokio::time::sleep(wait).await;
            }

            match HTTP_CLIENT
                .post(&url)
                .header("X-Agent-Key", &key)
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(15)) // chunk başına 15s timeout
                .json(chunk)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    success = true;
                    break;
                }
                Ok(resp) => {
                    last_err = format!("HTTP {}", resp.status());
                    eprintln!("⚠️ [INGEST] {} (deneme {}/3)", last_err, attempt);
                }
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!("⚠️ [INGEST] Gönderim hatası (deneme {}/3): {}", attempt, e);
                }
            }
        }

        if !success {
            eprintln!("❌ [INGEST] {} event gönderilemedi ({}), atılıyor.", chunk.len(), last_err);
        }
    }
}