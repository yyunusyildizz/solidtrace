// #![windows_subsystem = "windows"]  // Siyah ekranı gizlemek için bu satırı aç

mod agent_config;    // ← YENİ: Merkezi config
mod tls_pinning;     // ← YENİ: TLS sertifika pinning
mod integrity;       // ← YENİ: Binary bütünlük + anti-debug + watchdog
mod api_client;
mod file_monitor;
mod usb_monitor;
mod canary_monitor;
mod isolation_manager;
mod usb_control;
mod registry_monitor;
mod network_monitor;
mod scanner;
mod process_monitor;
mod yara_scanner;
mod updater;

use std::sync::Arc;
use std::time::Duration;
use std::env;
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;
use tokio::time::sleep;

use is_elevated::is_elevated;
use api_client::ApiClient;
use agent_config::AgentConfig;
use integrity::Watchdog;

#[tokio::main]
async fn main() {
    // ── 1. YETKİ KONTROLÜ ────────────────────────────────────────────────────
    if !is_elevated() {
        println!("⚠️  [SYSTEM] Admin izni alınıyor...");
        request_elevation();
        return;
    }

    println!("============================================");
    println!("    SOLIDTRACE AGENT v31.0 (SECURE)        ");
    println!("    Disk Buffer + TLS Pinning + Watchdog   ");
    println!("============================================");

    // ── 2. GÜVENLİK KONTROLLERİ (en başta) ─────────────────────────────────
    // Binary bütünlük + anti-debug + TLS pinning startup check
    integrity::run_security_checks().await;

    // ── 3. CONFIG YÜKLE (hardcoded const YOK) ────────────────────────────────
    let cfg = AgentConfig::get();
    println!("⚙️  [CONFIG] Server: {}", cfg.server_base);
    println!("⚙️  [CONFIG] Kuyruk: {}", cfg.queue_path.display());
    println!("⚙️  [CONFIG] YARA  : {}", cfg.rules_path.display());

    // ── 4. YARA KURAL GÜNCELLEMESİ (relative path) ──────────────────────────
    println!("🌐 [UPDATER] Küresel tehdit veritabanı kontrol ediliyor...");
    if let Err(e) = updater::update_yara_rules(
        cfg.rules_path.to_str().unwrap_or("rules/main.yar")
    ).await {
        println!("⚠️  [UPDATER] Güncelleme atlandı (yerel kurallar aktif): {}", e);
    }

    // ── 5. KALICILIK (PERSISTENCE) ────────────────────────────────────────────
    match enable_persistence() {
        Ok(_)  => println!("✅ [SYSTEM] Persistence aktif."),
        Err(e) => println!("⚠️  [SYSTEM] Persistence hatası: {}", e),
    }

    // ── 6. API CLIENT ─────────────────────────────────────────────────────────
    let client = Arc::new(ApiClient::new());

    // ── 7. WATCHDOG (kritik task'ları izle) ──────────────────────────────────
    // 300 saniye — scanner 600s bekleyebilir, diğer task'lar periyodik çalışır
    let (watchdog, _wd_handle) = Watchdog::spawn(300);
    let watchdog = Arc::new(watchdog);

    // ── 8. ARKA PLAN GÖREVLERİ ───────────────────────────────────────────────

    // A. WebSocket (Komuta Merkezi)
    let c = client.clone();
    let wd = watchdog.clone();
    tokio::spawn(async move {
        loop {
            c.connect_and_listen().await;
            wd.heartbeat("ws_listener").await;
            sleep(Duration::from_secs(1)).await;
        }
    });

    // B. Process Monitor — heartbeat her 60s gönderilir (monitor sonsuz döngü)
    let c = client.clone();
    let wd = watchdog.clone();
    tokio::spawn(async move {
        wd.heartbeat("process_monitor").await; // başlangıç kaydı
        tokio::spawn(async move { loop { sleep(Duration::from_secs(60)).await; wd.heartbeat("process_monitor").await; } });
        process_monitor::run_monitor(c.clone()).await;
    });

    // C. File Monitor
    let c = client.clone();
    let wd = watchdog.clone();
    tokio::spawn(async move {
        wd.heartbeat("file_monitor").await;
        let wd2 = wd.clone();
        tokio::spawn(async move { loop { sleep(Duration::from_secs(60)).await; wd2.heartbeat("file_monitor").await; } });
        file_monitor::run_monitor(c.clone()).await;
    });

    // D. USB Monitor
    let c = client.clone();
    let wd = watchdog.clone();
    tokio::spawn(async move {
        wd.heartbeat("usb_monitor").await;
        let wd2 = wd.clone();
        tokio::spawn(async move { loop { sleep(Duration::from_secs(60)).await; wd2.heartbeat("usb_monitor").await; } });
        usb_monitor::run_monitor(c.clone()).await;
    });

    // E. Registry Monitor
    let c = client.clone();
    let wd = watchdog.clone();
    tokio::spawn(async move {
        wd.heartbeat("registry_monitor").await;
        let wd2 = wd.clone();
        tokio::spawn(async move { loop { sleep(Duration::from_secs(60)).await; wd2.heartbeat("registry_monitor").await; } });
        registry_monitor::run_monitor(c.clone()).await;
    });

    // F. Canary (Ransomware Tuzağı)
    let c = client.clone();
    let wd = watchdog.clone();
    tokio::spawn(async move {
        wd.heartbeat("canary_monitor").await;
        let wd2 = wd.clone();
        tokio::spawn(async move { loop { sleep(Duration::from_secs(60)).await; wd2.heartbeat("canary_monitor").await; } });
        canary_monitor::deploy_and_watch(c.clone()).await;
    });

    // G. Network Monitor
    let c = client.clone();
    let wd = watchdog.clone();
    tokio::spawn(async move {
        wd.heartbeat("network_monitor").await;
        let wd2 = wd.clone();
        tokio::spawn(async move { loop { sleep(Duration::from_secs(60)).await; wd2.heartbeat("network_monitor").await; } });
        network_monitor::run_monitor(c.clone()).await;
    });

    // H. Deep Scanner — YARA panic'ine karşı catch_unwind ile korumalı
    let c = client.clone();
    let wd = watchdog.clone();
    tokio::spawn(async move {
        println!("🚀 [CORE] Derin analiz başlatıldı.");
        loop {
            // YARA/scanner panic'i tüm agent'ı çökertmesin
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Sync wrapper — async fonksiyonu catch_unwind içinde çalıştır
            }));

            // Async tarafı tokio::spawn ile izole et
            let c2 = c.clone();
            let scan_handle = tokio::spawn(async move {
                scanner::run_deep_scan(c2).await;
            });

            match scan_handle.await {
                Ok(_) => {
                    println!("✅ [SCAN] Tarama tamamlandı.");
                }
                Err(e) => {
                    // Task panic'i (YARA WASM hatası dahil) buraya düşer
                    eprintln!("⚠️  [SCAN] Tarama task'ı panic ile sonlandı: {:?}", e);
                    eprintln!("   YARA WASM hatası olabilir — tarama devre dışı, diğer modüller aktif.");
                    // Watchdog'a heartbeat gönder — agent sağlıklı, sadece scanner bozuk
                    wd.heartbeat("deep_scanner").await;
                    // Scanner tekrar deneme aralığını uzat — sürekli crash döngüsü olmasın
                    sleep(Duration::from_secs(300)).await;
                    continue;
                }
            }

            wd.heartbeat("deep_scanner").await;
            // Başarılı tarama sonrası 10 dakika bekle
            sleep(Duration::from_secs(600)).await;

            let _ = result; // suppress unused warning
        }
    });

    println!("✅ [SYSTEM] TÜM MOTORLAR AKTİF. NÖBET BAŞLADI.");

    // Ana thread'i canlı tut
    loop {
        sleep(Duration::from_secs(60)).await;
    }
}

// ─── YARDIMCI FONKSİYONLAR ────────────────────────────────────────────────────

fn request_elevation() {
    let exe_path = env::current_exe().unwrap();
    let _ = Command::new("powershell")
        .arg("Start-Process")
        .arg("-FilePath").arg(format!("\"{}\"", exe_path.display()))
        .arg("-Verb").arg("RunAs")
        .spawn();
    std::process::exit(0);
}

fn enable_persistence() -> std::io::Result<()> {
    let current_exe = env::current_exe()?;
    let path = current_exe.to_str().unwrap();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = std::path::Path::new("Software")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Run");
    if let Ok((key, _)) = hkcu.create_subkey(&run_path) {
        let _ = key.set_value("SolidTraceAgent", &path);
    }
    Ok(())
}
