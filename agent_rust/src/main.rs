// #![windows_subsystem = "windows"]  // Siyah ekranı gizlemek için bu satırı aç

mod agent_config;
mod tls_pinning;
mod integrity;
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
mod event_log_monitor;

use std::env;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use api_client::ApiClient;
use agent_config::AgentConfig;
use integrity::Watchdog;
use is_elevated::is_elevated;
use tokio::time::sleep;
use winreg::enums::*;
use winreg::RegKey;

async fn heartbeat_loop(watchdog: Arc<Watchdog>, task_name: &'static str, interval_secs: u64) {
    loop {
        watchdog.heartbeat(task_name).await;
        sleep(Duration::from_secs(interval_secs)).await;
    }
}

fn request_elevation() {
    let exe_path = match env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("❌ [SYSTEM] current_exe alınamadı: {}", e);
            std::process::exit(1);
        }
    };

    let exe_path_str = exe_path.display().to_string();

    let _ = Command::new("powershell")
        .arg("Start-Process")
        .arg("-FilePath")
        .arg(format!("\"{}\"", exe_path_str))
        .arg("-Verb")
        .arg("RunAs")
        .spawn();

    std::process::exit(0);
}

fn enable_persistence() -> std::io::Result<()> {
    let current_exe = env::current_exe()?;
    let path_string = current_exe.to_string_lossy().to_string();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = std::path::Path::new("Software")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Run");

    if let Ok((key, _)) = hkcu.create_subkey(&run_path) {
        let _ = key.set_value("SolidTraceAgent", &path_string);
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    if !is_elevated() {
        println!("⚠️  [SYSTEM] Admin izni alınıyor...");
        request_elevation();
        return;
    }

    println!("============================================");
    println!("    SOLIDTRACE AGENT v31.0 (SECURE)         ");
    println!("    Response + Telemetry + Watchdog         ");
    println!("============================================");

    integrity::run_security_checks().await;

    let cfg = AgentConfig::get();

    println!("⚙️  [CONFIG] Server : {}", cfg.server_base);
    println!("⚙️  [CONFIG] WS     : {}", cfg.ws_base);
    println!("⚙️  [CONFIG] Queue  : {}", cfg.queue_path.display());
    println!("⚙️  [CONFIG] Rules  : {}", cfg.rules_path.display());

    let rules_path_string = cfg.rules_path.to_string_lossy().to_string();

    println!("🌐 [UPDATER] Küresel tehdit veritabanı kontrol ediliyor...");
    if let Err(e) = updater::update_yara_rules(&rules_path_string).await {
        println!("⚠️  [UPDATER] Güncelleme atlandı (yerel kurallar aktif): {}", e);
    }

    match enable_persistence() {
        Ok(_) => println!("✅ [SYSTEM] Persistence aktif."),
        Err(e) => println!("⚠️  [SYSTEM] Persistence hatası: {}", e),
    }

    let client = Arc::new(ApiClient::new());

    let (watchdog, _wd_handle) = Watchdog::spawn(300);
    let watchdog = Arc::new(watchdog);

    // WebSocket command loop
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "ws_listener", 60));

            loop {
                c.connect_and_listen().await;
                wd.heartbeat("ws_listener").await;
                sleep(Duration::from_secs(5)).await;
            }
        });
    }

    // Process monitor
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "process_monitor", 60));
            process_monitor::run_monitor(c).await;
        });
    }

    // File monitor
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "file_monitor", 60));
            file_monitor::run_monitor(c).await;
        });
    }

    // USB monitor
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "usb_monitor", 60));
            usb_monitor::run_monitor(c).await;
        });
    }

    // Registry monitor
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "registry_monitor", 60));
            registry_monitor::run_monitor(c).await;
        });
    }

    // Canary monitor
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "canary_monitor", 60));
            canary_monitor::deploy_and_watch(c).await;
        });
    }

    // Network monitor
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "network_monitor", 60));
            network_monitor::run_monitor(c).await;
        });
    }

    // Event log monitor
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "event_log_monitor", 60));
            event_log_monitor::run_monitor(c).await;
        });
    }

    // Deep scanner loop
    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "deep_scanner", 60));

            loop {
                let c2 = Arc::clone(&c);
                let scan_handle = tokio::spawn(async move {
                    scanner::run_deep_scan(c2).await;
                });

                match scan_handle.await {
                    Ok(_) => {
                        println!("✅ [SCAN] Tarama tamamlandı.");
                        wd.heartbeat("deep_scanner").await;
                        sleep(Duration::from_secs(600)).await;
                    }
                    Err(e) => {
                        eprintln!("⚠️  [SCAN] Tarama task'ı panic ile sonlandı: {:?}", e);
                        eprintln!("   YARA/scanner katmanı sorun yaşadı; diğer modüller aktif kalıyor.");
                        wd.heartbeat("deep_scanner").await;
                        sleep(Duration::from_secs(300)).await;
                    }
                }
            }
        });
    }

    // YARA updater loop
    {
        let wd = Arc::clone(&watchdog);
        let rules_path_for_loop = rules_path_string.clone();

        tokio::spawn(async move {
            tokio::spawn(heartbeat_loop(Arc::clone(&wd), "updater", 60));

            loop {
                if let Err(e) = updater::update_yara_rules(&rules_path_for_loop).await {
                    eprintln!("⚠️  [UPDATER] Periyodik güncelleme başarısız: {}", e);
                }
                wd.heartbeat("updater").await;
                sleep(Duration::from_secs(3600)).await;
            }
        });
    }

    println!("✅ [SYSTEM] TÜM ANA MODÜLLER AKTİF. NÖBET BAŞLADI.");

    loop {
        sleep(Duration::from_secs(60)).await;
    }
}