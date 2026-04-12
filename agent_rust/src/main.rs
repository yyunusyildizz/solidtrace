// #![windows_subsystem = "windows"]  // Siyah ekranı gizlemek için bu satırı aç

mod agent_config;
mod tls_pinning;
mod integrity;
mod command_security;
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
use std::future::Future;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use agent_config::AgentConfig;
use api_client::ApiClient;
use integrity::Watchdog;
use is_elevated::is_elevated;
use tokio::time::sleep;
use winreg::enums::*;
use winreg::RegKey;

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

fn spawn_monitored_loop<F, Fut>(
    watchdog: Arc<Watchdog>,
    task_name: &'static str,
    heartbeat_secs: u64,
    restart_delay_secs: u64,
    mut factory: F,
) where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let mut task_handle = Box::pin(tokio::spawn(factory()));
            let mut ticker = tokio::time::interval(Duration::from_secs(heartbeat_secs));

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        watchdog.heartbeat(task_name).await;
                    }
                    result = &mut task_handle => {
                        match result {
                            Ok(_) => {
                                eprintln!("⚠️  [WATCHDOG] '{}' task'ı beklenmedik şekilde sonlandı. Yeniden başlatılıyor.", task_name);
                            }
                            Err(e) => {
                                eprintln!("🔥 [WATCHDOG] '{}' task'ı panic ile sonlandı: {:?}", task_name, e);
                            }
                        }
                        break;
                    }
                }
            }

            sleep(Duration::from_secs(restart_delay_secs)).await;
        }
    });
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

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

    if let Err(e) = tls_pinning::verify_server_tls().await {
        eprintln!("{}", e);
        std::process::exit(1);
    }

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

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "ws_listener", 60, 5, move || {
            let c = Arc::clone(&c);
            async move { c.connect_and_listen().await }
        });
    }

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "process_monitor", 60, 2, move || {
            let c = Arc::clone(&c);
            async move { process_monitor::run_monitor(c).await }
        });
    }

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "file_monitor", 60, 2, move || {
            let c = Arc::clone(&c);
            async move { file_monitor::run_monitor(c).await }
        });
    }

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "usb_monitor", 60, 2, move || {
            let c = Arc::clone(&c);
            async move { usb_monitor::run_monitor(c).await }
        });
    }

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "registry_monitor", 60, 2, move || {
            let c = Arc::clone(&c);
            async move { registry_monitor::run_monitor(c).await }
        });
    }

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "canary_monitor", 60, 2, move || {
            let c = Arc::clone(&c);
            async move { canary_monitor::deploy_and_watch(c).await }
        });
    }

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "network_monitor", 60, 2, move || {
            let c = Arc::clone(&c);
            async move { network_monitor::run_monitor(c).await }
        });
    }

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "event_log_monitor", 60, 2, move || {
            let c = Arc::clone(&c);
            async move { event_log_monitor::run_monitor(c).await }
        });
    }

    {
        let c = Arc::clone(&client);
        let wd = Arc::clone(&watchdog);
        spawn_monitored_loop(wd, "deep_scanner", 60, 5, move || {
            let c = Arc::clone(&c);
            async move {
                scanner::run_deep_scan(c).await;
            }
        });
    }

    {
        let wd = Arc::clone(&watchdog);
        let rules_path_for_loop = rules_path_string.clone();
        tokio::spawn(async move {
            loop {
                wd.heartbeat("updater").await;
                if let Err(e) = updater::update_yara_rules(&rules_path_for_loop).await {
                    eprintln!("⚠️  [UPDATER] Periyodik güncelleme başarısız: {}", e);
                }
                sleep(Duration::from_secs(3600)).await;
            }
        });
    }

    println!("✅ [SYSTEM] TÜM ANA MODÜLLER AKTİF. NÖBET BAŞLADI.");

    loop {
        sleep(Duration::from_secs(60)).await;
    }
}
