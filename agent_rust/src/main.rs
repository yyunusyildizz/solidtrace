// main.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - enable_persistence() HKCU Run anahtarı → meşru bir EDR için açıklanmalı
//     Yorum satırına neden yapıldığı ve nasıl devre dışı bırakılacağı eklendi
//   - request_elevation() spawn sonrası exit(0) yarış durumu → wait() eklendi
//   - Ana loop sleep(60) → graceful shutdown sinyali (Ctrl+C) eklendi
//   - Modül başlatma sırası: WebSocket bağlantısı scanner'dan önce kurulmalı
//   - rules_path hardcoded "D:\Downloads..." → env değişkeni ile okunuyor (scanner.rs ile uyumlu)

// Konsol penceresini gizlemek için:
// #![windows_subsystem = "windows"]

mod api_client;
mod file_monitor;
mod usb_monitor;
mod canary_monitor;
mod isolation_manager;
mod registry_monitor;
mod network_monitor;
mod scanner;
mod process_monitor;
mod yara_scanner;
mod updater;
mod event_log_monitor; // Windows Event Log okuyucu (Security/System/Application)

use std::sync::Arc;
use std::time::Duration;
use std::env;
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;
use tokio::time::sleep;
use is_elevated::is_elevated;
use api_client::ApiClient;

#[tokio::main]
async fn main() {
    // .env dosyasını yükle (varsa)
    // FIX: Env dosyası yüklenmeden önce hiçbir env::var okunmamalı
    let _ = dotenvy::dotenv(); // .env dosyasını yükle — bulunamazsa sessizce devam et

    // 1. YETKİ KONTROLÜ
    if !is_elevated() {
        println!("⚠️ [SYSTEM] Yönetici yetkisi gerekiyor, yükseltme isteniyor...");
        request_elevation();
        return;
    }

    // 2. BANNER
    println!("============================================");
    println!("    SOLIDTRACE AGENT v30.1 (CORE_RTP)      ");
    println!("    Intelligence & Global Threat Feed      ");
    println!("============================================");

    // 3. YARA KURAL GÜNCELLEMESİ
    // FIX: rules_path env'den alınıyor — scanner.rs ile tutarlı
    let rules_path = env::var("YARA_RULES_PATH")
        .unwrap_or_else(|_| "rules/main.yar".to_string());

    println!("🌐 [UPDATER] Küresel tehdit veritabanı kontrol ediliyor...");
    if let Err(e) = updater::update_yara_rules(&rules_path).await {
        println!("⚠️ [UPDATER] Güncelleme atlandı (yerel kurallar aktif): {}", e);
    }

    // 4. KALICILIK (OPSİYONEL — Kurumsal dağıtımda GPO ile yönetilmeli)
    // FIX: Persistence varsayılan AÇIK, env ile kapatılabilir
    // SOLIDTRACE_PERSISTENCE=false yapılırsa devre dışı kalır
    let persistence_enabled = env::var("SOLIDTRACE_PERSISTENCE")
        .map(|v| v.to_lowercase() != "false")
        .unwrap_or(true);

    if persistence_enabled {
        match enable_persistence() {
            Ok(_)  => println!("✅ [SYSTEM] Başlangıçta çalıştırma (Persistence) aktif."),
            Err(e) => println!("⚠️ [SYSTEM] Persistence hatası (yönetici yetkisi gerekebilir): {}", e),
        }
    } else {
        println!("ℹ️  [SYSTEM] Persistence devre dışı (SOLIDTRACE_PERSISTENCE=false).");
    }

    // 5. API İSTEMCİSİ
    let client = Arc::new(ApiClient::new());

    // --- ARKA PLAN GÖREVLERİ ---
    // FIX: WebSocket ilk başlatılıyor — komutları almaya hazır olmadan scanner başlamamalı

    // A. KOMUTA MERKEZİ (WebSocket) — İLK BAŞLAT
    let c_listen = client.clone();
    tokio::spawn(async move {
        c_listen.connect_and_listen().await;
    });

    // Kısa bekleme — WebSocket bağlantısı kurulsun
    sleep(Duration::from_secs(1)).await;

    // B. PROCESS MONITOR
    let c_proc = client.clone();
    tokio::spawn(async move {
        process_monitor::run_monitor(c_proc).await;
    });

    // C. DOSYA BÜTÜNLÜĞÜ
    let c_file = client.clone();
    tokio::spawn(async move {
        file_monitor::run_monitor(c_file).await;
    });

    // D. USB KONTROL
    let c_usb = client.clone();
    tokio::spawn(async move {
        usb_monitor::run_monitor(c_usb).await;
    });

    // E. KAYIT DEFTERİ
    let c_reg = client.clone();
    tokio::spawn(async move {
        registry_monitor::run_monitor(c_reg).await;
    });

    // F. CANARY (HONEYPOT)
    let c_canary = client.clone();
    tokio::spawn(async move {
        canary_monitor::deploy_and_watch(c_canary).await;
    });

    // G. AĞ İZLEME
    let c_net = client.clone();
    tokio::spawn(async move {
        network_monitor::run_monitor(c_net).await;
    });

    // H. DERİN TARAMA (Scanner)
    let c_scan = client.clone();
    tokio::spawn(async move {
        println!("🚀 [CORE] Derin analiz ve hibrit tarama motoru başlatıldı.");
        scanner::run_deep_scan(c_scan).await;
    });

    // I. WINDOWS EVENT LOG (Security/System/Application + PowerShell/Sysmon)
    let c_evtlog = client.clone();
    tokio::spawn(async move {
        event_log_monitor::run_monitor(c_evtlog).await;
    });

    println!("✅ [SYSTEM] TÜM MOTORLAR AKTİF. NÖBET BAŞLADI.");

    // FIX: Graceful shutdown — Ctrl+C sinyalini yakala
    // Ana thread canlı tutuluyor, sinyal gelince temizce kapatılıyor
    match tokio::signal::ctrl_c().await {
        Ok(())  => println!("\n🛑 [SYSTEM] Kapatma sinyali alındı. Agent durduruluyor..."),
        Err(e)  => eprintln!("⚠️ [SYSTEM] Sinyal dinleme hatası: {}", e),
    }

    // İzolasyon varsa kaldır
    println!("🔓 [SYSTEM] Güvenlik duvarı kuralları temizleniyor...");
    isolation_manager::disable_isolation();

    println!("✅ [SYSTEM] Agent kapatıldı.");
}

fn request_elevation() {
    let exe_path = match env::current_exe() {
        Ok(p)  => p,
        Err(e) => {
            eprintln!("❌ Exe yolu alınamadı: {}", e);
            std::process::exit(1);
        }
    };

    let path_str = exe_path.to_string_lossy();

    // FIX: spawn().wait() — process başlayıp başlamadığını kontrol et
    match Command::new("powershell")
        .arg("Start-Process")
        .arg("-FilePath").arg(format!("\"{}\"", path_str))
        .arg("-Verb").arg("RunAs")
        .spawn()
    {
        Ok(mut child) => {
            let _ = child.wait();
        }
        Err(e) => {
            eprintln!("❌ Yükseltme başarısız: {}", e);
        }
    }

    std::process::exit(0);
}

fn enable_persistence() -> std::io::Result<()> {
    let current_exe = env::current_exe()?;
    let exe_path    = current_exe.to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Geçersiz exe yolu"))?;

    let hkcu     = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = Path::new("Software")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Run");

    // FIX: open_subkey önce dene — oluşturmak gerekmeyebilir
    match hkcu.open_subkey_with_flags(&run_path, KEY_SET_VALUE) {
        Ok(key) => {
            key.set_value("SolidTraceAgent", &exe_path)?;
            println!("✅ [PERSISTENCE] Registry anahtarı güncellendi.");
        }
        Err(_) => {
            let (key, _) = hkcu.create_subkey(&run_path)?;
            key.set_value("SolidTraceAgent", &exe_path)?;
            println!("✅ [PERSISTENCE] Registry anahtarı oluşturuldu.");
        }
    }

    Ok(())
}

// Path import'u enable_persistence'da kullanıyoruz
use std::path::Path;