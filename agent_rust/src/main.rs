// 🔥 Siyah ekranı gizlemek istersen başındaki // işaretlerini kaldır.
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
mod updater; // ✅ YENİ: Otomatik İstihbarat Güncelleyici

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
    // 1. Yetki Kontrolü (Admin değilse kendini yükselt)
    if !is_elevated() {
        println!("⚠️ [SYSTEM] Yetkiler yetersiz! Yönetici izni alınıyor...");
        request_elevation();
        return; 
    }

    // 2. Banner ve Başlangıç
    println!("============================================");
    println!("    SOLIDTRACE AGENT v30.0 (CORE_RTP)       ");
    println!("    Intelligence & Global Threat Feed       ");
    println!("============================================");

    // 📌 ADIM 2.5: OTOMATİK İSTİHBARAT GÜNCELLEME (B Şıkkı)
    // Tarama motorları ayağa kalkmadan önce en güncel YARA kurallarını çekiyoruz.
    let rules_path = "D:\\Downloads\\solidtrace-ultimate-main\\rules\\main.yar";
    println!("🌐 [UPDATER] Küresel tehdit veritabanı kontrol ediliyor...");
    if let Err(e) = updater::update_yara_rules(rules_path).await {
        println!("⚠️ [UPDATER] Güncelleme atlandı (Yerel kurallar aktif): {}", e);
    }

    // 3. Kalıcılık (Persistence) Sağla
    match enable_persistence() {
        Ok(_) => println!("✅ [SYSTEM] Başlangıçta çalıştırma (Persistence) aktif."),
        Err(e) => println!("⚠️ [SYSTEM] Persistence hatası: {}", e),
    }
    
    // 4. API İstemcisini Başlat
    let client = Arc::new(ApiClient::new());

    // --- ARKA PLAN GÖREVLERİ (MODÜLLER) ---

    // A. KOMUTA MERKEZİ (WebSocket)
    let c_listen = client.clone();
    tokio::spawn(async move { 
        c_listen.connect_and_listen().await; 
    });

    // B. PROCESS MONITOR (Süreç İzleme)
    let c_proc = client.clone();
    tokio::spawn(async move { 
        process_monitor::run_monitor(c_proc).await; 
    });

    // C. REAL-TIME FILE PROTECTION (Dosya İzleme)
    let c_file = client.clone();
    tokio::spawn(async move { 
        file_monitor::run_monitor(c_file).await; 
    });

    // D. USB DEVICE CONTROL (Donanım)
    let c_usb = client.clone();
    tokio::spawn(async move { 
        usb_monitor::run_monitor(c_usb).await; 
    });

    // E. REGISTRY SENTINEL (Kayıt Defteri)
    let c_reg = client.clone();
    tokio::spawn(async move { 
        registry_monitor::run_monitor(c_reg).await; 
    });

    // F. CANARY (Fidye Yazılımı Tuzağı)
    let c_canary = client.clone();
    tokio::spawn(async move { 
        canary_monitor::deploy_and_watch(c_canary).await; 
    });

    // G. NETWORK TRAFFIC (Ağ İzleme)
    let c_net = client.clone();
    tokio::spawn(async move { 
        network_monitor::run_monitor(c_net).await; 
    });

    // H. BAŞLANGIÇ TARAMASI VE SÜREKLİ ANALİZ (Scanner)
    // Bu modül artık hem boot scan yapıyor hem de loop ile RAM'i izliyor.
    let c_scan = client.clone();
    tokio::spawn(async move {
        println!("🚀 [CORE] Derin analiz ve hibrit tarama motoru başlatıldı.");
        scanner::run_deep_scan(c_scan).await;
    });

    println!("✅ [SYSTEM] TÜM MOTORLAR GÜNCEL VE AKTİF. NÖBET BAŞLADI.");
    
    // Ana thread'i canlı tut
    loop {
        sleep(Duration::from_secs(60)).await;
    }
}

// --- YARDIMCI FONKSİYONLAR ---

fn request_elevation() {
    let exe_path = env::current_exe().unwrap();
    let path_str = exe_path.to_str().unwrap();
    let _ = Command::new("powershell")
        .arg("Start-Process")
        .arg("-FilePath").arg(format!("\"{}\"", path_str))
        .arg("-Verb").arg("RunAs")
        .spawn();
    std::process::exit(0);
}

fn enable_persistence() -> std::io::Result<()> {
    let current_exe = env::current_exe()?; 
    let path = current_exe.to_str().unwrap();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path_run = std::path::Path::new("Software").join("Microsoft").join("Windows").join("CurrentVersion").join("Run");
    
    if let Ok((key, _)) = hkcu.create_subkey(&path_run) {
        let _ = key.set_value("SolidTraceAgent", &path);
    }
    Ok(())
}