use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::thread; // Uyku modu için
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::sync::mpsc::channel;
use crate::api_client::ApiClient;

// TUZAK KLASÖRÜ
const CANARY_DIR: &str = r"C:\Users\Public\SolidTrace_Honeypot";

pub async fn deploy_and_watch(client: Arc<ApiClient>) {
    println!("🐤 [CANARY] Tuzak Klasörü: {}", CANARY_DIR);

    // 1. Başlangıçta klasörü ve dosyayı oluştur
    setup_honeypot_force();

    let (tx, rx) = channel();
    
    // İzleyiciyi başlat
    let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
        Ok(w) => w,
        Err(e) => {
            println!("⚠️ [CANARY] Watcher hatası: {}", e);
            return;
        }
    };

    if let Err(e) = watcher.watch(Path::new(CANARY_DIR), RecursiveMode::Recursive) {
        println!("⚠️ [CANARY] Path hatası: {}", e);
        return;
    }

    println!("✅ [CANARY] GÖZLER AÇIK! Klasördeki HER HAREKET izleniyor...");

    // 5. Olay Döngüsü
    for res in rx {
        match res {
            Ok(event) => {
                // Olayı işle
                handle_event_smart(event, client.clone()).await;
            },
            Err(e) => println!("⚠️ [CANARY] Hata: {:?}", e),
        }
    }
}

// Zorla oluştur (Başlangıç için)
fn setup_honeypot_force() {
    if !Path::new(CANARY_DIR).exists() {
        let _ = fs::create_dir_all(CANARY_DIR);
    }
    let p1 = format!("{}\\passwords.txt", CANARY_DIR);
    
    if !Path::new(&p1).exists() {
        if let Ok(mut f) = File::create(&p1) {
            let _ = f.write_all(b"admin:123456\nroot:toor\nfacebook:12345");
            println!("🔨 [REPAIR] passwords.txt yeniden oluşturuldu.");
        }
    }
}

// AKILLI ANALİZ VE İYİLEŞTİRME
async fn handle_event_smart(event: Event, client: Arc<ApiClient>) {
    let paths_str = format!("{:?}", event.paths);
    
    if paths_str.contains("passwords.txt") {
        
        match event.kind {
            EventKind::Access(_) => {
                // Sadece okuma - Alarm verme
            },
            _ => {
                println!("🔥 [RANSOMWARE] KRİTİK MÜDAHALE TESPİT EDİLDİ!");
                
                let details = format!("Honeypot Aktivitesi: {:?} | Dosya: passwords.txt", event.kind);
                let c = client.clone();
                let my_pid = std::process::id(); 

                // Logu gönder
                // canary_monitor.rs (Yaklaşık Satır 90)
tokio::spawn(async move {
    let _ = c.send_event(
        "RANSOMWARE_ACTIVITY", 
        &details, 
        "CRITICAL", 
        my_pid,
        None // 🔥 EKLENDİ: 5. parametre olarak None (Option<String>)
    ).await;
});

                // --- SELF HEALING (KENDİNİ İYİLEŞTİRME) ---
                let file_path = format!("{}\\passwords.txt", CANARY_DIR);
                
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(1));
                    if !Path::new(&file_path).exists() {
                        if let Ok(mut f) = File::create(&file_path) {
                            let _ = f.write_all(b"admin:123456\nroot:toor");
                            println!("✨ [SELF-HEALING] Dosya sihirli bir sekilde geri geldi!");
                        }
                    }
                });
            }
        }
    }
}