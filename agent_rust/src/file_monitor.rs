use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config, EventKind};
use std::path::Path;
use tokio::sync::mpsc;
use std::time::{Duration, Instant}; // Artık bunlar kullanılıyor!
use std::sync::Arc;
use crate::api_client::ApiClient;
use crate::scanner;

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("🛡️ [FIM] Akıllı Dosya Bütünlük Motoru Aktif (Ransomware Korumalı)...");

    let (tx, mut rx) = mpsc::channel(100);

    let mut watcher: RecommendedWatcher = Watcher::new(move |res| {
        if let Ok(event) = res {
            let _ = tx.blocking_send(event);
        }
    }, Config::default()).unwrap();

    // 1. İZLENECEK KRİTİK YOLLAR
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        let desktop = format!("{}\\Desktop", user_profile);
        let _ = watcher.watch(Path::new(&desktop), RecursiveMode::Recursive);

        let downloads = format!("{}\\Downloads", user_profile);
        let _ = watcher.watch(Path::new(&downloads), RecursiveMode::Recursive);
        
        let documents = format!("{}\\Documents", user_profile);
        let _ = watcher.watch(Path::new(&documents), RecursiveMode::Recursive);
    }

    // Hosts dosyasını izle
    let hosts_dir = "C:\\Windows\\System32\\drivers\\etc";
    if Path::new(hosts_dir).exists() {
        let _ = watcher.watch(Path::new(hosts_dir), RecursiveMode::NonRecursive);
    }

    // 🔥 RANSOMWARE HEURISTIC DEĞİŞKENLERİ (Eksik olanlar bunlardı)
    let mut change_count = 0;
    let mut last_check = Instant::now();

    while let Some(event) = rx.recv().await {
        for path in event.paths {
            let path_str = path.to_string_lossy().to_string();
            let path_lower = path_str.to_lowercase();

            // --- 🧹 GÜRÜLTÜ FİLTRESİ ---
            if path_lower.contains("appdata") || 
               path_lower.contains("tmp") || 
               path_lower.contains("temp") || 
               path_lower.contains(".log") || 
               path_lower.contains(".ini") ||
               path_lower.contains("~") { 
                continue; 
            }

            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    if path.is_file() {
                        // Sayaç Artır
                        change_count += 1;

                        // 1. HOSTS DOSYASI
                        if path_lower.ends_with("\\hosts") {
                            let msg = format!("🚨 KRİTİK: Hosts dosyası manipüle edildi!\nYol: {}", path_str);
                            let _ = client.send_event("SYSTEM_TAMPERING", &msg, "CRITICAL", 0, None).await;
                            continue;
                        }

                        // 2. DOSYA LOGLAMA (Masaüstü ve Tehlikeli Türler)
                        let is_desktop = path_lower.contains("\\desktop\\");
                        let is_create = matches!(event.kind, EventKind::Create(_));
                        let is_dangerous = path_lower.ends_with(".exe") || 
                                           path_lower.ends_with(".bat") || 
                                           path_lower.ends_with(".ps1") ||
                                           path_lower.ends_with(".vbs");

                        if (is_desktop && is_create) || is_dangerous {
                            println!("📄 [FIM] Dosya Tespit: {}", path_str);
                            
                            let severity = if is_dangerous { "HIGH" } else { "INFO" };
                            let details = format!("Dosya İşlemi: {}", path_str);
                            
                            let _ = client.send_event("FILE_ACTIVITY", &details, severity, 0, None).await;

                            // Tehlikeliyse Hash al
                            if is_dangerous {
                                if let Some(hash) = scanner::get_file_hash(&path) {
                                    let _ = client.report_file_hash(&path_str, &hash, 0).await;
                                }
                            }
                        }
                    }
                },
                _ => {}
            }
        }

        // 🔥 3. RANSOMWARE ANALİZİ (Artık Çalışıyor!)
        // Eğer 2 saniye içinde 20'den fazla dosya değişirse -> ALARM!
        if last_check.elapsed() >= Duration::from_secs(2) {
            if change_count > 20 { 
                let msg = format!("⚠️ RANSOMWARE ŞÜPHESİ: Kısa sürede {} dosya değiştirildi!", change_count);
                println!("🔥 [HEURISTIC] {}", msg);
                let _ = client.send_event("RANSOMWARE_ALERT", &msg, "CRITICAL", 0, None).await;
            }
            // Sayacı sıfırla
            change_count = 0;
            last_check = Instant::now();
        }
    }
}