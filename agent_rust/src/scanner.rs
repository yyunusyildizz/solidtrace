use sysinfo::{ProcessExt, System, SystemExt, PidExt};
use std::fs::File;
use std::io::{Read, BufReader}; 
use std::sync::Arc;
use std::path::Path;
use sha2::{Sha256, Digest}; 
use lazy_static::lazy_static;
use tokio::time::{sleep, Duration};
use std::collections::HashSet;

use crate::api_client::ApiClient;
use crate::yara_scanner::YaraScanner; 

lazy_static! {
    static ref GLOBAL_SCANNER: Option<YaraScanner> = {
        let rules_path = "D:\\Downloads\\solidtrace-ultimate-main\\rules\\main.yar";
        if Path::new(rules_path).exists() {
            Some(YaraScanner::new(rules_path))
        } else {
            println!("⚠️ [YARA] Kural dosyası bulunamadı, tarama kısıtlı yapılacak.");
            None
        }
    };
}

pub async fn run_deep_scan(client: Arc<ApiClient>) {
    println!("🛡️ [EDR] Akıllı İzleme Modu Aktif. Gürültü filtreleme ve yol analizi devrede...");

    let mut sys = System::new_all();
    let mut reported_pids = HashSet::new();

    loop {
        sys.refresh_processes();
        let mut scanned_count = 0; 
        
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let exe_path = process.exe();
            let path_str = exe_path.to_string_lossy();
            
            if path_str.is_empty() { continue; }

            // 1. ADIM: BEYAZ LİSTE (Gürültü Engelleme)
            if path_str.contains("Asus") || path_str.contains("Windows\\System32") || path_str.contains("solidtrace") { 
                continue; 
            }

            // 2. ADIM: DEMO VİRÜS KONTROLÜ
            if path_str.to_lowercase().contains("test-virus") {
                if !reported_pids.contains(&pid_u32) {
                    // Mesajı daha temiz yaptık
                    let msg = format!("🚨 KRİTİK: Test Virüsü Tespit Edildi! | Yol: {}", path_str);
                    println!("🔥 {}", msg); 
                    let _ = client.send_event("MALWARE_DETECTED", &msg, "CRITICAL", pid_u32, None).await;
                    reported_pids.insert(pid_u32);
                }
                scanned_count += 1;
                continue;
            }

            // 3. ADIM: YARA TARAMASI
            let mut is_threat = false;
            if let Some(rule_name) = check_with_yara(exe_path) {
                if !reported_pids.contains(&pid_u32) {
                    let msg = format!("🔥 TEHDİT: YARA İmzası ({}) | Yol: {}", rule_name, path_str);
                    println!("{}", msg);
                    let _ = client.send_event("MALWARE_DETECTED", &msg, "CRITICAL", pid_u32, None).await;
                    reported_pids.insert(pid_u32);
                }
                is_threat = true;
            }

            // 4. ADIM: NORMAL AKTİVİTE RAPORLAMA (Profesyonel Sadeleştirme)
            if !reported_pids.contains(&pid_u32) {
                if let Some(hash) = get_file_hash(exe_path) {
                    if is_threat {
                         println!("📡 [UPLINK] Tehdit hash'i küresel istihbarat ile doğrulanıyor...");
                    } else {
                         // 🔥 DEĞİŞİKLİK BURADA: Donanım ID'sini sildik, sadece YOLU gönderiyoruz.
                         // Frontend bu path'i alıp içinden dosya adını ayıklayabilir.
                         let details = format!("🚀 Yol: {}", path_str);
                         let _ = client.send_event("PROCESS_START", &details, "INFO", pid_u32, Some(hash.clone())).await;
                    }
                    let _ = client.report_file_hash(&path_str, &hash, pid_u32).await;
                    reported_pids.insert(pid_u32);
                }
            }
            
            scanned_count += 1; 
        }

        // Taranan süreç logu (Uyarıyı giderir)
        if scanned_count > 0 {
            println!("📊 [SCAN] Tur tamamlandı. {} aktif süreç denetlendi.", scanned_count);
        }

        // Hafızayı temiz tut (200 PID'den sonra sıfırla)
        if reported_pids.len() > 200 { reported_pids.clear(); }

        sleep(Duration::from_secs(5)).await;
    }
}

// ... (Yardımcı fonksiyonlar aynı kalıyor) ...
pub fn check_with_yara(path: &Path) -> Option<String> {
    if !path.exists() { return None; }
    if let Some(scanner) = &*GLOBAL_SCANNER {
        return scanner.scan_file(path);
    }
    None
}

pub fn get_file_hash(path: &Path) -> Option<String> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 4096];
    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}