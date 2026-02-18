use sysinfo::{ProcessExt, System, SystemExt, PidExt};
use std::time::Duration;
use std::sync::Arc;
use crate::api_client::ApiClient;
use std::collections::HashSet;
// Path kütüphanesine gerek kalmadı, sildik.

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("👁️ [EDR] Process Monitor Başlatıldı (Path Verification Active)...");

    let mut sys = System::new_all();
    let mut known_pids: HashSet<u32> = HashSet::new();

    // Başlangıç anındaki süreçleri "Bilinen" olarak işaretle (Sistemi yormamak için)
    sys.refresh_processes();
    for (pid, _) in sys.processes() {
        known_pids.insert(pid.as_u32());
    }

    loop {
        // CPU Tasarrufu: 1.5 Saniyede bir kontrol (Yeterince hızlı)
        tokio::time::sleep(Duration::from_secs_f32(1.5)).await;
        
        sys.refresh_processes();

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();

            if !known_pids.contains(&pid_u32) {
                let name = process.name().to_string();
                let name_lower = name.to_lowercase();
                
                // 🔥 DÜZELTME BURASI: 
                // .unwrap_or(...) KULLANMIYORUZ. Direkt string'e çeviriyoruz.
                let exe_path = process.exe().to_string_lossy().to_string().to_lowercase();

                // 🛡️ AKILLI FİLTRE (PRODUCTION GRADE)
                let is_safe = is_legit_system_process(&name_lower, &exe_path);

                if is_safe {
                    // Güvenli ve gürültülü süreç, loglama yapma, sadece listeye al.
                    known_pids.insert(pid_u32);
                    continue; 
                }

                // Eğer buraya geldiyse ya normal bir programdır (Notepad) ya da Masquerading yapan bir virüstür.
                
                let mut severity = "INFO";
                let mut alert_msg = format!("Yeni Süreç: {} (PID: {})", name, pid_u32);

                // 🚨 MASQUERADING TESPİTİ (Sahte Sistem Dosyası)
                // Adı 'svchost' ama yolu System32 değilse YAKALA!
                if (name_lower == "svchost.exe" || name_lower == "explorer.exe" || name_lower == "winlogon.exe") 
                   && !exe_path.contains("windows\\system32") 
                   && !exe_path.contains("windows\\explorer.exe") { // Explorer istisnası
                    
                    severity = "CRITICAL";
                    alert_msg = format!("🚨 PROCESS MASQUERADING TESPİTİ!\nZararlı Sistem Süreci Taklidi Yapıyor!\nAd: {}\nYol: {}", name, exe_path);
                    println!("{}", alert_msg);
                }

                println!("⚡ [YENİ] {} -> {}", name, exe_path);
                
                let client_clone = client.clone();
                let msg_clone = alert_msg.clone();
                
                tokio::spawn(async move {
                    let _ = client_clone.send_event(
                        "PROCESS_CREATED", 
                        &msg_clone, 
                        severity, 
                        pid_u32,
                        None 
                    ).await;
                });

                known_pids.insert(pid_u32);
            }
        }
    }
}

// 🛡️ WHITELIST LOGIC
fn is_legit_system_process(name: &str, path: &str) -> bool {
    // 1. Chrome / Edge Sekmeleri (Genelde Program Files içindedir)
    if (name == "chrome.exe" || name == "msedge.exe") && path.contains("program files") {
        return true; 
    }

    // 2. Sistem Servisleri (MUTLAKA System32 içinde olmalı)
    if (name == "svchost.exe" || 
        name == "conhost.exe" || 
        name == "searchui.exe" || 
        name == "wudfhost.exe" || 
        name == "taskhostw.exe" || 
        name == "runtimebroker.exe" ||
        name == "lsass.exe" ||
        name == "services.exe") && path.contains("windows\\system32") {
        return true;
    }

    // 3. System Idle Process (PID 0) ve System (PID 4)
    if name == "system idle process" || name == "system" {
        return true;
    }

    false // Diğer her şey loglanmalı
}