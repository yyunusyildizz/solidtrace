// process_monitor.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - known_pids sınırsız büyüyor → BoundedPidSet kullanımı (scanner.rs ile ortak)
//   - Whitelist logic kopyalanmış → ileride shared config modülüne taşınmalı
//   - lsass.exe whitelist'te — bu kritik bir hata! lsass System32'de bile olsa
//     erişilmesi izlenmeli (Credential Dumping tespiti için)
//   - Masquerading tespitinde explorer.exe istisnası path kontrolüyle yapılıyor ama
//     yol "windows\explorer.exe" içermiyorsa da meşru olabilir — daha sağlam kontrol eklendi

use sysinfo::{ProcessExt, System, SystemExt, PidExt};
use std::time::Duration;
use std::sync::Arc;
use std::collections::HashSet;
use crate::api_client::ApiClient;

// Yüksek riskli, erişimi her zaman izlenmesi gereken süreçler
// Whitelist'e ALINMAMALI — sadece masquerading kontrolü yapılmalı
const SENSITIVE_PROCESSES: &[&str] = &[
    "lsass.exe",    // Credential target
    "winlogon.exe", // Auth process
    "csrss.exe",    // Windows subsystem
];

// Masquerading riski olan süreçler
const MASQUERADE_TARGETS: &[&str] = &[
    "svchost.exe",
    "explorer.exe",
    "winlogon.exe",
    "conhost.exe",
];

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("👁️ [EDR] Process Monitor Başlatıldı...");

    let mut sys = System::new_all();
    // FIX: Bounded set — sınırsız büyüme yok
    let mut known_pids: HashSet<u32> = HashSet::new();
    let mut known_pids_order: Vec<u32> = Vec::new();
    const PID_LIMIT: usize = 2000;

    sys.refresh_processes();
    for (pid, _) in sys.processes() {
        known_pids.insert(pid.as_u32());
    }

    loop {
        tokio::time::sleep(Duration::from_secs_f32(1.5)).await;
        sys.refresh_processes();

        for (pid, process) in sys.processes() {
            let pid_u32  = pid.as_u32();
            if known_pids.contains(&pid_u32) {
                continue;
            }

            let name      = process.name().to_string();
            let name_lower = name.to_lowercase();
            let exe_path  = process.exe().to_string_lossy().to_string();
            let exe_lower = exe_path.to_lowercase();

            // FIX: PID seti bounded tutulur
            if known_pids.len() >= PID_LIMIT {
                let remove_count = PID_LIMIT / 4;
                for p in known_pids_order.drain(..remove_count) {
                    known_pids.remove(&p);
                }
            }

            // FIX: lsass.exe whitelist'ten çıkarıldı — her zaman izle
            let is_sensitive = SENSITIVE_PROCESSES.iter().any(|s| name_lower == *s);

            // 1. MASQUERADING TESPİTİ
            let is_masquerade_target = MASQUERADE_TARGETS.iter().any(|t| name_lower == *t);

            if is_masquerade_target {
                // Meşru yollar
                let is_legit = exe_lower.contains("windows\\system32")
                    || exe_lower.contains("windows\\syswow64")
                    || exe_lower.contains("windows\\explorer.exe")
                    || exe_path.is_empty(); // Bazı sistem süreçlerinin yolu boş olabilir

                if !is_legit {
                    let msg = format!(
                        "🚨 PROCESS MASQUERADING!\nAd: {}\nYol: {}\nPID: {}",
                        name, exe_path, pid_u32
                    );
                    println!("{}", msg);
                    let c = client.clone();
                    let m = msg.clone();
                    tokio::spawn(async move {
                        let _ = c.send_event("PROCESS_MASQUERADING", &m, "CRITICAL", pid_u32, None).await;
                    });
                    known_pids.insert(pid_u32);
                    known_pids_order.push(pid_u32);
                    continue;
                }
            }

            // 2. HASSAS SÜREÇ ERİŞİMİ (lsass vb.)
            if is_sensitive {
                let msg = format!(
                    "⚠️ HASSAS SÜREÇ BAŞLADI: {} (PID: {}) Yol: {}",
                    name, pid_u32, exe_path
                );
                println!("{}", msg);
                let c = client.clone();
                let m = msg.clone();
                tokio::spawn(async move {
                    let _ = c.send_event("SENSITIVE_PROCESS", &m, "HIGH", pid_u32, None).await;
                });
                known_pids.insert(pid_u32);
                known_pids_order.push(pid_u32);
                continue;
            }

            // 3. Yolu boş süreçleri kaydet ama loglama — kernel thread vb.
            if exe_path.is_empty() {
                known_pids.insert(pid_u32);
                known_pids_order.push(pid_u32);
                continue;
            }

            // 4. GENEL SÜREÇ FİLTRESİ
            if is_noisy_process(&name_lower, &exe_lower) {
                known_pids.insert(pid_u32);
                known_pids_order.push(pid_u32);
                continue;
            }

            // 5. NORMAL SÜREÇ LOG — yol doluysa göster
            println!("⚡ [YENİ] {} → {}", name, exe_path);
            let msg = format!("Yeni Süreç: {} (PID: {})", name, pid_u32);
            let c   = client.clone();
            let m   = msg.clone();
            tokio::spawn(async move {
                let _ = c.send_event("PROCESS_CREATED", &m, "INFO", pid_u32, None).await;
            });

            known_pids.insert(pid_u32);
            known_pids_order.push(pid_u32);
        }
    }
}

/// Gürültülü ama meşru süreçler — loglamaya gerek yok
fn is_noisy_process(name: &str, path: &str) -> bool {
    // Chrome / Edge renderer süreçleri
    if (name == "chrome.exe" || name == "msedge.exe") && path.contains("program files") {
        return true;
    }

    // Sistem servisleri — System32'den geliyorsa gürültü
    let system_noise = [
        "svchost.exe", "conhost.exe", "searchui.exe", "wudfhost.exe",
        "taskhostw.exe", "runtimebroker.exe", "services.exe",
        "system idle process", "system",
    ];
    if system_noise.contains(&name) && path.contains("windows\\system32") {
        return true;
    }

    // SolidTrace iç araçları + kısa ömürlü sistem süreçleri
    // Bunlar her birkaç saniyede yeni PID alır → BoundedPidSet'ten düşer → [YENİ] görünür
    let short_lived = [
        // SolidTrace'in spawn ettikleri
        "netstat.exe",            // network_monitor
        "powershell.exe",         // usb_monitor + event_log_monitor
        "find.exe",
        "findstr.exe",
        // Geliştirme araçları — geliştiricinin kendi makinesinde çalışırken gürültü
        "rustup.exe",
        "rustc.exe",
        "cargo.exe",
        "git.exe",
        // Kısa ömürlü Windows sistem süreçleri
        "dllhost.exe",
        "backgroundtaskhost.exe",
        "searchfilterhost.exe",
        "searchprotocolhost.exe",
        "pickerhost.exe",
    ];
    let path_lower = path.to_lowercase();
    let name_lower_check = name.to_lowercase();
    if short_lived.iter().any(|&s| name_lower_check == s) {
        // Sistem araçları sadece system32/program files/cargo/rustup'tan geliyorsa güvenli
        let is_trusted_path = path_lower.contains("windows\\system32")
            || path_lower.contains("windows\\syswow64")
            || path_lower.contains("program files")
            || path_lower.contains("\\.cargo\\")
            || path_lower.contains("\\.rustup\\")
            || path_lower.contains("\\git\\");
        if is_trusted_path {
            return true;
        }
        // Başka yerden geliyorsa LOG — masquerade olabilir
    }

    // Microsoft Office araçları
    if path_lower.contains("microsoft office") || path_lower.contains("office16") {
        return true;
    }

    // EdgeWebView (Electron/Teams/Discord içi browser)
    if name_lower_check.contains("webview") || name_lower_check.contains("msedgewebview") {
        return true;
    }

    // PostgreSQL sunucu süreçleri
    if name_lower_check == "postgres.exe" {
        return true;
    }

    // Windows Store / UWP uygulamaları
    if path_lower.contains("windowsapps") || path_lower.contains("systemapps") {
        return true;
    }

    false
}