// src/process_monitor.rs
use sysinfo::{ProcessExt, System, SystemExt};
use std::collections::HashSet;
use tokio::time::{sleep, Duration};
use crate::api_client::ApiClient;
use std::sync::Arc;

pub async fn run_monitor(api: Arc<ApiClient>) {
    println!("👁️ Process Monitor (Async) Başlatıldı...");
    let mut sys = System::new_all();
    let mut known_pids: HashSet<sysinfo::Pid> = HashSet::new();

    // İlk tarama (Mevcutları yoksay)
    sys.refresh_processes();
    for (pid, _) in sys.processes() {
        known_pids.insert(*pid);
    }

    loop {
        sys.refresh_processes();
        let current_pids: HashSet<sysinfo::Pid> = sys.processes().keys().cloned().collect();

        // Sadece YENİ olanları bul (Process Diffing)
        for pid in &current_pids {
            if !known_pids.contains(pid) {
                if let Some(process) = sys.process(*pid) {
                    let name = process.name();
                    let cmd = process.cmd().join(" ");

                    // Filtreleme (Gürültüyü azalt)
                    let targets = ["cmd", "powershell", "notepad", "python", "mimikatz", "ncat", "netcat"];
                    
                    if targets.iter().any(|t| name.to_lowercase().contains(t)) {
                        println!("⚡ [PROCESS] Yeni Süreç: {} ({})", name, pid);
                        
                        // API'ye bildir
                        api.send_alert("process_creation", &cmd).await;
                    }
                }
            }
        }

        // Listeyi güncelle
        known_pids = current_pids;
        
        // İşlemciyi yormamak için mikro bekleme (100ms)
        sleep(Duration::from_millis(100)).await;
    }
}