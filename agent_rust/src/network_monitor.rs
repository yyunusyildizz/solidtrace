use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use std::process::Command;
use crate::api_client::ApiClient;

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("📡 [NETWORK] Ağ Trafiği İzleyicisi Başlatıldı...");

    loop {
        // Rakipler ağı saniyede bir taramaz, sistemi yormamak için 5sn bekler.
        sleep(Duration::from_secs(5)).await;

        let output = Command::new("netstat")
            .args(&["-ano"]) 
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            
            for line in stdout.lines() {
                // Sadece kurulu (ESTABLISHED) bağlantılara odaklan
                if line.contains("ESTABLISHED") && line.contains("TCP") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    
                    if parts.len() >= 5 {
                        let remote_addr = parts[2];
                        let pid_str = parts[4];
                        let pid: u32 = pid_str.parse().unwrap_or(0);

                        // Kendi kendine konuşan (Localhost) bağlantıları yoksay (Gürültü Kirliliği Önleme)
                        if remote_addr.starts_with("127.0.0.1") || remote_addr.starts_with("[::1]") || remote_addr.starts_with("0.0.0.0") {
                            continue;
                        }

                        // Kritik Port Kontrolü (Malware genelde bu portları sever)
                        let is_suspicious = remote_addr.ends_with(":4444") || // Metasploit
                                          remote_addr.ends_with(":6667") || // IRC Botnet
                                          remote_addr.ends_with(":3389") || // RDP
                                          remote_addr.ends_with(":22") ||   // SSH
                                          remote_addr.ends_with(":8080");   // Proxy

                        if is_suspicious {
                            let msg = format!("ŞÜPHELİ AĞ BAĞLANTISI: Uzak Sunucu -> {}", remote_addr);
                            println!("🚨 [NETWORK] {}", msg);
                            
                            let client_clone = client.clone();
                            let msg_clone = msg.clone();
                            
                            // Asenkron gönderim (Sistemi kilitlemez)
                            tokio::spawn(async move {
                                // 🔥 BURASI ÖNEMLİ: 5. Parametre (Serial) burada None olmalı çünkü bu bir USB olayı değil.
                                let _ = client_clone.send_event(
                                    "NETWORK_CONNECTION", 
                                    &msg_clone, 
                                    "HIGH", 
                                    pid,
                                    None // <-- Serial No (Ağ olayında yoktur)
                                ).await;
                            });
                        }
                    }
                }
            }
        }
    }
}