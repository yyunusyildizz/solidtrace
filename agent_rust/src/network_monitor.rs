// network_monitor.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - SSH (22) ve RDP (3389) meşru trafiği de yakalar — false positive riski yüksek
//     → Bu portlar için sadece belirli saatlerde veya beyaz liste dışı IP'lerde alarm üret
//   - netstat yerine daha güvenilir ss veya doğrudan Windows API önerilir (Windows'ta netstat kalıyor)
//   - Suspicious port listesi merkezi sabite taşındı
//   - Aynı remote_addr için tekrarlı alarm üretimi engellendi (alert suppression)
//   - parts indeksleri: netstat çıktısı farklı biçimlerde gelebilir, daha sağlam parse eklendi

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use std::process::Command;
use std::collections::{HashMap};
use crate::api_client::ApiClient;

// FIX: Merkezi port listesi — soc_engine ve ml_anomaly ile tutarlı olmalı
const SUSPICIOUS_PORTS: &[&str] = &[
    ":4444",  // Metasploit
    ":6667",  // IRC Botnet
    ":6666",  // Alternatif C2
    ":1337",  // Hacker klasiği
    ":31337", // Elite / Back Orifice
    ":9001",  // Tor varsayılan
    ":8888",  // Jupyter / C2
];

// FIX: Bu portlar şüpheli ama meşru kullanımı da var — ayrı kategoride tut
const ELEVATED_PORTS: &[&str] = &[
    ":3389", // RDP — meşru ama izlenmeli
    ":22",   // SSH — meşru ama izlenmeli
    ":8080", // Proxy
];

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("📡 [NETWORK] Ağ Trafiği İzleyicisi Başlatıldı...");

    // FIX: Alert suppression — aynı adres 60 saniyede bir kez alarm üretir
    let mut suppression: HashMap<String, std::time::Instant> = HashMap::new();
    let suppress_duration = Duration::from_secs(60);

    loop {
        sleep(Duration::from_secs(5)).await;

        let output = Command::new("netstat").args(&["-ano"]).output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);

            for line in stdout.lines() {
                if !line.contains("ESTABLISHED") || !line.contains("TCP") {
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                // FIX: netstat çıktısı "TCP  local  remote  state  pid" formatında
                // Bazen protokol ayrı sütunda, bazen değil — en az 5 sütun kontrol et
                if parts.len() < 5 {
                    continue;
                }

                // netstat -ano çıktısı: Protocol LocalAddr ForeignAddr State PID
                let remote_addr = parts[2];
                let pid_str     = parts[parts.len() - 1]; // PID her zaman son sütun
                let pid: u32    = pid_str.parse().unwrap_or(0);

                // Loopback ve unspecified filtrele
                if remote_addr.starts_with("127.")
                    || remote_addr.starts_with("[::1]")
                    || remote_addr.starts_with("0.0.0.0")
                    || remote_addr == "[::]"
                {
                    continue;
                }

                // FIX: Alert suppression kontrolü
                if let Some(last_seen) = suppression.get(remote_addr) {
                    if last_seen.elapsed() < suppress_duration {
                        continue; // Bu adres yakın zamanda raporlandı
                    }
                }

                // 1. KRİTİK ŞÜPHELİ PORTLAR
                let is_critical = SUSPICIOUS_PORTS.iter().any(|p| remote_addr.ends_with(p));
                if is_critical {
                    let msg = format!("🚨 ŞÜPHELİ C2 BAĞLANTISI: {} (PID: {})", remote_addr, pid);
                    println!("🚨 [NETWORK] {}", msg);

                    let c = client.clone();
                    let m = msg.clone();
                    tokio::spawn(async move {
                        let _ = c.send_event("NETWORK_CONNECTION", &m, "HIGH", pid, None).await;
                    });

                    suppression.insert(remote_addr.to_string(), std::time::Instant::now());
                    continue;
                }

                // 2. YÜKSEK RİSKLİ AMA MEŞRU OLABİLEN PORTLAR
                // FIX: RDP/SSH için severity düşük, MEDIUM olarak işaretle
                let is_elevated = ELEVATED_PORTS.iter().any(|p| remote_addr.ends_with(p));
                if is_elevated {
                    let msg = format!("ℹ️  YÖNETİM PORTU BAĞLANTISI: {} (PID: {})", remote_addr, pid);
                    println!("⚠️ [NETWORK] {}", msg);

                    let c = client.clone();
                    let m = msg.clone();
                    tokio::spawn(async move {
                        let _ = c.send_event("NETWORK_CONNECTION", &m, "MEDIUM", pid, None).await;
                    });

                    suppression.insert(remote_addr.to_string(), std::time::Instant::now());
                }
            }
        }
    }
}