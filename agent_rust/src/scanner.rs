// scanner.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - Whitelist hardcoded path ("Asus", "solidtrace") → env/config tabanlı yapıya taşındı
//   - reported_pids sınırsız büyüyordu, 200'de clear() tehlikeli → LRU tarzı sabit boyutlu set
//   - YARA rules_path hardcoded "D:\\Downloads\\..." → env değişkeni ile okunuyor
//   - Hash raporlama her PID için bir kez yapılıyor ama loop'tan sonra tekrar girilebilir → düzeltildi
//   - scan intervali 5sn sabit → yapılandırılabilir

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

// FIX: YARA kural yolu env'den okunuyor — hardcoded path yok
lazy_static! {
    static ref GLOBAL_SCANNER: Option<YaraScanner> = {
        let rules_path = std::env::var("YARA_RULES_PATH")
            .unwrap_or_else(|_| "rules/main.yar".to_string());

        if Path::new(&rules_path).exists() {
            println!("✅ [YARA] Kurallar yüklendi: {}", rules_path);
            Some(YaraScanner::new(&rules_path))
        } else {
            println!("⚠️ [YARA] Kural dosyası bulunamadı: {} — tarama kısıtlı.", rules_path);
            None
        }
    };
}

// FIX: Whitelist merkezi ve genişletilebilir yapıda
// process_monitor.rs ile aynı mantık — iki yerde tekrar etmemek için
// ileride shared config modülüne taşınabilir
fn is_whitelisted(path_str: &str) -> bool {
    let path_lower = path_str.to_lowercase();

    // Sistem yolları
    if path_lower.contains("windows\\system32")
        || path_lower.contains("windows\\syswow64")
        || path_lower.contains("windows\\systemapps")
    {
        return true;
    }

    // Bilinen meşru uygulama yolları — YARA taramasına gerek yok
    // AppData\Local\Programs: kullanıcı kurulumu (VS Code, Discord, Slack vb.)
    // Program Files: sistem geneli kurulumlar
    if path_lower.contains("appdata\\local\\programs")
        || path_lower.contains("program files (x86)")
        || path_lower.contains("program files\\")
    {
        return true;
    }

    // SolidTrace agent'ın kendisi
    if let Ok(current_exe) = std::env::current_exe() {
        let current_lower = current_exe.to_string_lossy().to_lowercase();
        if path_lower == current_lower {
            return true;
        }
    }

    // Env'den ek whitelist girişleri (virgülle ayrılmış)
    if let Ok(extra) = std::env::var("SCANNER_WHITELIST") {
        for entry in extra.split(',') {
            if path_lower.contains(&entry.trim().to_lowercase()) {
                return true;
            }
        }
    }

    false
}

// FIX: Sabit boyutlu PID seti — sınırsız büyüme yok
// 200'de clear() yerine en eski 100'ü sil (basit FIFO yaklaşımı)
struct BoundedPidSet {
    set:    HashSet<u32>,
    order:  Vec<u32>,
    limit:  usize,
}

impl BoundedPidSet {
    fn new(limit: usize) -> Self {
        Self { set: HashSet::new(), order: Vec::new(), limit }
    }

    fn contains(&self, pid: &u32) -> bool {
        self.set.contains(pid)
    }

    fn insert(&mut self, pid: u32) {
        if self.set.contains(&pid) {
            return;
        }
        if self.order.len() >= self.limit {
            // En eski %50'yi temizle
            let remove_count = self.limit / 2;
            let to_remove: Vec<u32> = self.order.drain(..remove_count).collect();
            for p in to_remove {
                self.set.remove(&p);
            }
        }
        self.set.insert(pid);
        self.order.push(pid);
    }
}

pub async fn run_deep_scan(client: Arc<ApiClient>) {
    println!("🛡️ [EDR] Akıllı İzleme Modu Aktif...");

    let scan_interval_secs = std::env::var("SCAN_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5);

    let mut sys = System::new_all();
    // FIX: BoundedPidSet — 500 PID sınırı, yarısı dolunca eski yarısı temizlenir
    let mut reported_pids = BoundedPidSet::new(500);

    loop {
        sys.refresh_processes();

        for (pid, process) in sys.processes() {
            let pid_u32  = pid.as_u32();
            let exe_path = process.exe();
            let path_str = exe_path.to_string_lossy();

            if path_str.is_empty() {
                continue;
            }

            // 1. WHITELIST
            if is_whitelisted(&path_str) {
                continue;
            }

            // 2. DEMO VİRÜS KONTROLÜ
            if path_str.to_lowercase().contains("test-virus") {
                if !reported_pids.contains(&pid_u32) {
                    let msg = format!("🚨 KRİTİK: Test Virüsü! Yol: {}", path_str);
                    println!("🔥 {}", msg);
                    let _ = client.send_event("MALWARE_DETECTED", &msg, "CRITICAL", pid_u32, None).await;
                    reported_pids.insert(pid_u32);
                }
                continue;
            }

            // 3. YARA TARAMASI
            let mut is_threat = false;
            if let Some(rule_name) = check_with_yara(exe_path) {
                if !reported_pids.contains(&pid_u32) {
                    let msg = format!("🔥 TEHDİT: YARA ({}) | Yol: {}", rule_name, path_str);
                    println!("{}", msg);
                    let _ = client.send_event("MALWARE_DETECTED", &msg, "CRITICAL", pid_u32, None).await;
                    reported_pids.insert(pid_u32);
                }
                is_threat = true;
            }

            // 4. NORMAL AKTİVİTE + HASH RAPORU
            if !reported_pids.contains(&pid_u32) {
                if let Some(hash) = get_file_hash(exe_path) {
                    if is_threat {
                        println!("📡 [UPLINK] Tehdit hash'i küresel istihbarat ile doğrulanıyor...");
                    } else {
                        let details = format!("Yol: {}", path_str);
                        let _ = client.send_event("PROCESS_START", &details, "INFO", pid_u32, None).await;
                    }
                    let _ = client.report_file_hash(&path_str, &hash, pid_u32).await;
                    reported_pids.insert(pid_u32);
                }
            }

        }

        // Log sadece DEBUG modunda veya yeni tehdit bulunduğunda
        // Her turda basılması terminali kirletiyor
        // [SCAN] tur logu tamamen kaldırıldı — her 5sn terminale spam üretiyordu
        // Sadece tehdit bulunduğunda zaten ayrı log basılıyor

        sleep(Duration::from_secs(scan_interval_secs)).await;
    }
}

pub fn check_with_yara(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    if let Some(scanner) = &*GLOBAL_SCANNER {
        return scanner.scan_file(path);
    }
    None
}

pub fn get_file_hash(path: &Path) -> Option<String> {
    let file = match File::open(path) {
        Ok(f)  => f,
        Err(_) => return None,
    };
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192]; // FIX: 4KB → 8KB buffer (küçük dosyalar için daha az syscall)
    loop {
        match reader.read(&mut buffer) {
            Ok(0)  => break,
            Ok(n)  => hasher.update(&buffer[..n]),
            Err(_) => return None,
        }
    }
    Some(hex::encode(hasher.finalize()))
}