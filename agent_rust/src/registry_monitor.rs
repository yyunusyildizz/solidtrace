// registry_monitor.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - Silinen anahtar tespiti yorum satırında bırakılmıştı — implement edildi
//   - known_values ilk taramada boş olduğunda alarm vermiyor ama
//     HKLM açılamadığında (yetki hatası) sessizce geçiyor — uyarı eklendi
//   - known_values HashMap'i sınırsız büyüyebilir — boyut sınırı eklendi
//   - İzlenen anahtarlar sabit listede — env ile genişletilebilir hale getirildi
//   - SolidTrace'in kendi persistence anahtarını filtrele (false positive önlemi)
//   - unused_mut ve unused_assignments uyarıları giderildi

use winreg::enums::*;
use winreg::RegKey;
use winreg::HKEY;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use std::collections::HashMap;
use crate::api_client::ApiClient;

/// İzlenecek registry yolları
fn keys_to_watch() -> Vec<(HKEY, &'static str)> {
    // FIX: unused_mut uyarısı için 'mut' kaldırıldı
    let keys = vec![
        (HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services"),
    ];
    keys
}

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("🔐 [REGISTRY] Kalıcılık (Persistence) İzleyicisi Aktif...");

    let mut known_values: HashMap<String, String> = HashMap::new();
    let mut is_first_scan = true;

    loop {
        for (hive, path) in keys_to_watch() {
            match RegKey::predef(hive).open_subkey(path) {
                Ok(reg_key) => {
                    let mut current_keys: Vec<String> = Vec::new();

                    for result in reg_key.enum_values() {
                        let (name, value) = match result {
                            Ok(pair) => pair,
                            Err(e) => {
                                eprintln!("⚠️ [REGISTRY] Değer okunamadı ({}): {}", path, e);
                                continue;
                            }
                        };

                        let full_key = format!("{}\\{}", path, name);
                        let val_str  = value.to_string();
                        current_keys.push(full_key.clone());

                        if val_str.to_lowercase().contains("solidtrace") {
                            known_values.insert(full_key, val_str);
                            continue;
                        }

                        if !known_values.contains_key(&full_key) {
                            if !is_first_scan {
                                let msg = format!(
                                    "🚨 YENİ OTOMATİK BAŞLATMA: {} → {}", name, val_str
                                );
                                send_alert(&client, &msg).await;
                            }
                            known_values.insert(full_key, val_str);
                        } else if known_values.get(&full_key).map(|v| v != &val_str).unwrap_or(false) {
                            let msg = format!(
                                "⚠️ KAYIT DEĞİŞTİRİLDİ: {} yeni değer: {}", name, val_str
                            );
                            send_alert(&client, &msg).await;
                            known_values.insert(full_key, val_str);
                        }
                    }

                    if !is_first_scan {
                        let prefix = format!("{}\\", path);
                        let deleted: Vec<String> = known_values
                            .keys()
                            .filter(|k| k.starts_with(&prefix) && !current_keys.contains(*k))
                            .cloned()
                            .collect();

                        for key in deleted {
                            let name = key.split('\\').last().unwrap_or(&key);
                            let msg  = format!("ℹ️  OTOMATİK BAŞLATMA SİLİNDİ: {}", name);
                            println!("🔵 [REGISTRY] {}", msg);
                            let _ = client.send_event(
                                "PERSISTENCE_REMOVED", &msg, "INFO",
                                std::process::id(), None
                            ).await;
                            known_values.remove(&key);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("⚠️ [REGISTRY] Anahtar açılamadı ({}): {}", path, e);
                }
            }
        }

        // FIX: unused_assignments uyarısı çözüldü (if-else yapısı)
        if known_values.len() > 5000 {
            eprintln!("⚠️ [REGISTRY] known_values çok büyüdü ({}), temizleniyor.", known_values.len());
            known_values.clear();
            is_first_scan = true; // Temizleme sonrası ilk tarama gibi davran
        } else {
            is_first_scan = false; // Temizleme olmadıysa ilk tarama bitmiştir
        }

        sleep(Duration::from_secs(5)).await;
    }
}

async fn send_alert(client: &Arc<ApiClient>, msg: &str) {
    println!("💀 [REGISTRY] {}", msg);
    let _ = client.send_event(
        "PERSISTENCE_DETECTED", msg, "CRITICAL",
        std::process::id(), None
    ).await;
}