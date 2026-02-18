use winreg::enums::*;
use winreg::RegKey;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use std::collections::HashMap;
use crate::api_client::ApiClient;

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("🔐 [REGISTRY] Kalıcılık (Persistence) İzleyicisi Aktif...");

    let keys_to_watch = vec![
        (HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ];

    // bilinen değerleri sakla: Key -> Value
    let mut known_values: HashMap<String, String> = HashMap::new();

    loop {
        for (hive, path) in &keys_to_watch {
            if let Ok(reg_key) = RegKey::predef(*hive).open_subkey(path) {
                // Mevcut değerleri tara
                for (name, value) in reg_key.enum_values().flatten() {
                    let full_key = format!("{}\\{}", path, name);
                    let val_str = value.to_string();

                    // 1. Durum: Yeni bir anahtar eklendi mi?
                    if !known_values.contains_key(&full_key) {
                        if !known_values.is_empty() { // İlk taramada alarm verme
                            let msg = format!("🚨 YENİ OTOMATİK BAŞLATMA: {} -> {}", name, val_str);
                            send_alert(&client, &msg).await;
                        }
                        known_values.insert(full_key.clone(), val_str.clone());
                    } 
                    // 2. Durum: Mevcut bir anahtarın değeri DEĞİŞTİ mi? (Kritik!)
                    else if known_values.get(&full_key).unwrap() != &val_str {
                        let msg = format!("⚠️ KAYIT DEĞİŞTİRİLDİ: {} değeri artık: {}", name, val_str);
                        send_alert(&client, &msg).await;
                        known_values.insert(full_key, val_str);
                    }
                }
            }
        }

        // 3. Durum: Bir anahtar SİLİNDİ mi? (Opsiyonel ama pro gösterir)
        // known_values içinde olup reg_key içinde olmayanları temizlemek için 
        // buraya bir temizlik mantığı eklenebilir, ama güvenlik için yukarıdaki ikisi şart.

        sleep(Duration::from_secs(5)).await;
    }
}

// Yardımcı fonksiyon: Kod kalabalığını önler
async fn send_alert(client: &Arc<ApiClient>, msg: &str) {
    println!("💀 [REGISTRY] {}", msg);
    let my_pid = std::process::id();
    let _ = client.send_event(
        "PERSISTENCE_DETECTED", 
        msg, 
        "CRITICAL", 
        my_pid,
        None
    ).await;
}