use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use std::process::Command;
use crate::api_client::ApiClient;

#[derive(Debug, PartialEq, Clone)]
struct UsbDevice {
    model: String,
    serial: String,
    size: String,
}

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("🛡️ [USB MONITOR] WMI (Enterprise Mode) Aktif...");
    
    // Başlangıç durumu tespiti
    let mut known_devices = get_usb_devices_via_wmi();
    println!("ℹ️  [USB] Başlangıçta Takılı Cihazlar: {}", known_devices.len());

    loop {
        // 🔥 CPU FIX: 2 saniye yerine 5-10 saniye idealdir. 
        // PowerShell başlatmak pahalı bir işlemdir.
        sleep(Duration::from_secs(5)).await;

        let current_devices = get_usb_devices_via_wmi();

        // 1. YENİ CİHAZ KONTROLÜ
        for device in &current_devices {
            if !known_devices.contains(device) {
                let msg = format!("USB TESPİT EDİLDİ: {} (Boyut: {})", device.model, device.size);
                
                println!("🚨 [ALARM] {}", msg);
                println!("   🔍 Serial: {}", device.serial);

                let my_pid = std::process::id(); 
                let client_clone = client.clone();
                let msg_clone = msg.clone();
                
                // 🔥 SERIAL FIX: Seri numarasını API'ye gönderiyoruz
                let serial_clone = Some(device.serial.clone());
                
                tokio::spawn(async move {
                    // Güncellenmiş send_event fonksiyonuna serial verisini ekledik
                    let _ = client_clone.send_event(
                        "USB_DEVICE_DETECTED", 
                        &msg_clone, 
                        "HIGH", 
                        my_pid,
                        serial_clone
                    ).await;
                });
            }
        }

        // 2. ÇIKARILAN CİHAZ KONTROLÜ
        for device in &known_devices {
            if !current_devices.contains(device) {
                println!("ℹ️ [USB] Cihaz Çıkarıldı: {}", device.model);
            }
        }

        known_devices = current_devices;
    }
}

// 🧠 WMI BRIDGE: PowerShell üzerinden optimize edilmiş sorgu
fn get_usb_devices_via_wmi() -> Vec<UsbDevice> {
    // PowerShell komutunu daha temiz bir JSON çıktısı için revize ettik
    let output = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | Select-Object Model, SerialNumber, Size | ConvertTo-Json"
        ])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let mut devices = Vec::new();

            if stdout.trim().is_empty() {
                return devices;
            }

            // JSON Liste veya Tek Obje kontrolü
            if stdout.trim().starts_with('[') {
                let entries: Vec<&str> = stdout.split("},").collect();
                for entry in entries {
                    if let Some(dev) = parse_json_entry(entry) { devices.push(dev); }
                }
            } else {
                if let Some(dev) = parse_json_entry(&stdout) { devices.push(dev); }
            }
            
            devices
        },
        Err(_) => Vec::new(),
    }
}

// Basit String Parse (Hafiflik için devam ediyoruz)
fn parse_json_entry(entry: &str) -> Option<UsbDevice> {
    let model = extract_value(entry, "Model");
    let serial = extract_value(entry, "SerialNumber");
    let size_raw = extract_value(entry, "Size");

    if model.is_empty() { return None; }

    let size_gb = match size_raw.parse::<u64>() {
        Ok(bytes) => format!("{:.1} GB", bytes as f64 / 1_073_741_824.0),
        Err(_) => "Bilinmiyor".to_string(),
    };

    Some(UsbDevice {
        model,
        serial,
        size: size_gb,
    })
}

fn extract_value(json: &str, key: &str) -> String {
    let search = format!("\"{}\":", key);
    if let Some(start) = json.find(&search) {
        let rest = &json[start + search.len()..];
        if let Some(val_start) = rest.find(|c: char| c.is_alphanumeric() || c == '"') {
            let val_rest = &rest[val_start..];
            if val_rest.starts_with('"') {
                if let Some(end) = val_rest[1..].find('"') {
                    return val_rest[1..end+1].to_string();
                }
            } else {
                if let Some(end) = val_rest.find(|c: char| !c.is_numeric() && c != '.') {
                    return val_rest[..end].to_string();
                }
            }
        }
    }
    "".to_string()
}