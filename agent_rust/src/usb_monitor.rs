use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use std::process::Command;
use crate::api_client::ApiClient;

#[derive(Debug, PartialEq, Clone)]
struct UsbDevice {
    name: String,
    device_id: String,
}

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("🛡️ [USB MONITOR] Aktif (Win32_PnPEntity modu)...");

    let mut known_devices = get_usb_devices();
    println!("ℹ️  [USB] Başlangıçta {} cihaz takılı.", known_devices.len());

    loop {
        sleep(Duration::from_secs(5)).await;

        let current_devices = get_usb_devices();

        // Yeni takılan cihazlar
        for device in &current_devices {
            if !known_devices.contains(device) {
                let msg = format!("🔌 USB CİHAZ TAKILDI: {}", device.name);
                println!("🚨 [USB] {}", msg);
                println!("   DeviceID: {}", device.device_id);

                let c = client.clone();
                let m = msg.clone();
                let serial = Some(device.device_id.clone());
                tokio::spawn(async move {
                    let _ = c.send_event(
                        "USB_DEVICE_DETECTED",
                        &m,
                        "HIGH",
                        std::process::id(),
                        serial,
                    ).await;
                });
            }
        }

        // Çıkarılan cihazlar
        for device in &known_devices {
            if !current_devices.contains(device) {
                let msg = format!("🔌 USB CİHAZ ÇIKARILDI: {}", device.name);
                println!("ℹ️  [USB] {}", msg);

                let c = client.clone();
                let m = msg.clone();
                tokio::spawn(async move {
                    let _ = c.send_event(
                        "USB_DEVICE_REMOVED",
                        &m,
                        "WARNING",
                        std::process::id(),
                        None,
                    ).await;
                });
            }
        }

        known_devices = current_devices;
    }
}

/// Win32_PnPEntity — DiskDrive yerine tüm USB cihazlarını yakalar
/// (flash drive, mouse, keyboard, hub dahil)
fn get_usb_devices() -> Vec<UsbDevice> {
    // ÇÖZÜM 1: r"..." (Raw String) eklendi ve boşluklar temizlendi.
    let ps_cmd = r"$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); Get-PnpDevice | Where-Object { $_.InstanceId -like 'USB\*' -and $_.Status -eq 'OK' } | Select-Object FriendlyName, InstanceId | ConvertTo-Json -Compress";

    let output = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            // ÇÖZÜM 2: "-OutputEncoding", "UTF8" satırı silindi çünkü powershell.exe bunu desteklemez.
            "-Command", ps_cmd,
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            // Windows-1252 → UTF8 dönüşümü için lossy kullan
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let trimmed = stdout.trim();
            if trimmed.is_empty() || trimmed == "null" {
                return Vec::new();
            }
            parse_pnp_json(trimmed)
        }
        _ => Vec::new(),
    }
}

fn parse_pnp_json(json: &str) -> Vec<UsbDevice> {
    let mut devices = Vec::new();

    // Tek obje veya dizi kontrolü
    let is_array = json.trim_start().starts_with('[');

    if is_array {
        // Manuel split — serde bağımlılığı olmadan
        // Her { ... } bloğunu ayrı ayrı parse et
        let mut depth = 0i32;
        let mut start = 0usize;
        let chars: Vec<char> = json.chars().collect();

        for (i, &c) in chars.iter().enumerate() {
            match c {
                '{' => {
                    if depth == 0 { start = i; }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        let block: String = chars[start..=i].iter().collect();
                        if let Some(dev) = parse_single_entry(&block) {
                            devices.push(dev);
                        }
                    }
                }
                _ => {}
            }
        }
    } else {
        if let Some(dev) = parse_single_entry(json) {
            devices.push(dev);
        }
    }

    devices
}

fn parse_single_entry(block: &str) -> Option<UsbDevice> {
    let name = extract_json_str(block, "FriendlyName");
    let device_id = extract_json_str(block, "InstanceId");

    // Boş veya null değerleri filtrele
    if name.is_empty() || name == "null" {
        return None;
    }

    // Sadece gerçek USB depolama cihazlarını değil, tüm USB cihazları logla
    // Ama çok gürültülü temel bileşenleri filtrele
    let name_lower = name.to_lowercase();
    let skip_keywords = ["root hub", "composite device", "generic hub"];
    if skip_keywords.iter().any(|k| name_lower.contains(k)) {
        return None;
    }

    Some(UsbDevice { name, device_id })
}

fn extract_json_str(json: &str, key: &str) -> String {
    let search = format!("\"{}\":", key);
    if let Some(pos) = json.find(&search) {
        let rest = &json[pos + search.len()..].trim_start_matches(' ');
        if rest.starts_with('"') {
            // String değer
            if let Some(end) = rest[1..].find('"') {
                return rest[1..end + 1].to_string();
            }
        } else if rest.starts_with("null") {
            return "null".to_string();
        } else {
            // Sayısal veya boolean
            let end = rest.find(|c: char| c == ',' || c == '}').unwrap_or(rest.len());
            return rest[..end].trim().to_string();
        }
    }
    String::new()
}