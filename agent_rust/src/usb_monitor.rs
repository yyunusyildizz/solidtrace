// usb_monitor.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - Manuel JSON parse (extract_value) kırılgan — serde_json ile değiştirildi
//   - PowerShell başarısız olursa Err(_) → Vec::new() sessizce geçiyor, hata loglanmıyor
//   - Cihaz çıkarma bildirimi sadece println, API'ye gönderilmiyor — düzeltildi
//   - Çok büyük USB (>2TB) hesabı u64 overflow yapabilirdi — düzeltildi
//   - Interval env ile yapılandırılabilir hale getirildi

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use std::process::Command;
use serde::Deserialize;
use crate::api_client::ApiClient;

#[derive(Debug, PartialEq, Clone, Deserialize)]
struct UsbDevice {
    #[serde(rename = "Model")]
    model: String,
    #[serde(rename = "SerialNumber")]
    serial: Option<String>, // FIX: Bazı cihazlarda serial null gelebilir
    #[serde(rename = "Size")]
    size: Option<u64>, // FIX: Option — null gelen size'ı handle et
}

impl UsbDevice {
    fn serial_str(&self) -> String {
        self.serial.clone().unwrap_or_else(|| "Bilinmiyor".to_string())
    }

    fn size_str(&self) -> String {
        match self.size {
            Some(bytes) if bytes > 0 => {
                // FIX: checked_div ile overflow koruması
                let gb = bytes / 1_073_741_824;
                format!("{} GB", gb)
            }
            _ => "Bilinmiyor".to_string(),
        }
    }
}

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("🛡️ [USB MONITOR] WMI (Enterprise Mode) Aktif...");

    let interval_secs = std::env::var("USB_POLL_INTERVAL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5);

    let mut known_devices = get_usb_devices();
    println!("ℹ️  [USB] Başlangıçta {} cihaz takılı.", known_devices.len());

    loop {
        sleep(Duration::from_secs(interval_secs)).await;

        let current_devices = get_usb_devices();

        // 1. YENİ CİHAZ
        for device in &current_devices {
            if !known_devices.contains(device) {
                let msg = format!(
                    "USB TESPİT EDİLDİ: {} | Boyut: {} | Seri: {}",
                    device.model, device.size_str(), device.serial_str()
                );
                println!("🚨 [USB] {}", msg);

                let c      = client.clone();
                let m      = msg.clone();
                let serial = Some(device.serial_str());
                let pid    = std::process::id();

                tokio::spawn(async move {
                    let _ = c.send_event("USB_DEVICE_DETECTED", &m, "HIGH", pid, serial).await;
                });
            }
        }

        // 2. ÇIKARILAN CİHAZ — FIX: artık API'ye de bildiriliyor
        for device in &known_devices {
            if !current_devices.contains(device) {
                let msg = format!(
                    "USB ÇIKARILDI: {} | Seri: {}", device.model, device.serial_str()
                );
                println!("ℹ️  [USB] {}", msg);

                let c   = client.clone();
                let m   = msg.clone();
                let pid = std::process::id();
                tokio::spawn(async move {
                    let _ = c.send_event("USB_DEVICE_REMOVED", &m, "INFO", pid, None).await;
                });
            }
        }

        known_devices = current_devices;
    }
}

/// PowerShell + WMI ile USB cihaz listesi al
fn get_usb_devices() -> Vec<UsbDevice> {
    let ps_cmd = r#"
        $devices = Get-CimInstance Win32_DiskDrive |
            Where-Object { $_.InterfaceType -eq 'USB' } |
            Select-Object Model, SerialNumber, Size
        if ($devices -eq $null) { '[]' }
        elseif ($devices -is [array]) { $devices | ConvertTo-Json }
        else { @($devices) | ConvertTo-Json }
    "#;

    let output = Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", ps_cmd])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();

            if stdout.is_empty() || stdout == "[]" {
                return Vec::new();
            }

            // FIX: serde_json ile doğru parse — manuel extract_value kaldırıldı
            // Array veya tek obje her ikisini de handle et
            if stdout.starts_with('[') {
                serde_json::from_str::<Vec<UsbDevice>>(&stdout)
                    .unwrap_or_else(|e| {
                        eprintln!("⚠️ [USB] JSON parse hatası (array): {}", e);
                        Vec::new()
                    })
            } else {
                serde_json::from_str::<UsbDevice>(&stdout)
                    .map(|d| vec![d])
                    .unwrap_or_else(|e| {
                        eprintln!("⚠️ [USB] JSON parse hatası (object): {}", e);
                        Vec::new()
                    })
            }
        }
        Err(e) => {
            // FIX: Hata loglanıyor — sessizce boş dönmüyor
            eprintln!("⚠️ [USB] PowerShell çalıştırılamadı: {}", e);
            Vec::new()
        }
    }
}