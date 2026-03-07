#![allow(dead_code)]

use std::process::Command;

/// USB depolama birimlerini devre dışı bırak (Hybrid: Registry + PnP + Scan)
pub fn disable_usb_storage() {
    println!("⛔ [USB] USB depolama engelleniyor...");

    // 1. Registry kilidi — yeni takılacak cihazlar sürücü yükleyemez
    reg_write_dword(
        r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
        "Start", 4,
    );
    println!("✅ [USB-REG] Kapı kilitlendi (Start=4)");

    // 2. Anlık bağlı USB depolama cihazlarını düşür
    let ps_disable = r#"
        $devices = Get-PnpDevice -InstanceId "*USBSTOR*" -ErrorAction SilentlyContinue
        if ($devices) {
            $devices | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue
            foreach ($d in $devices) {
                Write-Host "DISABLED:$($d.FriendlyName)"
            }
        } else {
            Write-Host "NONE"
        }
    "#;

    let out = run_ps(ps_disable);
    for line in out.lines() {
        let l = line.trim();
        if l.starts_with("DISABLED:") {
            println!("✅ [USB-PNP] Devre dışı: {}", &l[9..]);
        } else if l == "NONE" {
            println!("ℹ️  [USB-PNP] Şu an takılı USB depolama yok.");
        }
    }

    // 3. Donanım değişikliklerini tara
    let _ = Command::new("pnputil").arg("/scan-devices").output();
    println!("✅ [USB-SCAN] Donanım taraması tamamlandı.");
    println!("🔒 [USB] USB depolama tamamen engellendi!");
}

/// USB depolama birimlerini tekrar etkinleştir
pub fn enable_usb_storage() {
    println!("🔓 [USB] USB depolama etkinleştiriliyor...");

    // 1. Registry engelini kaldır
    reg_write_dword(
        r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
        "Start", 3,
    );
    println!("✅ [USB-REG] Kilit açıldı (Start=3)");

    // 2. Sadece pasif/disabled cihazları uyandır
    let ps_enable = r#"
        $devices = Get-PnpDevice -InstanceId "*USBSTOR*" -ErrorAction SilentlyContinue |
                   Where-Object { $_.Status -ne "OK" }
        if ($devices) {
            $devices | Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue
            foreach ($d in $devices) {
                Write-Host "ENABLED:$($d.FriendlyName)"
            }
        } else {
            Write-Host "NONE"
        }
    "#;

    let out = run_ps(ps_enable);
    for line in out.lines() {
        let l = line.trim();
        if l.starts_with("ENABLED:") {
            println!("✅ [USB-PNP] Etkinleştirildi: {}", &l[8..]);
        } else if l == "NONE" {
            println!("ℹ️  [USB-PNP] Etkinleştirilecek pasif cihaz yok.");
        }
    }

    // 3. Donanım değişikliklerini tara (zorla yenile)
    let _ = Command::new("pnputil").arg("/scan-devices").output();
    println!("✅ [USB-SCAN] Donanım taraması tamamlandı.");
    println!("✅ [USB] USB depolama etkin! Gerekirse USB'yi çıkarıp tekrar takın.");
}

// ─────────────────────────────────────────────────────────────────────────────

fn reg_write_dword(key: &str, value: &str, data: u32) {
    let data_str = data.to_string();
    let result = Command::new("reg")
        .args(["add", key, "/v", value, "/t", "REG_DWORD", "/d", &data_str, "/f"])
        .output();
    match result {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                println!("⚠️  [USB-REG] Hata: {}", err.trim());
            }
        }
        Err(e) => println!("❌ [USB-REG] reg komutu çalışmadı: {}", e),
    }
}

fn run_ps(script: &str) -> String {
    match Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-OutputEncoding", "UTF8",
            "-Command", script,
        ])
        .output()
    {
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                println!("⚠️  [USB-PS] {}", err.trim());
            }
            String::from_utf8_lossy(&o.stdout).to_string()
        }
        Err(e) => {
            println!("❌ [USB-PS] PowerShell çalışmadı: {}", e);
            String::new()
        }
    }
}
