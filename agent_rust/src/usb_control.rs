#![allow(dead_code)]

use std::process::Command;

pub fn disable_usb_storage() {
    println!("⛔ [USB] USB depolama engelleniyor...");
    reg_set_usbstor_start(4);
    reg_set_write_protect(1);
    println!("✅ [USB-REG] Registry koruması aktif (Start=4, WriteProtect=1)");

    #[cfg(target_os = "windows")]
    match enumerate_usb_devices(true) {
        Ok(0) => println!("ℹ️  [USB-API] Takılı USB depolama cihazı bulunamadı."),
        Ok(n) => println!("✅ [USB-API] {} cihaz devre dışı bırakıldı.", n),
        Err(e) => {
            println!("⚠️  [USB-API] SetupDi başarısız: {} — PnP fallback...", e);
            pnp_disable_fallback();
        }
    }

    println!("🔒 [USB] USB depolama tamamen engellendi!");
}

pub fn enable_usb_storage() {
    println!("🔓 [USB] USB depolama etkinleştiriliyor...");
    reg_set_usbstor_start(3);
    reg_set_write_protect(0);
    println!("✅ [USB-REG] Registry koruması kaldırıldı (Start=3, WriteProtect=0)");

    #[cfg(target_os = "windows")]
    match enumerate_usb_devices(false) {
        Ok(0) => {
            println!("ℹ️  [USB-API] Etkinleştirilecek USB cihazı bulunamadı.");
            println!("ℹ️  [USB] USB'yi çıkarıp tekrar takın.");
        }
        Ok(n) => println!("✅ [USB-API] {} cihaz etkinleştirildi.", n),
        Err(e) => {
            println!("⚠️  [USB-API] SetupDi başarısız: {} — PnP fallback...", e);
            pnp_enable_fallback();
        }
    }

    println!("✅ [USB] USB depolama etkin!");
}

// ─────────────────────────────────────────────────────────────────────────────
// WINDOWS SETUPDI
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn enumerate_usb_devices(disable: bool) -> Result<usize, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Disable_DevNode, CM_Enable_DevNode, CM_Locate_DevNodeW,
        CM_LOCATE_DEVNODE_NORMAL, CR_SUCCESS,
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
        SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
        DIGCF_ALLCLASSES, DIGCF_PRESENT, SP_DEVINFO_DATA,
    };

    let mut count = 0usize;

    unsafe {
        // USB bus'taki tüm mevcut cihazları listele
        let dev_info = SetupDiGetClassDevsW(
            None,
            PCWSTR::from_raw(
                "USB\0".encode_utf16().collect::<Vec<u16>>().as_ptr()
            ),
            None,
            DIGCF_PRESENT | DIGCF_ALLCLASSES,
        ).map_err(|e| format!("SetupDiGetClassDevs: {:?}", e))?;

        let mut dev_info_data = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };

        let mut index = 0u32;
        loop {
            if SetupDiEnumDeviceInfo(dev_info, index, &mut dev_info_data).is_err() {
                break;
            }
            index += 1;

            // Instance ID al
            let mut id_buf = vec![0u16; 512];
            let mut required = 0u32;
            if SetupDiGetDeviceInstanceIdW(
                dev_info,
                &dev_info_data,
                Some(&mut id_buf),
                Some(&mut required),
            ).is_err() {
                continue;
            }

            let id_len = id_buf.iter().position(|&c| c == 0).unwrap_or(0);
            let instance_id = String::from_utf16_lossy(&id_buf[..id_len]);

            // Sadece USB depolama cihazları
            if !instance_id.to_uppercase().contains("USBSTOR") {
                continue;
            }

            println!("🔍 [USB-API] Cihaz: {}", &instance_id[..instance_id.len().min(60)]);

            // DevNode handle al
            let id_wide: Vec<u16> = instance_id
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut dev_node = 0u32;

            let cr = CM_Locate_DevNodeW(
                &mut dev_node,
                PCWSTR(id_wide.as_ptr()),
                CM_LOCATE_DEVNODE_NORMAL,
            );

            if cr != CR_SUCCESS {
                println!("⚠️  [USB-API] CM_Locate_DevNodeW başarısız: {:?}", cr);
                continue;
            }

            // Devre dışı bırak veya etkinleştir
            let cr2 = if disable {
                CM_Disable_DevNode(dev_node, 0)
            } else {
                CM_Enable_DevNode(dev_node, 0)
            };

            if cr2 == CR_SUCCESS {
                let action = if disable { "devre dışı" } else { "etkin" };
                println!("✅ [USB-API] {} bırakıldı: {}",
                    action, &instance_id[..instance_id.len().min(50)]);
                count += 1;
            } else {
                println!("⚠️  [USB-API] İşlem başarısız (Yönetici yetkisi?): {:?}", cr2);
            }
        }

        let _ = SetupDiDestroyDeviceInfoList(dev_info);
    }

    Ok(count)
}

// ─────────────────────────────────────────────────────────────────────────────
// FALLBACK: PowerShell
// ─────────────────────────────────────────────────────────────────────────────

fn pnp_disable_fallback() {
    let ps = r#"
        $d = Get-PnpDevice | Where-Object { $_.InstanceId -like 'USBSTOR*' -and $_.Status -ne 'Error' }
        foreach ($x in $d) {
            Disable-PnpDevice -InstanceId $x.InstanceId -Confirm:$false -EA SilentlyContinue
            Write-Host "DISABLED:$($x.FriendlyName)"
        }
        if (-not $d) { Write-Host "NONE" }
    "#;
    for line in run_ps(ps).lines() {
        let l = line.trim();
        if l.starts_with("DISABLED:") { println!("✅ [USB-PS] {}", &l[9..]); }
        else if l == "NONE" { println!("ℹ️  [USB-PS] Takılı USB yok."); }
    }
}

fn pnp_enable_fallback() {
    let ps = r#"
        $d = Get-PnpDevice | Where-Object { $_.InstanceId -like 'USBSTOR*' }
        foreach ($x in $d) {
            Enable-PnpDevice -InstanceId $x.InstanceId -Confirm:$false -EA SilentlyContinue
            Write-Host "ENABLED:$($x.FriendlyName)"
        }
        Start-Service USBSTOR -EA SilentlyContinue
        if (-not $d) { Write-Host "NONE" }
    "#;
    for line in run_ps(ps).lines() {
        let l = line.trim();
        if l.starts_with("ENABLED:") { println!("✅ [USB-PS] {}", &l[8..]); }
        else if l == "NONE" { println!("ℹ️  [USB-PS] Etkinleştirilecek USB yok."); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YARDIMCILAR
// ─────────────────────────────────────────────────────────────────────────────

fn reg_set_usbstor_start(value: u32) {
    reg_write_dword(
        r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
        "Start", value,
    );
}

fn reg_set_write_protect(value: u32) {
    let key = r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
    let _ = Command::new("reg").args(["add", key, "/f"]).output();
    reg_write_dword(key, "WriteProtect", value);
}

fn reg_write_dword(key: &str, value: &str, data: u32) {
    let data_str = data.to_string();
    let _ = Command::new("reg")
        .args(["add", key, "/v", value, "/t", "REG_DWORD", "/d", &data_str, "/f"])
        .output();
}

fn run_ps(script: &str) -> String {
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-OutputEncoding", "UTF8", "-Command", script])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    }
}
