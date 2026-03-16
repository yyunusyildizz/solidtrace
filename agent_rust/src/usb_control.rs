use std::process::Command;

fn run_reg(args: &[&str]) -> Result<String, String> {
    let output = Command::new("reg")
        .args(args)
        .output()
        .map_err(|e| format!("reg komutu çalıştırılamadı: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        Ok(if stdout.is_empty() {
            "ok".to_string()
        } else {
            stdout
        })
    } else {
        Err(if stderr.is_empty() {
            format!("reg başarısız oldu: {:?}", args)
        } else {
            stderr
        })
    }
}

fn run_powershell(script: &str) -> Result<String, String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
        .map_err(|e| format!("powershell çalıştırılamadı: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        Ok(if stdout.is_empty() {
            "ok".to_string()
        } else {
            stdout
        })
    } else {
        Err(if stderr.is_empty() {
            "powershell komutu başarısız oldu".to_string()
        } else {
            stderr
        })
    }
}

/// USB storage kullanımını registry üzerinden kapatır ve takılı depolama aygıtlarını disable etmeye çalışır.
pub fn disable_usb_storage() -> Result<String, String> {
    let mut messages = Vec::new();

    messages.push(run_reg(&[
        "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
        "/v",
        "Start",
        "/t",
        "REG_DWORD",
        "/d",
        "4",
        "/f",
    ])?);

    // takılı removable storage cihazlarını disable etmeye çalış
    let disable_script = r#"
$devices = Get-PnpDevice | Where-Object {
    $_.Class -eq 'DiskDrive' -or $_.FriendlyName -match 'USB'
}
foreach ($d in $devices) {
    try {
        Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Output ("disabled:" + $d.InstanceId)
    } catch {
        Write-Output ("skip:" + $d.InstanceId)
    }
}
"#;

    match run_powershell(disable_script) {
        Ok(out) => messages.push(out),
        Err(e) => messages.push(format!("PnP disable uyarısı: {}", e)),
    }

    Ok(format!("USB storage devre dışı bırakıldı. {}", messages.join(" | ")))
}

/// USB storage kullanımını tekrar açar ve uygun aygıtları enable etmeye çalışır.
pub fn enable_usb_storage() -> Result<String, String> {
    let mut messages = Vec::new();

    messages.push(run_reg(&[
        "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
        "/v",
        "Start",
        "/t",
        "REG_DWORD",
        "/d",
        "3",
        "/f",
    ])?);

    let enable_script = r#"
$devices = Get-PnpDevice | Where-Object {
    $_.Class -eq 'DiskDrive' -or $_.FriendlyName -match 'USB'
}
foreach ($d in $devices) {
    try {
        Enable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Output ("enabled:" + $d.InstanceId)
    } catch {
        Write-Output ("skip:" + $d.InstanceId)
    }
}
"#;

    match run_powershell(enable_script) {
        Ok(out) => messages.push(out),
        Err(e) => messages.push(format!("PnP enable uyarısı: {}", e)),
    }

    Ok(format!("USB storage aktif edildi. {}", messages.join(" | ")))
}