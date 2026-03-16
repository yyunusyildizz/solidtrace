use std::process::Command;

fn apply_firewall_rule(
    rule_name: &str,
    dir: &str,
    action: &str,
    remote_ip: Option<&str>,
) -> Result<String, String> {
    let mut args: Vec<String> = vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={}", rule_name),
        format!("dir={}", dir),
        format!("action={}", action),
        "enable=yes".to_string(),
    ];

    if let Some(ip) = remote_ip {
        args.push(format!("remoteip={}", ip));
    }

    let output = Command::new("netsh")
        .args(&args)
        .output()
        .map_err(|e| format!("firewall rule uygulanamadı: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        Ok(if stdout.is_empty() {
            format!("Firewall rule uygulandı: {}", rule_name)
        } else {
            stdout
        })
    } else {
        Err(if stderr.is_empty() {
            format!("Firewall rule başarısız: {}", rule_name)
        } else {
            stderr
        })
    }
}

fn delete_firewall_rule(rule_name: &str) -> Result<String, String> {
    let args: Vec<String> = vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "delete".to_string(),
        "rule".to_string(),
        format!("name={}", rule_name),
    ];

    let output = Command::new("netsh")
        .args(&args)
        .output()
        .map_err(|e| format!("Firewall rule silinemedi: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        Ok(if stdout.is_empty() {
            format!("Firewall rule silindi: {}", rule_name)
        } else {
            stdout
        })
    } else {
        let combined = format!("{} {}", stdout, stderr).to_lowercase();
        if combined.contains("no rules match")
            || combined.contains("eşleşen kural yok")
            || combined.contains("ok.")
        {
            Ok(format!("Rule zaten yok: {}", rule_name))
        } else {
            Err(if stderr.is_empty() {
                format!("Firewall rule silme başarısız: {}", rule_name)
            } else {
                stderr
            })
        }
    }
}

/// Host'u ağdan büyük ölçüde izole eder.
/// `server_ip` verilirse bu IP için erişim koruma kuralı ekler.
pub fn enable_isolation(server_ip: &str) -> Result<String, String> {
    let allow_out_name = "SolidTrace Allow Server Out";
    let allow_in_name = "SolidTrace Allow Server In";
    let block_out_name = "SolidTrace Block All Out";
    let block_in_name = "SolidTrace Block All In";

    let mut messages = Vec::new();

    if !server_ip.trim().is_empty() {
        messages.push(apply_firewall_rule(
            allow_out_name,
            "out",
            "allow",
            Some(server_ip),
        )?);
        messages.push(apply_firewall_rule(
            allow_in_name,
            "in",
            "allow",
            Some(server_ip),
        )?);
    }

    messages.push(apply_firewall_rule(block_out_name, "out", "block", None)?);
    messages.push(apply_firewall_rule(block_in_name, "in", "block", None)?);

    Ok(format!(
        "İzolasyon etkinleştirildi. {}",
        messages.join(" | ")
    ))
}

/// Host izolasyonunu kaldırır.
pub fn disable_isolation() -> Result<String, String> {
    let rules = [
        "SolidTrace Allow Server Out",
        "SolidTrace Allow Server In",
        "SolidTrace Block All Out",
        "SolidTrace Block All In",
    ];

    let mut messages = Vec::new();
    for rule in rules {
        messages.push(delete_firewall_rule(rule)?);
    }

    Ok(format!(
        "İzolasyon kaldırıldı. {}",
        messages.join(" | ")
    ))
}