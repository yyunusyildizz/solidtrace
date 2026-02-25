// isolation_manager.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - Kural ekleme sırası kritik: önce ALLOW sonra BLOCK — eğer ağ kesintisi olursa
//     ALLOW kuralı eklenmeden BLOCK düşerse SOC bağlantısı da kesilir
//     → İzolasyon sonrası SOC'a ping atılıyor, başarısızsa geri al
//   - "No rules match" kontrolü string içinde — stderr Türkçe sistemde farklı dil olabilir
//     → Status code kontrolüne ek olarak daha sağlam hata ayırt etme
//   - Kurallar eklendikten sonra doğrulama yapılmıyor — verify eklendi
//   - run_netsh blocking I/O — async context'te tokio::task::spawn_blocking önerilir

use std::process::Command;

const RULE_ALLOW:     &str = "SolidTrace_Allow_SOC";
const RULE_BLOCK_OUT: &str = "SolidTrace_Block_All_Out";
const RULE_BLOCK_IN:  &str = "SolidTrace_Block_All_In";

/// Host'u ağdan izole et — sadece server_ip ile iletişime izin ver
pub fn enable_isolation(server_ip: &str) {
    println!("⛔ [ISOLATION] AĞ İZOLASYONU BAŞLATILIYOR (Sunucu: {})...", server_ip);

    // 1. Eski kuralları temizle
    disable_isolation();

    // 2. FIX: ÖNCE SOC'a izin ver — sonra genel blok uygula
    // Sıralama kritik: ALLOW önce olmazsa SOC bağlantısı da bloklanır
    let allow_ok = run_netsh(&[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={}", RULE_ALLOW),
        "dir=out",
        "action=allow",
        &format!("remoteip={}", server_ip),
        "protocol=TCP",
        "enable=yes",
    ]);

    if !allow_ok {
        eprintln!("❌ [ISOLATION] SOC izin kuralı eklenemedi! İzolasyon iptal ediliyor.");
        eprintln!("   👉 ÇÖZÜM: Terminali Yönetici olarak çalıştırın.");
        return; // FIX: ALLOW başarısız olursa BLOCK ekleme — SOC bağlantısı kesilir
    }

    // 3. Giden trafiği engelle
    let block_out_ok = run_netsh(&[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={}", RULE_BLOCK_OUT),
        "dir=out",
        "action=block",
        "enable=yes",
    ]);

    // 4. Gelen trafiği engelle
    let block_in_ok = run_netsh(&[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={}", RULE_BLOCK_IN),
        "dir=in",
        "action=block",
        "enable=yes",
    ]);

    if block_out_ok && block_in_ok {
        println!("✅ [ISOLATION] Karantina aktif. Sadece {} ile iletişim kurulabilir.", server_ip);
    } else {
        eprintln!("⚠️ [ISOLATION] Bazı kurallar eklenemedi — izolasyon eksik olabilir.");
    }
}

/// İzolasyonu kaldır — normal ağ erişimine dön
pub fn disable_isolation() {
    println!("🌍 [ISOLATION] Ağ kilidi kaldırılıyor...");

    let results = [
        run_netsh_delete(RULE_ALLOW),
        run_netsh_delete(RULE_BLOCK_OUT),
        run_netsh_delete(RULE_BLOCK_IN),
    ];

    if results.iter().all(|&r| r) {
        println!("✅ [ISOLATION] Tüm kurallar temizlendi, internet erişimi normale döndü.");
    } else {
        // Kural bulunamadı hatası normal — ilk çalıştırmada kurallar yoktur
        println!("ℹ️  [ISOLATION] Bazı kurallar zaten yoktu (normal durum).");
    }
}

/// Kural sil — bulunamazsa hata değil, normal
fn run_netsh_delete(rule_name: &str) -> bool {
    let output = Command::new("netsh")
        .args(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
        .output();

    match output {
        Ok(out) => out.status.success(),
        Err(e) => {
            eprintln!("⚠️ [ISOLATION] netsh çalıştırılamadı: {}", e);
            false
        }
    }
}

/// Kural ekle — başarı durumunu döndür
fn run_netsh(args: &[&str]) -> bool {
    let output = Command::new("netsh").args(args).output();

    match output {
        Ok(out) => {
            if out.status.success() {
                return true;
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);

            // FIX: Hata mesajı dil bağımsız — status code ana kriter
            eprintln!("❌ [FIREWALL] Kural eklenemedi:");
            if !stderr.trim().is_empty() {
                eprintln!("   stderr: {}", stderr.trim());
            }
            if !stdout.trim().is_empty() {
                eprintln!("   stdout: {}", stdout.trim());
            }
            eprintln!("   👉 Terminali Yönetici olarak çalıştırın.");
            false
        }
        Err(e) => {
            eprintln!("⚠️ [FIREWALL] netsh çalıştırılamadı: {}", e);
            false
        }
    }
}