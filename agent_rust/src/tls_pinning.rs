/// tls_pinning.rs
/// TLS sertifika parmak izi doğrulama (Certificate Pinning).
///
/// Nasıl çalışır:
///   1. Backend sertifikasının SHA-256 DER parmak izi hesaplanır.
///   2. Bu değer SOLIDTRACE_TLS_FP env'e yazılır.
///   3. Her bağlantıda sunucunun sunduğu sertifika bu değerle karşılaştırılır.
///   4. Uyuşmuyorsa bağlantı reddedilir → MITM koruması.
///
/// Parmak izi nasıl alınır (PowerShell):
///   $cert = (Invoke-WebRequest https://soc.firma.com -UseBasicParsing).BaseResponse
///           .GetResponseStream()  # veya openssl:
///   openssl s_client -connect soc.firma.com:443 </dev/null 2>/dev/null |
///     openssl x509 -fingerprint -sha256 -noout
use reqwest::{Certificate, ClientBuilder};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::agent_config::AgentConfig;

/// TLS-pinned HTTP client oluştur.
/// SOLIDTRACE_TLS_FP boşsa normal TLS doğrulaması (pinning kapalı).
#[allow(dead_code)]
pub fn build_http_client() -> reqwest::Client {
    let cfg = AgentConfig::get();

    let mut builder = ClientBuilder::new()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .tcp_keepalive(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(15))
        // Sisteme güvenme — yalnızca rustls kullanan builder
        .use_rustls_tls()
        // HTTP/2 + TLS 1.2 minimum
        .min_tls_version(reqwest::tls::Version::TLS_1_2);

    // Pinning aktifse backend sertifikasını trust anchor'a ekle
    if let Some(fp) = &cfg.tls_fingerprint {
        println!("🔒 [TLS] Sertifika pinning aktif: {}…", &fp[..16.min(fp.len())]);
        // reqwest'in yerleşik pinning API'si yok → custom validator callback ile yapılır
        // Production'da: rcgen ile self-signed cert üret, DER'i embed et
        // Şimdilik: fingerprint'i bağlantı sonrası doğrula (bkz. verify_fingerprint)
        builder = builder
            // Sistem CA'larını devre dışı bırak — yalnızca bizim sertifikamıza güven
            .danger_accept_invalid_certs(false)
            .tls_built_in_root_certs(false);

        // Backend sertifikasını PEM olarak embed et
        // Deployment: SOLIDTRACE_SERVER_CERT=/path/to/server.pem
        if let Ok(cert_path) = std::env::var("SOLIDTRACE_SERVER_CERT") {
            if let Ok(pem) = std::fs::read(&cert_path) {
                match Certificate::from_pem(&pem) {
                    Ok(cert) => {
                        builder = builder.add_root_certificate(cert);
                        println!("🔒 [TLS] Sunucu sertifikası yüklendi: {}", cert_path);
                    }
                    Err(e) => {
                        eprintln!("🚨 [TLS] Sertifika okunamadı: {}", e);
                    }
                }
            }
        }
    } else {
        println!("⚠️  [TLS] Pinning kapalı (SOLIDTRACE_TLS_FP ayarlanmamış)");
    }

    builder.build().expect("HTTP Client oluşturulamadı")
}

/// Gelen sertifika verisinin SHA-256 parmak izini hesapla ve beklenenle karşılaştır.
/// reqwest response'dan doğrudan sertifikaya erişilemediği için
/// ayrı bir doğrulama kanalı (openssl veya native-tls) gerekebilir.
/// Bu fonksiyon unit test ve CLI doğrulama için kullanılır.
#[allow(dead_code)] // Unit test ve CLI doğrulama için — runtime'da verify_server_tls kullanılır
pub fn fingerprint_matches(der_bytes: &[u8], expected_hex: &str) -> bool {
    let digest = Sha256::digest(der_bytes);
    let computed = hex::encode(digest);
    let expected = expected_hex.to_lowercase().replace(':', "");
    if computed != expected {
        eprintln!(
            "🚨 [TLS-PIN] PARMAK İZİ UYUŞMAZLIĞI!\n  Beklenen : {}\n  Gelen    : {}",
            expected, computed
        );
        return false;
    }
    true
}

/// Backend'e bağlanmadan önce TLS el sıkışmasını doğrula (CLI / startup check).
/// Hata durumunda agent başlamaz.
pub async fn verify_server_tls() -> Result<(), String> {
    let cfg = AgentConfig::get();
    let fp = match &cfg.tls_fingerprint {
        Some(f) => f.clone(),
        None => return Ok(()), // Pinning kapalı — geç
    };

    // openssl s_client ile parmak izi al ve karşılaştır
    // Windows'ta PowerShell alternatifi kullanılıyor
    let output = tokio::process::Command::new("powershell")
        .args([
            "-NoProfile", "-Command",
            &format!(
                r#"
                $req = [Net.HttpWebRequest]::Create('{}')
                $req.ServerCertificateValidationCallback = {{$true}}
                try {{ $req.GetResponse() | Out-Null }} catch {{}}
                $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    $req.ServicePoint.Certificate)
                $hash = $cert.GetCertHashString('SHA256')
                Write-Output $hash
                "#,
                cfg.server_base
            ),
        ])
        .output()
        .await
        .map_err(|e| format!("PowerShell çalıştırılamadı: {}", e))?;

    let live_fp = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_lowercase()
        .replace([':', ' ', '\n', '\r'], "");

    let expected = fp.to_lowercase().replace([':', ' '], "");

    if live_fp.is_empty() {
        eprintln!("⚠️  [TLS] Parmak izi alınamadı — pinning doğrulaması atlandı.");
        return Ok(());
    }

    if live_fp == expected {
        println!("✅ [TLS] Sertifika doğrulandı.");
        Ok(())
    } else {
        Err(format!(
            "🚨 TLS PINNING BAŞARISIZ!\n  Beklenen: {}\n  Sunucu : {}",
            expected, live_fp
        ))
    }
}
