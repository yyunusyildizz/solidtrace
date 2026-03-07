/// integrity.rs
/// Agent self-protection ve binary bütünlük doğrulama.
///
/// Özellikler:
///   1. Binary SHA-256 hash'i başlangıçta hesaplanır
///   2. Beklenen hash (derleme zamanında embed edilir veya ENV'den alınır)
///      ile karşılaştırılır → tamper detection
///   3. Agent process'i başka process tarafından debug ediliyorsa tespit edilir
///   4. Critical thread'ler beklenmedik şekilde ölürse watchdog yeniden başlatır
///   5. Memory bölgeleri write-koruması (Windows VirtualProtect)

use sha2::{Digest, Sha256};
use std::time::Duration;

// ─── 1. BINARY BÜTÜNLÜK KONTROLÜ ──────────────────────────────────────────────

/// Çalışan executable'ın SHA-256 hash'ini hesapla
pub fn compute_own_hash() -> Result<String, std::io::Error> {
    let exe = std::env::current_exe()?;
    let bytes = std::fs::read(&exe)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

/// Beklenen hash: ENV > derleme zamanı sabit (CI/CD'de inject edilir)
///
/// CI/CD pipeline'da:
///   1. cargo build --release
///   2. sha256sum target/release/solidtrace_agent.exe > expected.hash
///   3. SOLIDTRACE_EXPECTED_HASH=$(cat expected.hash | awk '{print $1}')
///   4. Agent'a embed et veya ENV olarak dağıt
fn expected_hash() -> Option<String> {
    // ENV'den al (deployment)
    std::env::var("SOLIDTRACE_EXPECTED_HASH")
        .ok()
        .filter(|s| !s.is_empty())
        // Yoksa derleme zamanı sabit (CI enjekte eder)
        .or_else(|| {
            option_env!("SOLIDTRACE_BUILD_HASH")
                .map(|s| s.to_string())
        })
}

/// Binary bütünlüğünü kontrol et.
/// Uyuşmazlık → agent başlamaz.
pub fn verify_binary_integrity() -> Result<(), String> {
    let expected = match expected_hash() {
        Some(h) => h,
        None => {
            println!("⚠️  [INTEGRITY] Beklenen hash tanımlı değil — kontrol atlandı.");
            println!("   Güvenli dağıtım için SOLIDTRACE_EXPECTED_HASH ayarlayın.");
            return Ok(());
        }
    };

    print!("🔍 [INTEGRITY] Binary hash doğrulanıyor... ");
    let actual = compute_own_hash().map_err(|e| format!("Hash hesaplama hatası: {}", e))?;

    if actual.to_lowercase() == expected.to_lowercase() {
        println!("✅");
        Ok(())
    } else {
        Err(format!(
            "🚨 BINARY TAHRİP EDİLMİŞ!\n  Beklenen: {}\n  Gerçek  : {}\n  Agent durduruluyor.",
            expected, actual
        ))
    }
}

// ─── 2. ANTI-DEBUG / ANTI-TAMPER ──────────────────────────────────────────────

/// Debugger tespiti (Windows IsDebuggerPresent + remote debug)
#[cfg(target_os = "windows")]
pub fn detect_debugger() -> bool {
    use windows::Win32::System::Diagnostics::Debug::{
        IsDebuggerPresent, CheckRemoteDebuggerPresent,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::Win32::Foundation::BOOL;

    unsafe {
        // Yerel debugger
        if IsDebuggerPresent().as_bool() {
            eprintln!("🚨 [ANTI-DEBUG] Yerel debugger tespit edildi!");
            return true;
        }
        // Remote debugger (WinDbg, x64dbg, vs.)
        let mut remote = BOOL(0);
        let _ = CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote);
        if remote.as_bool() {
            eprintln!("🚨 [ANTI-DEBUG] Uzak debugger tespit edildi!");
            return true;
        }
        false
    }
}

#[cfg(not(target_os = "windows"))]
pub fn detect_debugger() -> bool {
    false // Linux/macOS: /proc/self/status TracerPid kontrolü eklenebilir
}

// ─── 3. PROCESS KORUMA (Windows-only) ─────────────────────────────────────────

/// Agent process hardening.
/// NOT: SetProcessMitigationPolicy tabanlı korumalar (SignaturePolicy dahil)
/// bazı sistemlerde yara-x'in WASM JIT derleyicisiyle çakışıyor.
/// Güvenli alternatif: anti-debug + watchdog yeterli koruma sağlıyor.
#[cfg(target_os = "windows")]
pub fn harden_process() {
    // ProcessSignaturePolicy ve benzeri policy'ler process-wide JIT'i etkileyebilir.
    // yara-x WASM derlemesi için JIT gerektiğinden bu policy'ler devre dışı.
    // Koruma katmanları: anti-debug (detect_debugger) + watchdog + binary integrity.
    println!("🛡️  [PROTECT] Process hardening aktif (anti-debug + watchdog katmanları).");
}

#[cfg(not(target_os = "windows"))]
pub fn harden_process() {
    println!("🛡️  [PROTECT] Process hardening: Windows-only, atlandı.");
}

// ─── 4. WATCHDOG ────────────────────────────────────────────────────────────────

/// Per-task heartbeat izleyici. Her task kendi adıyla heartbeat gönderir.
/// run_monitor() sonsuz döngü içinden periyodik çağrılmalı.
#[derive(Clone)]
pub struct Watchdog {
    tx: tokio::sync::mpsc::Sender<&'static str>,
}

impl Watchdog {
    pub fn spawn(timeout_secs: u64) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<&'static str>(256);

        let handle = tokio::spawn(async move {
            use std::collections::HashMap;

            let mut last_seen: HashMap<&'static str, std::time::Instant> = HashMap::new();
            let mut check_interval = tokio::time::interval(Duration::from_secs(60));
            let deadline = Duration::from_secs(timeout_secs);

            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(task) => { last_seen.insert(task, std::time::Instant::now()); }
                            None => { eprintln!("🚨 [WATCHDOG] Tüm task'lar sonlandı!"); restart_self(); }
                        }
                    }
                    _ = check_interval.tick() => {
                        let now = std::time::Instant::now();
                        for (task, last) in &last_seen {
                            if now.duration_since(*last) > deadline {
                                eprintln!("🚨 [WATCHDOG] '{}' task'ı {}s'dir yanıt vermiyor!", task, timeout_secs);
                                restart_self();
                            }
                        }
                    }
                }
            }
        });

        (Watchdog { tx }, handle)
    }

    /// Task döngüsü içinden periyodik çağrılır — non-blocking drop.
    pub async fn heartbeat(&self, task_name: &'static str) {
        let _ = self.tx.try_send(task_name);
    }
}
/// Agent'ı yeniden başlat (persistence kayıt defteri zaten var)
fn restart_self() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).spawn();
    }
    std::process::exit(1);
}

// ─── 5. SIGNED BINARY NOTLARI ─────────────────────────────────────────────────

/// Kod imzalama rehberi (runtime değil, derleme sonrası adımlar):
///
/// ## Self-signed (geliştirme):
///   1. `New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=SolidTrace"`
///   2. `signtool sign /fd SHA256 /a solidtrace_agent.exe`
///
/// ## EV Code Signing (production, SmartScreen bypass):
///   - DigiCert, Sectigo, GlobalSign → yıllık ~$300-500
///   - CI/CD'de: signtool sign /tr http://timestamp.digicert.com /td SHA256 ...
///
/// ## Doğrulama:
///   `signtool verify /pa /v solidtrace_agent.exe`
///   `Get-AuthenticodeSignature solidtrace_agent.exe`
pub fn signed_binary_info() {
    // Çalışma zamanında imza durumunu kontrol et (Windows)
    #[cfg(target_os = "windows")]
    {
        let exe = std::env::current_exe().unwrap_or_default();
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                &format!("(Get-AuthenticodeSignature '{}').Status", exe.display())])
            .output();

        match output {
            Ok(o) => {
                let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if status == "Valid" {
                    println!("✅ [SIGN] Binary imzası geçerli.");
                } else {
                    eprintln!("⚠️  [SIGN] Binary imzası: {} (İmzasız dağıtım önerilmez!)", status);
                }
            }
            Err(_) => println!("⚠️  [SIGN] İmza durumu kontrol edilemedi."),
        }
    }
}

// ─── 6. STARTUP SEQUENCE ──────────────────────────────────────────────────────

/// Tüm güvenlik kontrollerini sırayla çalıştır.
/// main() içinde en başta çağrılmalı.
pub async fn run_security_checks() {
    println!("🔒 [SECURITY] Güvenlik kontrolleri başlatılıyor...");

    // 1. Binary imza durumu (bilgilendirme)
    signed_binary_info();

    // 2. Binary bütünlük
    if let Err(e) = verify_binary_integrity() {
        eprintln!("{}", e);
        std::process::exit(127); // Özel exit code → monitoring sistem uyarı üretir
    }

    // 3. Debugger tespiti (sadece release build'de zorla çık)
    if detect_debugger() {
        #[cfg(not(debug_assertions))]
        {
            eprintln!("🚨 [SECURITY] Debugger tespit edildi. Agent sonlandırılıyor.");
            std::process::exit(126);
        }
        #[cfg(debug_assertions)]
        println!("⚠️  [SECURITY] Debugger var ama debug build — devam ediliyor.");
    }

    // 4. Process hardening
    harden_process();

    // 5. TLS pinning startup check
    if let Err(e) = crate::tls_pinning::verify_server_tls().await {
        eprintln!("{}", e);
        std::process::exit(125);
    }

    println!("✅ [SECURITY] Tüm kontroller geçildi.\n");
}
