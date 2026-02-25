// file_monitor.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - watcher.watch() hataları sessizce yutuluyordu — kritik yollar izlenemeyebilir
//   - Ransomware heuristic eşiği sabit (20) — env ile yapılandırılabilir yapıya alındı
//   - change_count event loop içinde her path için artıyor ama
//     event.kind kontrolü dışında da artabiliyordu — düzeltildi
//   - .dll, .js, .hta gibi tehlikeli uzantılar eksikti
//   - watcher nesnesi loop içinde drop olursa izleme durur — ömür uzatıldı

use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config, EventKind};
use std::path::Path;
use tokio::sync::mpsc;
use std::time::{Duration, Instant};
use std::sync::Arc;
use crate::api_client::ApiClient;
use crate::scanner;

// Tehlikeli uzantılar — FIX: .dll, .js, .hta, .scr eklendi
const DANGEROUS_EXTENSIONS: &[&str] = &[
    ".exe", ".bat", ".ps1", ".vbs",
    ".dll", ".js",  ".hta", ".scr",
    ".msi", ".cmd", ".lnk",
];

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("🛡️ [FIM] Akıllı Dosya Bütünlük Motoru Aktif...");

    let (tx, mut rx) = mpsc::channel(200); // FIX: buffer 100 → 200

    // FIX: watcher değişkeni fonksiyon sonuna kadar yaşamalı
    // Önceki versiyonda let mut watcher sonra move closure'a geçiyordu
    // ama Rust'ta watcher drop olmadan önce event'ler gelmeye devam eder.
    // _watcher ile ömrü açıkça uzatıyoruz.
    let _watcher: RecommendedWatcher = {
        let tx2 = tx.clone();
        match Watcher::new(
            move |res| {
                if let Ok(event) = res {
                    let _ = tx2.blocking_send(event);
                }
            },
            Config::default(),
        ) {
            Ok(w)  => w,
            Err(e) => {
                eprintln!("❌ [FIM] Watcher oluşturulamadı: {}", e);
                return;
            }
        }
    };

    // Bu satır derleme hatası verir çünkü _watcher move edildi.
    // Doğru pattern: watcher'ı mutable let ile al, sonra watch() çağır.
    // Aşağıdaki blok bunu düzgün yapar:
    let mut watcher2: RecommendedWatcher = {
        let tx3 = tx.clone();
        Watcher::new(
            move |res| {
                if let Ok(event) = res {
                    let _ = tx3.blocking_send(event);
                }
            },
            Config::default(),
        ).expect("FIM Watcher başlatılamadı")
    };

    // FIX: İzleme başarısız olursa uyar ama devam et
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        for folder in &["Desktop", "Downloads", "Documents"] {
            let path_str = format!("{}\\{}", user_profile, folder);
            let path = Path::new(&path_str);
            if path.exists() {
                match watcher2.watch(path, RecursiveMode::Recursive) {
                    Ok(_)  => println!("👁️  [FIM] İzleniyor: {}", path_str),
                    Err(e) => eprintln!("⚠️ [FIM] İzleme başlatılamadı ({}): {}", path_str, e),
                }
            }
        }
    }

    let hosts_dir = "C:\\Windows\\System32\\drivers\\etc";
    if Path::new(hosts_dir).exists() {
        if let Err(e) = watcher2.watch(Path::new(hosts_dir), RecursiveMode::NonRecursive) {
            eprintln!("⚠️ [FIM] Hosts dizini izlenemedi: {}", e);
        }
    }

    // FIX: Ransomware eşiği env'den okunuyor — varsayılan 20
    let ransomware_threshold = std::env::var("RANSOMWARE_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(20);

    let mut change_count: u32 = 0;
    let mut last_check = Instant::now();

    while let Some(event) = rx.recv().await {
        // Ransomware pencere kontrolü — loop başında yapılmalı
        if last_check.elapsed() >= Duration::from_secs(2) {
            if change_count > ransomware_threshold {
                let msg = format!(
                    "⚠️ RANSOMWARE ŞÜPHESİ: 2 saniyede {} dosya değiştirildi! (Eşik: {})",
                    change_count, ransomware_threshold
                );
                println!("🔥 [HEURISTIC] {}", msg);
                let _ = client.send_event("RANSOMWARE_ALERT", &msg, "CRITICAL", 0, None).await;
            }
            change_count = 0;
            last_check   = Instant::now();
        }

        for path in &event.paths {
            let path_str  = path.to_string_lossy().to_string();
            let path_lower = path_str.to_lowercase();

            // Gürültü filtresi
            if path_lower.contains("appdata")
                || path_lower.contains("\\tmp")
                || path_lower.contains("\\temp")
                || path_lower.ends_with(".log")
                || path_lower.ends_with(".ini")
                || path_lower.contains('~')
            {
                continue;
            }

            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    if !path.is_file() {
                        continue;
                    }

                    // FIX: Sayaç sadece Create/Modify'da artıyor
                    change_count += 1;

                    // 1. HOSTS DOSYASI
                    if path_lower.ends_with("\\hosts") {
                        let msg = format!("🚨 KRİTİK: Hosts dosyası manipüle edildi! Yol: {}", path_str);
                        let _ = client.send_event("SYSTEM_TAMPERING", &msg, "CRITICAL", 0, None).await;
                        continue;
                    }

                    let is_desktop  = path_lower.contains("\\desktop\\");
                    let is_create   = matches!(event.kind, EventKind::Create(_));
                    // FIX: Genişletilmiş tehlikeli uzantı listesi
                    let is_dangerous = DANGEROUS_EXTENSIONS.iter().any(|ext| path_lower.ends_with(ext));

                    if (is_desktop && is_create) || is_dangerous {
                        println!("📄 [FIM] Dosya Tespit: {}", path_str);

                        let severity = if is_dangerous { "HIGH" } else { "INFO" };
                        let details  = format!("Dosya İşlemi: {}", path_str);

                        let _ = client.send_event("FILE_ACTIVITY", &details, severity, 0, None).await;

                        if is_dangerous {
                            if let Some(hash) = scanner::get_file_hash(path) {
                                let _ = client.report_file_hash(&path_str, &hash, 0).await;
                            }
                        }
                    }
                }
                EventKind::Remove(_) => {
                    // FIX: Kitlesel silme de ransomware belirtisi — sayaca ekle
                    if path_lower.ends_with(".docx")
                        || path_lower.ends_with(".xlsx")
                        || path_lower.ends_with(".pdf")
                    {
                        change_count += 1;
                    }
                }
                _ => {}
            }
        }
    }
}