// canary_monitor.rs - v3.0 (REVISED - INFINITE LOOP FIXED)
// Düzeltmeler:
//   - CANARY_DIR hardcoded → env değişkeninden alınıyor
//   - Sadece passwords.txt izleniyor → birden fazla tuzak dosyası desteği
//   - thread::sleep → tokio::time::sleep (async bağlam uyumu)
//   - EventKind::Access sadece okuma diye alarm verilmiyor AMA bazı ransomware önce okur
//     → Erişim sayacı eklendi, kısa sürede çok fazla Access varsa alarm üret
//   - KRİTİK DÜZELTME: Modify eventinde dosyanın yeniden yazılması (Infinite Loop) engellendi.
//     Self-healing SADECE dosya tamamen silindiğinde (Remove) çalışacak.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use crate::api_client::ApiClient;

fn canary_dir() -> String {
    // FIX: env'den al, yoksa varsayılan kullan
    std::env::var("CANARY_DIR")
        .unwrap_or_else(|_| r"C:\Users\Public\SolidTrace_Honeypot".to_string())
}

// Tuzak dosyaları — birden fazla dosya daha gerçekçi bir honeypot oluşturur
fn canary_files(dir: &str) -> Vec<(PathBuf, &'static [u8])> {
    vec![
        (
            PathBuf::from(format!("{}\\passwords.txt", dir)),
            b"admin:123456\nroot:toor\nfacebook:12345" as &[u8],
        ),
        (
            PathBuf::from(format!("{}\\credit_cards.txt", dir)),
            b"VISA: 4111111111111111 CVV: 123 EXP: 12/28" as &[u8],
        ),
        (
            PathBuf::from(format!("{}\\backup_keys.txt", dir)),
            b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\nSECRET=wJalrXUtnFEMI" as &[u8],
        ),
    ]
}

pub async fn deploy_and_watch(client: Arc<ApiClient>) {
    let dir = canary_dir();
    println!("🐤 [CANARY] Tuzak Klasörü: {}", dir);

    setup_honeypot(&dir);

    // FIX: notify → tokio mpsc ile async uyumlu hale getirildi
    let (tx, mut rx) = mpsc::channel(50);

    let mut watcher = match RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        Config::default(),
    ) {
        Ok(w)  => w,
        Err(e) => {
            eprintln!("⚠️ [CANARY] Watcher başlatılamadı: {}", e);
            return;
        }
    };

    if let Err(e) = watcher.watch(Path::new(&dir), RecursiveMode::Recursive) {
        eprintln!("⚠️ [CANARY] İzleme başlatılamadı: {}", e);
        return;
    }

    println!("✅ [CANARY] GÖZLER AÇIK! {} dosya izleniyor.", canary_files(&dir).len());

    // FIX: Access sayacı — kısa sürede çok erişim = şüpheli tarama davranışı
    let mut access_count   = 0u32;
    let mut access_window  = Instant::now();

    while let Some(res) = rx.recv().await {
        match res {
            Ok(event) => {
                // Hangi canary dosyası etkilendi?
                let affected: Vec<PathBuf> = event.paths.iter()
                    .filter(|p| {
                        canary_files(&dir).iter().any(|(cp, _)| cp == *p)
                    })
                    .cloned()
                    .collect();

                if affected.is_empty() {
                    continue;
                }

                let file_name = affected[0]
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "bilinmeyen".to_string());

                match event.kind {
                    // FIX: Access izleniyor ama her access alarm vermiyor
                    // Kısa sürede 5+ access → şüpheli tarama davranışı
                    EventKind::Access(_) => {
                        access_count += 1;
                        if access_window.elapsed() > Duration::from_secs(10) {
                            access_count  = 1;
                            access_window = Instant::now();
                        }
                        if access_count >= 5 {
                            let msg = format!(
                                "🔍 HONEYPOT TARAMASI: {} saniyede {} erişim — {}",
                                access_window.elapsed().as_secs(), access_count, file_name
                            );
                            println!("⚠️ [CANARY] {}", msg);
                            let c = client.clone();
                            let m = msg.clone();
                            tokio::spawn(async move {
                                let _ = c.send_event(
                                    "CANARY_SCAN_DETECTED", &m, "HIGH",
                                    std::process::id(), None
                                ).await;
                            });
                            access_count  = 0;
                            access_window = Instant::now();
                        }
                    }

                    // KRİTİK FIX: Sadece Remove (Silme) durumunda Self-Healing çalışır
                    EventKind::Remove(_) => {
                        println!("🔥 [RANSOMWARE] KRİTİK! Tuzak dosya SİLİNDİ → {}", file_name);

                        let details = format!("Honeypot SİLİNDİ: {} | Dosya: {}", dir, file_name);
                        let c = client.clone();
                        let d = details.clone();
                        let pid = std::process::id();
                        
                        tokio::spawn(async move {
                            let _ = c.send_event("RANSOMWARE_ACTIVITY", &d, "CRITICAL", pid, None).await;
                        });

                        // Self-healing sadece dosya yok olduğunda (Remove) devreye girer
                        let dir_clone = dir.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            setup_honeypot(&dir_clone);
                            println!("✨ [SELF-HEALING] Eksik tuzak dosyaları yenilendi.");
                        });
                    }

                    // Modify (Değiştirme) durumunda SADECE ALARM verilir, dosya yenilenmez (Sonsuz döngüyü önler)
                    EventKind::Modify(_) => {
                        println!("🔥 [RANSOMWARE] KRİTİK! Tuzak dosya DEĞİŞTİRİLDİ → {}", file_name);

                        let details = format!("Honeypot DEĞİŞTİRİLDİ: {} | Dosya: {}", dir, file_name);
                        let c = client.clone();
                        let d = details.clone();
                        let pid = std::process::id();

                        tokio::spawn(async move {
                            let _ = c.send_event("RANSOMWARE_ACTIVITY", &d, "CRITICAL", pid, None).await;
                        });
                        // DİKKAT: Burada setup_honeypot() çağrılmaz!
                    }

                    _ => {} // Diğer önemsiz eventleri yoksay
                }
            }
            Err(e) => eprintln!("⚠️ [CANARY] İzleme hatası: {:?}", e),
        }
    }
}

fn setup_honeypot(dir: &str) {
    let _ = fs::create_dir_all(dir);

    for (path, content) in canary_files(dir) {
        // Dosya zaten varsa dokunma, yoksa oluştur. 
        // Bu, Modify eventini gereksiz yere tetiklemememizi sağlar.
        if !path.exists() {
            match File::create(&path) {
                Ok(mut f) => {
                    let _ = f.write_all(content);
                }
                Err(e) => eprintln!("⚠️ [CANARY] Dosya oluşturulamadı {:?}: {}", path, e),
            }
        }
    }

    println!("🔨 [CANARY] {} tuzak dosyası hazır/kontrol edildi.", canary_files(dir).len());
}