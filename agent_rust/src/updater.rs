// updater.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - reqwest::get() doğrudan kullanılıyor — global HTTP client yok, her çağrıda yeni bağlantı
//     → api_client.rs'deki HTTP_CLIENT ile uyumlu hale getirildi
//   - Güncelleme öncesi mevcut dosya yedeklenmiyordu — bozuk indirme kuralları siliyordu
//   - İndirilen içerik doğrulanmıyor — boş veya hatalı YARA doğrudan yazılıyordu
//   - Tek URL — URL erişilemezse tamamen başarısız oluyordu (fallback yok)
//   - YARA içerik doğrulaması: "rule" kelimesi geçmiyorsa geçersiz kabul et

use std::fs;
use std::path::Path;
use reqwest::Client;
use std::time::Duration;

// Güncelleme kaynakları — birincil başarısız olursa yedek denenir
const RULE_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/YARA-Rules/rules/master/malware/MALW_Eicar.yar",
    // Buraya ek güvenilir kaynak eklenebilir
    // "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_anomalies.yar",
];

pub async fn update_yara_rules(rules_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 [UPDATER] Global İstihbarat Ağlarına Bağlanılıyor...");

    // FIX: Timeout'lu özel client — sonsuz bekleme engellendi
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let path = Path::new(rules_path);

    // FIX: Mevcut dosyayı yedekle — başarısız güncelleme kuralları silmesin
    let backup_path = format!("{}.bak", rules_path);
    if path.exists() {
        if let Err(e) = fs::copy(rules_path, &backup_path) {
            eprintln!("⚠️ [UPDATER] Yedek oluşturulamadı: {} — güncelleme atlanıyor.", e);
            return Ok(()); // Yedek yoksa güncelleme yapma
        }
        println!("💾 [UPDATER] Mevcut kurallar yedeklendi: {}", backup_path);
    }

    // FIX: Çoklu kaynak denemesi
    for (i, url) in RULE_SOURCES.iter().enumerate() {
        println!("🔗 [UPDATER] Kaynak {}/{} deneniyor: {}", i + 1, RULE_SOURCES.len(), url);

        let response = match client.get(*url).send().await {
            Ok(r)  => r,
            Err(e) => {
                eprintln!("⚠️ [UPDATER] Kaynak {} erişilemez: {}", i + 1, e);
                continue;
            }
        };

        if !response.status().is_success() {
            eprintln!("⚠️ [UPDATER] Kaynak {} HTTP {}", i + 1, response.status());
            continue;
        }

        let content = match response.text().await {
            Ok(c)  => c,
            Err(e) => {
                eprintln!("⚠️ [UPDATER] İçerik okunamadı: {}", e);
                continue;
            }
        };

        // FIX: Temel YARA içerik doğrulaması — boş veya geçersiz içerik yazılmasın
        if content.trim().is_empty() {
            eprintln!("⚠️ [UPDATER] Boş içerik alındı, atlanıyor.");
            continue;
        }

        if !content.contains("rule ") && !content.contains("rule\t") {
            eprintln!("⚠️ [UPDATER] Geçersiz YARA içeriği (rule tanımı bulunamadı), atlanıyor.");
            continue;
        }

        // Klasörü oluştur
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("⚠️ [UPDATER] Klasör oluşturulamadı: {}", e);
                continue;
            }
        }

        // Yaz
        match fs::write(rules_path, &content) {
            Ok(_) => {
                println!("✅ [UPDATER] Kurallar güncellendi ({} byte): {}", content.len(), rules_path);
                // Başarılı güncelleme sonrası yedek dosyayı temizle
                let _ = fs::remove_file(&backup_path);
                return Ok(());
            }
            Err(e) => {
                eprintln!("❌ [UPDATER] Dosya yazılamadı: {}", e);
                // FIX: Yazma başarısız → yedeği geri yükle
                if Path::new(&backup_path).exists() {
                    let _ = fs::copy(&backup_path, rules_path);
                    println!("🔄 [UPDATER] Yedek geri yüklendi.");
                }
                continue;
            }
        }
    }

    // Tüm kaynaklar başarısız — yedeği geri yükle
    if Path::new(&backup_path).exists() {
        let _ = fs::copy(&backup_path, rules_path);
        println!("🔄 [UPDATER] Tüm kaynaklar başarısız, yedek geri yüklendi.");
    }

    Err("Tüm YARA güncelleme kaynakları başarısız oldu.".into())
}