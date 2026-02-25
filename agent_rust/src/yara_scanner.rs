// yara_scanner.rs - v2.0 (REVISED)
// Düzeltmeler:
//   - unwrap_or_else içinde panic riski — compiler.build() başarısız olursa
//     scanner çalışmaz ama sessizce devam eder; hata açıkça loglanıyor
//   - scan_file hatası tamamen yutuluyordu (_) — erişim hatası vs. ayırt edilmeli
//   - YaraScanner::new() kurallar geçersizse dummy kural ile devam ediyor
//     ama bunu çağıran (scanner.rs) bilmiyor — hata loglanıyor
//   - Scanner her dosya için yeniden oluşturuluyor — bu doğru (Scanner !Send)
//     ama dosya erişim hatası ile YARA eşleşmemesi ayrı loglanmalı

use std::path::Path;
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraScanner {
    rules: Rules,
}

impl YaraScanner {
    pub fn new(rules_path: &str) -> Self {
        println!("⚙️ [YARA] Kurallar derleniyor: {}", rules_path);

        let (rule_source, is_real) = match std::fs::read_to_string(rules_path) {
            Ok(content) if !content.trim().is_empty() => {
                println!("✅ [YARA] Kural dosyası okundu ({} byte).", content.len());
                (content, true)
            }
            Ok(_) => {
                eprintln!("⚠️ [YARA] Kural dosyası boş — dummy kural ile devam ediliyor.");
                ("rule Dummy { condition: false }".to_string(), false)
            }
            Err(e) => {
                eprintln!("⚠️ [YARA] Kural dosyası okunamadı ({}): {} — dummy kural aktif.", rules_path, e);
                ("rule Dummy { condition: false }".to_string(), false)
            }
        };

        let mut compiler = Compiler::new();

        if let Err(e) = compiler.add_source(rule_source.as_str()) {
            // FIX: Derleme hatası loglanıyor — sessizce geçilmiyordu
            eprintln!("❌ [YARA] Kural derleme hatası: {} — dummy kural ile devam.", e);
            let mut fallback = Compiler::new();
            let _ = fallback.add_source("rule Dummy { condition: false }");
            return YaraScanner {
                rules: fallback.build(),
            };
        }

        let rules = compiler.build();

        if is_real {
            println!("✅ [YARA] Kurallar mühürlendi ve taramaya hazır!");
        }

        YaraScanner { rules }
    }

    /// Dosyayı YARA kurallarıyla tara.
    /// Eşleşme bulunursa kural adını döndürür, bulunmazsa None.
    pub fn scan_file(&self, path: &Path) -> Option<String> {
        if !path.exists() {
            return None;
        }

        // Dosya boyutu kontrolü — 100 MB üzeri dosyaları atla
        // eprintln yerine sessiz return: büyük dosyalar zaten whitelist'te olmali
        // Tekrar eden uyarilar (VS Code gibi cok PID açan uygulamalar) engellendi
        const MAX_SCAN_SIZE: u64 = 100 * 1024 * 1024;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_SCAN_SIZE {
                // Sessiz skip — whitelist'ten kaçan büyük dosyalar için debug log yeterli
                // eprintln kaldırıldı: aynı exe için her PID'de tekrar üretiyordu
                return None;
            }
        }

        let mut scanner = Scanner::new(&self.rules);

        match scanner.scan_file(path) {
            Ok(results) => {
                // İlk eşleşen kuralı döndür
                for rule in results.matching_rules() {
                    return Some(rule.identifier().to_string());
                }
                None
            }
            Err(e) => {
                // FIX: Hata türüne göre farklı log seviyesi
                let err_str = e.to_string();
                if err_str.contains("permission") || err_str.contains("access") {
                    // Erişim hatası — sık olabilir, debug seviyesinde tut
                    eprintln!("🔒 [YARA] Erişim reddedildi: {:?}", path);
                } else {
                    eprintln!("⚠️ [YARA] Tarama hatası ({:?}): {}", path, e);
                }
                None
            }
        }
    }
}