use std::path::Path;
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraScanner {
    rules: Rules,
}

impl YaraScanner {
    pub fn new(rules_path: &str) -> Self {
        println!("⚙️ [YARA] Kurallar derleniyor: {}", rules_path);
        
        let rule_source = std::fs::read_to_string(rules_path)
            .unwrap_or_else(|_| {
                println!("⚠️ [YARA] Kural dosyası bulunamadı, varsayılan kural kullanılıyor.");
                "rule Dummy { condition: false }".to_string()
            });

        // 🔥 ÇÖZÜM: Compiler'ı adım adım yöneterek mülkiyet hatasını (move out) gideriyoruz
        let mut compiler = Compiler::new();
        
        // Kaynağı ekle
        if let Err(e) = compiler.add_source(rule_source.as_str()) {
            eprintln!("❌ [YARA] Kaynak ekleme hatası: {}", e);
        }
        
        // build(self) diyerek compiler nesnesini Rules'a dönüştürüyoruz
        let rules = compiler.build();

        println!("✅ [YARA] Kurallar mühürlendi!");
        YaraScanner { rules }
    }

    pub fn scan_file(&self, path: &Path) -> Option<String> {
        if !path.exists() { 
            return None; 
        }

        let mut scanner = Scanner::new(&self.rules);
        
        // e değişkenini loglamayacaksak '_' kullanarak uyarıyı siliyoruz
        match scanner.scan_file(path) {
            Ok(scan_results) => {
                for matching_rule in scan_results.matching_rules() {
                    return Some(matching_rule.identifier().to_string());
                }
                None
            },
            Err(_) => None
        }
    }
}