use std::fs;
use std::path::Path;
use reqwest;

pub async fn update_yara_rules(rules_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 [UPDATER] Global İstihbarat Ağlarına Bağlanılıyor...");

    // ÖRNEK: Güvenilir bir YARA repo'sunun URL'si
    // Not: Bu URL'yi gerçek, tek bir dev .yar dosyasıyla değiştirebilirsin
    let url = "https://raw.githubusercontent.com/YARA-Rules/rules/master/malware/MALW_Eicar.yar";

    let response = reqwest::get(url).await?;

    if response.status().is_success() {
        let content = response.text().await?;
        
        // Klasör yoksa oluştur
        let path = Path::new(rules_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Mevcut dosyanın üstüne yaz veya yeni oluştur
        fs::write(rules_path, content)?;
        println!("✅ [UPDATER] En güncel kurallar indirildi ve mühürlendi: {}", rules_path);
    } else {
        println!("⚠️ [UPDATER] Sunucuya ulaşılamadı, yerel kurallarla devam ediliyor.");
    }

    Ok(())
}