use std::process::Command;

// 🔒 İZOLASYONU BAŞLAT (Karantina)
pub fn enable_isolation(server_ip: &str) {
    println!("⛔ [ISOLATION] AĞ İZOLASYONU BAŞLATILIYOR...");

    // 1. Önce eski kurallar varsa temizle
    disable_isolation();

    // 2. KRİTİK ADIM: SOC Sunucusuna (Backend) İzin Ver
    // format! ile string oluşturup referansını kullanamayız, o yüzden değişken yapıyoruz.
    let rule_name_allow = "name=SolidTrace_Allow_SOC";
    let remote_ip = format!("remoteip={}", server_ip);
    
    // allow_rule komutunu parçalara bölerek gönderiyoruz
    run_netsh(&[
        "advfirewall", "firewall", "add", "rule", 
        rule_name_allow, 
        "dir=out", 
        "action=allow", 
        &remote_ip, 
        "protocol=TCP", 
        "localport=any"
    ]);

    // 3. KİLİDİ VUR (Giden Trafik - Block)
    run_netsh(&[
        "advfirewall", "firewall", "add", "rule", 
        "name=SolidTrace_Block_All_Out", 
        "dir=out", 
        "action=block"
    ]);
    
    // 4. KİLİDİ VUR (Gelen Trafik - Block)
    run_netsh(&[
        "advfirewall", "firewall", "add", "rule", 
        "name=SolidTrace_Block_All_In", 
        "dir=in", 
        "action=block"
    ]);

    println!("✅ [ISOLATION] BİLGİSAYAR KARANTİNAYA ALINDI. SADECE {} İLE KONUŞABİLİR.", server_ip);
}

// 🔓 İZOLASYONU KALDIR (Normale Dön)
pub fn disable_isolation() {
    println!("🌍 [ISOLATION] Ağ kilidi kaldırılıyor...");
    
    // Kuralları sil
    run_netsh(&["advfirewall", "firewall", "delete", "rule", "name=SolidTrace_Allow_SOC"]);
    run_netsh(&["advfirewall", "firewall", "delete", "rule", "name=SolidTrace_Block_All_Out"]);
    run_netsh(&["advfirewall", "firewall", "delete", "rule", "name=SolidTrace_Block_All_In"]);

    println!("✅ [ISOLATION] İNTERNET ERİŞİMİ NORMALE DÖNDÜ.");
}

// Yardımcı Fonksiyon: Komut Çalıştırıcı
fn run_netsh(args: &[&str]) {
    // Windows komut satırını gizli çalıştır
    // (creation_flags eklenebilir ama şimdilik standart bırakıyoruz)
    let output = Command::new("netsh")
        .args(args)
        .output();

    match output {
        Ok(out) => {
            if !out.status.success() {
                // Sadece hata varsa detay göster
                let err_msg = String::from_utf8_lossy(&out.stderr);
                // "Kural bulunamadı" hatasını görmezden gelebiliriz (ilk temizlikte normal)
                if !err_msg.contains("No rules match") {
                    println!("❌ [FIREWALL HATASI]: {}", err_msg.trim());
                    println!("   👉 ÇÖZÜM: Terminali 'Yönetici Olarak' çalıştır.");
                }
            }
        },
        Err(e) => println!("⚠️ Komut çalıştırılamadı: {}", e),
    }
}