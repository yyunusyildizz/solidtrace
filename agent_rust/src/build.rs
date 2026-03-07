fn main() {
    // Windows'ta UAC manifest göm — agent her zaman yönetici yetkisi ister
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("solidtrace.manifest");
        // İsteğe bağlı: icon ekle
        // res.set_icon("assets/icon.ico");
        if let Err(e) = res.compile() {
            // winres yoksa sessizce geç — sadece manifest gömülmez
            eprintln!("cargo:warning=winres hatası (manifest gömülemedi): {}", e);
        }
    }
}
