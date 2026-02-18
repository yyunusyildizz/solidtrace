import os

# Taranacak kök klasör (Burayı projenin olduğu klasör yolu yapabilirsin veya scripti proje içine atabilirsin)
ROOT_DIR = "." 

# Bu klasörleri ASLA okuma
EXCLUDE_DIRS = {'node_modules', '.git', '__pycache__', 'venv', 'env', '.next', '.vscode', 'dist', 'build'}

# Sadece bu uzantıları oku
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.css', '.html', '.json', '.sql', '.yaml', '.yml'}

# Çıktı dosyası
OUTPUT_FILE = "TUM_PROJE_KODLARI.txt"

def merge_files():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as outfile:
        outfile.write(f"--- SOLIDTRACE PROJE DÖKÜMÜ ---\n\n")
        
        for root, dirs, files in os.walk(ROOT_DIR):
            # Gereksiz klasörleri atla
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            
            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in EXTENSIONS and file != os.path.basename(__file__) and file != "package-lock.json":
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as infile:
                            content = infile.read()
                            # Dosya başlığını yaz
                            outfile.write(f"\n{'='*50}\n")
                            outfile.write(f"DOSYA: {file_path}\n")
                            outfile.write(f"{'='*50}\n")
                            outfile.write(content + "\n")
                            print(f"Eklendi: {file_path}")
                    except Exception as e:
                        print(f"Hata (Atlandı): {file_path} - {e}")

if __name__ == "__main__":
    merge_files()
    print(f"\n✅ İŞLEM TAMAM! '{OUTPUT_FILE}' dosyası oluşturuldu. Bunu Gemini'ye yükle.")