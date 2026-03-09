"""
SolidTrace Database Reset Utility - v2.0 (REVISED)
Düzeltmeler:
  - Production ortam kontrolü eklendi (ENV=production ise çalışmaz)
  - Kullanıcı onayı zorunlu hale getirildi
  - Hangi tabloların silineceği açıkça listeleniyor
  - Silme işlemi loglanıyor
"""

import os
import sys
import logging
from datetime import datetime
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SolidTraceReset")

# Silinecek tablolar (sıra önemli — foreign key bağımlılıkları)
TABLES_TO_DROP = [
    "alerts_v2",
    "users",
    "detection_rules",
]

def main():
    # --- FIX: ORTAM KONTROLÜ ---
    env = os.getenv("ENV", "production").lower()
    if env == "production":
        logger.error("❌ HATA: Bu script production ortamında çalıştırılamaz!")
        logger.error("   ENV=development veya ENV=staging olarak ayarlayın.")
        sys.exit(1)

    # --- FIX: KULLANICI ONAYI ---
    print("\n" + "="*55)
    print("⚠️  SOLIDTRACE VERİTABANI SIFIRLAMA ARACI")
    print("="*55)
    print(f"\nOrtam : {env.upper()}")
    print(f"DB URL : {os.getenv('DATABASE_URL', 'tanımsız')[:40]}...")
    print("\nAşağıdaki tablolar kalıcı olarak SİLİNECEK:")
    for table in TABLES_TO_DROP:
        print(f"  • {table}")

    print("\nDevam etmek için 'RESET' yazın (iptal için Enter):")
    confirm = input("> ").strip()

    if confirm != "RESET":
        print("\n❌ İşlem iptal edildi.")
        sys.exit(0)

    # --- BAĞLANTI ---
    database_url = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/solidtrace_db")
    try:
        engine = create_engine(database_url)
    except Exception as e:
        logger.error(f"❌ Veritabanı bağlantısı kurulamadı: {e}")
        sys.exit(1)

    # --- SILME İŞLEMİ ---
    print(f"\n🧹 Silme başlıyor — {datetime.utcnow().isoformat()}")
    dropped = []
    errors = []

    with engine.connect() as conn:
        for table in TABLES_TO_DROP:
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE;"))
                dropped.append(table)
                logger.info(f"✔ Tablo silindi: {table}")
            except Exception as e:
                errors.append(table)
                logger.error(f"✗ Tablo silinemedi ({table}): {e}")
        conn.commit()

    # --- ÖZET ---
    print("\n" + "="*55)
    print(f"✅ Silinen tablolar ({len(dropped)}): {', '.join(dropped)}")
    if errors:
        print(f"❌ Başarısız ({len(errors)}): {', '.join(errors)}")
    print("\nBackend'i yeniden başlattığınızda tablolar temiz olarak oluşturulacak.")
    print("="*55 + "\n")


if __name__ == "__main__":
    main()
