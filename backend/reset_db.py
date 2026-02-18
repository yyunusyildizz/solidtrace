import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

# Veritabanı URL'sini al
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/solidtrace_db")

try:
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        print("🧹 Kullanıcı tablosu temizleniyor...")
        # Users tablosunu zorla sil (Drop)
        connection.execute(text("DROP TABLE IF EXISTS users CASCADE;"))
        connection.execute(text("DROP TABLE IF EXISTS detection_rules CASCADE;"))
        connection.commit()
        print("✅ Tablolar silindi. Backend'i yeniden başlattığında tertemiz şekilde yeniden kurulacaklar.")
except Exception as e:
    print(f"❌ Hata: {e}")