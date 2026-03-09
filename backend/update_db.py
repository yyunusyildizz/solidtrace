import os
from dotenv import load_dotenv
load_dotenv() # .env dosyasını oku

from app.database.db_manager import engine
from sqlalchemy import text

cols = [
    'invite_token_hash TEXT', 
    'invite_expires_at TEXT', 
    'must_setup_password BOOLEAN DEFAULT false', 
    'password_changed_at TEXT', 
    'token_version INTEGER DEFAULT 0'
]

with engine.begin() as conn:
    for col in cols:
        name = col.split()[0]
        try:
            conn.execute(text(f'ALTER TABLE users ADD COLUMN IF NOT EXISTS {col}'))
            print(f'✅ OK: {name} başarıyla eklendi.')
        except Exception as e:
            print(f'⚠️ SKIP {name}: Zaten var veya hata oluştu -> {e}')

print("🎉 Veritabanı tablo güncellemesi tamamlandı!")