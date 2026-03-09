import os
from dotenv import load_dotenv

# 1. EN KRİTİK ADIM: Diğer her şeyden önce .env dosyasını oku!
load_dotenv()

from app.database.db_manager import SessionLocal, UserModel, init_db
from app.core.security import get_password_hash
import uuid
from datetime import datetime

init_db()
db = SessionLocal()

existing = db.query(UserModel).filter(UserModel.username == 'admin').first()

if existing:
    print('🔄 Admin zaten var, şifre sıfırlanıyor ve eksik veriler dolduruluyor...')
    existing.hashed_password = get_password_hash('GucluSifre123!')
    existing.token_version = (existing.token_version or 0) + 1
    existing.is_active = True
    existing.invite_token_hash = None
    existing.must_setup_password = False
else:
    print('🆕 Admin sıfırdan oluşturuluyor...')
    db.add(UserModel(
        id=str(uuid.uuid4()),
        username='admin',
        hashed_password=get_password_hash('GucluSifre123!'),
        role='admin',
        created_at=datetime.now().isoformat(),
        password_change_required=False,
        is_active=True,
        token_version=0
    ))

db.commit()
db.close()
print('✅ Hazır! Artık panale "admin" ve "GucluSifre123!" ile sorunsuzca giriş yapabilirsiniz.')