"""
SolidTrace — Veritabanı Migration Script
=========================================
Mevcut PostgreSQL tablolarına yeni kolonları ekler.
Kolon zaten varsa atlar (idempotent — birden fazla çalıştırmak güvenli).

Kullanım:
    python migrate_db.py

.env dosyasındaki DATABASE_URL değişkenini kullanır.
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost/solidtrace_db"
)

# ─── Migration tanımları ───────────────────────────────────────────────────────
# Format: (tablo_adı, kolon_adı, kolon_tipi, default_değer)
MIGRATIONS = [
    # alerts_production_v2
    ("alerts_production_v2", "tenant_id",  "VARCHAR",  None),

    # users
    ("users", "email",                    "VARCHAR",  None),
    ("users", "password_change_required", "BOOLEAN",  "TRUE"),
    ("users", "is_active",                "BOOLEAN",  "TRUE"),
    ("users", "totp_secret",              "VARCHAR",  None),
    ("users", "totp_enabled",             "BOOLEAN",  "FALSE"),
    ("users", "tenant_id",                "VARCHAR",  None),

    # detection_rules
    ("detection_rules", "tenant_id", "VARCHAR", None),

    # audit_log (yeni tablo — yoksa oluştur)
    # tenants (yeni tablo — yoksa oluştur)
]

CREATE_TABLES = [
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id         VARCHAR PRIMARY KEY,
        timestamp  VARCHAR,
        username   VARCHAR,
        action     VARCHAR,
        target     VARCHAR,
        detail     TEXT,
        ip_address VARCHAR,
        result     VARCHAR DEFAULT 'SUCCESS',
        tenant_id  VARCHAR
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tenants (
        id            VARCHAR PRIMARY KEY,
        name          VARCHAR NOT NULL,
        slug          VARCHAR UNIQUE,
        agent_key     VARCHAR UNIQUE,
        max_agents    INTEGER DEFAULT 10,
        is_active     BOOLEAN DEFAULT TRUE,
        created_at    VARCHAR,
        plan          VARCHAR DEFAULT 'starter',
        contact_email VARCHAR
    )
    """,
]

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_alerts_tenant ON alerts_production_v2(tenant_id)",
    "CREATE INDEX IF NOT EXISTS ix_users_tenant ON users(tenant_id)",
    "CREATE INDEX IF NOT EXISTS ix_audit_timestamp ON audit_log(timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_audit_username ON audit_log(username)",
    "CREATE INDEX IF NOT EXISTS ix_audit_tenant ON audit_log(tenant_id)",
    "CREATE INDEX IF NOT EXISTS ix_tenants_slug ON tenants(slug)",
]


def run():
    try:
        import psycopg2
    except ImportError:
        print("❌ psycopg2 bulunamadı: pip install psycopg2-binary")
        sys.exit(1)

    print(f"🔌 Bağlanıyor: {DATABASE_URL.split('@')[-1]}")

    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        cur = conn.cursor()
    except Exception as e:
        print(f"❌ Bağlantı hatası: {e}")
        sys.exit(1)

    print("✅ Bağlantı başarılı\n")

    # ─── Yeni tabloları oluştur ───────────────────────────────────────────────
    print("📋 Tablolar kontrol ediliyor...")
    for sql in CREATE_TABLES:
        table_name = sql.strip().split("EXISTS")[1].strip().split("(")[0].strip()
        try:
            cur.execute(sql)
            conn.commit()
            print(f"  ✅ {table_name} hazır")
        except Exception as e:
            conn.rollback()
            print(f"  ❌ {table_name}: {e}")

    # ─── Mevcut tablolara kolon ekle ─────────────────────────────────────────
    print("\n📦 Kolonlar ekleniyor...")
    for table, column, col_type, default in MIGRATIONS:
        # Kolon var mı kontrol et
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = %s AND column_name = %s
        """, (table, column))

        if cur.fetchone():
            print(f"  ⏭  {table}.{column} — zaten var, atlanıyor")
            continue

        # Kolonu ekle
        if default is not None:
            sql = f'ALTER TABLE {table} ADD COLUMN {column} {col_type} DEFAULT {default}'
        else:
            sql = f'ALTER TABLE {table} ADD COLUMN {column} {col_type}'

        try:
            cur.execute(sql)
            conn.commit()
            print(f"  ✅ {table}.{column} ({col_type}) eklendi")
        except Exception as e:
            conn.rollback()
            print(f"  ❌ {table}.{column}: {e}")

    # ─── İndeksler ───────────────────────────────────────────────────────────
    print("\n🔍 İndeksler oluşturuluyor...")
    for sql in CREATE_INDEXES:
        idx_name = sql.split("IF NOT EXISTS")[1].strip().split(" ")[0]
        try:
            cur.execute(sql)
            conn.commit()
            print(f"  ✅ {idx_name}")
        except Exception as e:
            conn.rollback()
            print(f"  ⚠️  {idx_name}: {e}")

    cur.close()
    conn.close()

    print("\n✅ Migration tamamlandı!")
    print("   Şimdi backend'i yeniden başlatabilirsiniz.")


if __name__ == "__main__":
    run()
