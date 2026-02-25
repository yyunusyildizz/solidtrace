import psycopg2

try:
    # Veritabanına bağlan
    conn = psycopg2.connect("postgresql://postgres:password@localhost/solidtrace_db")
    cur = conn.cursor()
    
    # Eksik sütunları ekle
    cur.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0;")
    cur.execute("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP;")
    
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Veritabanı başarıyla güncellendi! Sütunlar eklendi.")
except psycopg2.errors.DuplicateColumn:
    print("ℹ️ Sütunlar zaten varmış, sorun yok.")
except Exception as e:
    print(f"❌ Bir hata oluştu: {e}")