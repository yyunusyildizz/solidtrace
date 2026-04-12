import sys
import os

from app.database.db_manager import SessionLocal, UserModel
from app.core.security import get_password_hash


NEW_USERNAME = "admin"
NEW_PASSWORD = os.getenv("SOLIDTRACE_ADMIN_PASSWORD", "CHANGE_ME")
NEW_ROLE = "admin"
NEW_TENANT_ID = "default_tenant"


def main() -> int:
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.username == NEW_USERNAME).first()

        hashed = get_password_hash(NEW_PASSWORD)

        if user:
            user.hashed_password = hashed

            if hasattr(user, "role"):
                user.role = NEW_ROLE
            if hasattr(user, "is_active"):
                user.is_active = True
            if hasattr(user, "tenant_id") and not getattr(user, "tenant_id", None):
                user.tenant_id = NEW_TENANT_ID
            if hasattr(user, "must_change_password"):
                user.must_change_password = False
            if hasattr(user, "password_change_required"):
                user.password_change_required = False
            if hasattr(user, "token_version"):
                user.token_version = (user.token_version or 0) + 1

            db.add(user)
            db.commit()
            print(f"✅ Admin kullanıcısı güncellendi: {NEW_USERNAME}")
        else:
            payload = {
                "username": NEW_USERNAME,
                "hashed_password": hashed,
            }

            if hasattr(UserModel, "role"):
                payload["role"] = NEW_ROLE
            if hasattr(UserModel, "is_active"):
                payload["is_active"] = True
            if hasattr(UserModel, "tenant_id"):
                payload["tenant_id"] = NEW_TENANT_ID
            if hasattr(UserModel, "must_change_password"):
                payload["must_change_password"] = False
            if hasattr(UserModel, "password_change_required"):
                payload["password_change_required"] = False
            if hasattr(UserModel, "token_version"):
                payload["token_version"] = 1

            user = UserModel(**payload)
            db.add(user)
            db.commit()
            print(f"✅ Admin kullanıcısı oluşturuldu: {NEW_USERNAME}")

        print("🔐 Yeni giriş bilgileri:")
        print(f"   username: {NEW_USERNAME}")
        print(f"   password: {NEW_PASSWORD}")
        return 0

    except Exception as exc:
        db.rollback()
        print(f"❌ Hata: {exc}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())