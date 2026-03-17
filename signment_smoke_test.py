[35m.gitignore[m[36m:[m[32m15[m[36m:[m[1;31msecret[ms/
[35magent_rust/src/agent_config.rs[m[36m:[m[32m40[m[36m:[m        let agent_key = env_or("SOLIDTRACE_[1;31mAGENT_KEY[m", "solidtrace-agent-key-2024");
[35magent_rust/src/agent_config.rs[m[36m:[m[32m71[m[36m:[m                "⚠️  [CONFIG] Varsayılan agent key kullanılıyor (geliştirme modu).\n   Production için: set SOLIDTRACE_[1;31mAGENT_KEY[m=<tenant-key>"
[35magent_rust/src/canary_monitor.rs[m[36m:[m[32m4[m[36m:[m//   - Sadece [1;31mpassword[ms.txt izleniyor → birden fazla tuzak dosyası desteği
[35magent_rust/src/canary_monitor.rs[m[36m:[m[32m30[m[36m:[m            PathBuf::from(format!("{}\\[1;31mpassword[ms.txt", dir)),
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m12[m[36m:[mdef admin_login(base_url: str, username: str, [1;31mpassword[m: str) -> str:
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m15[m[36m:[m        data={"username": username, "[1;31mpassword[m": [1;31mpassword[m},
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m21[m[36m:[m    [1;31mtoken[m = data.get("access_[1;31mtoken[m")
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m22[m[36m:[m    if not [1;31mtoken[m:
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m23[m[36m:[m        raise RuntimeError(f"access_[1;31mtoken[m alınamadı. Response: {data}")
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m25[m[36m:[m    return [1;31mtoken[m
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m28[m[36m:[mdef auth_headers([1;31mtoken[m: str) -> dict:
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m29[m[36m:[m    return {"[1;31mAuthorization[m": f"[1;31mBearer[m {[1;31mtoken[m}"}
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m35[m[36m:[m    parser.add_argument("--[1;31mpassword[m", required=True)
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m43[m[36m:[m    [1;31mtoken[m = admin_login(base_url, args.username, args.[1;31mpassword[m)
[35mbackend/alert_assignment_smoke_test.py[m[36m:[m[32m44[m[36m:[m    headers = auth_headers([1;31mtoken[m)
[35mbackend/app/api/routes_admin.py[m[36m:[m[32m128[m[36m:[m    import [1;31msecret[ms as _s
[35mbackend/app/api/routes_admin.py[m[36m:[m[32m137[m[36m:[m            slug = f"{slug}-{_s.[1;31mtoken[m_hex(3)}"
[35mbackend/app/api/routes_admin.py[m[36m:[m[32m141[m[36m:[m            agent_key=f"st-{_s.[1;31mtoken[m_urlsafe(24)}",
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m10[m[36m:[mimport [1;31msecret[ms
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m18[m[36m:[m    encrypt_agent_[1;31msecret[m,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m20[m[36m:[m    hash_[1;31msecret[m,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m21[m[36m:[m    hash_[1;31mtoken[m,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m60[m[36m:[m    "/api/agents/enrollment-[1;31mtoken[m",
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m63[m[36m:[masync def create_enrollment_[1;31mtoken[m(
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m83[m[36m:[m        raw_[1;31mtoken[m = [1;31msecret[ms.[1;31mtoken[m_urlsafe(32)
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m84[m[36m:[m        [1;31mtoken[m_hash = hash_[1;31mtoken[m(raw_[1;31mtoken[m)
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m87[m[36m:[m        [1;31mtoken[m_rec = AgentEnrollmentTokenModel(
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m90[m[36m:[m            [1;31mtoken[m_hash=[1;31mtoken[m_hash,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m98[m[36m:[m        db.add([1;31mtoken[m_rec)
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m102[m[36m:[m            "agent_enrollment_[1;31mtoken[m_created request_id=%s tenant=%s user=%s expires_at=%s",
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m110[m[36m:[m            enrollment_[1;31mtoken[m=raw_[1;31mtoken[m,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m139[m[36m:[m        [1;31mtoken[m_hash = hash_[1;31mtoken[m(body.enrollment_[1;31mtoken[m)
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m141[m[36m:[m        [1;31mtoken[m_rec = (
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m143[m[36m:[m            .filter(AgentEnrollmentTokenModel.[1;31mtoken[m_hash == [1;31mtoken[m_hash)
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m147[m[36m:[m        if not [1;31mtoken[m_rec:
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m148[m[36m:[m            raise HTTPException(status_code=401, detail="Geçersiz enrollment [1;31mtoken[m")
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m150[m[36m:[m        if [1;31mtoken[m_rec.revoked_at:
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m151[m[36m:[m            raise HTTPException(status_code=401, detail="Enrollment [1;31mtoken[m iptal edilmiş")
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m153[m[36m:[m        if [1;31mtoken[m_rec.used_at:
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m154[m[36m:[m            raise HTTPException(status_code=401, detail="Enrollment [1;31mtoken[m zaten kullanılmış")
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m156[m[36m:[m        [1;31mtoken[m_exp = datetime.fromisoformat([1;31mtoken[m_rec.expires_at)
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m157[m[36m:[m        if [1;31mtoken[m_exp < utcnow():
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m158[m[36m:[m            raise HTTPException(status_code=401, detail="Enrollment [1;31mtoken[m süresi dolmuş")
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m163[m[36m:[m                AgentModel.tenant_id == [1;31mtoken[m_rec.tenant_id,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m177[m[36m:[m        agent_[1;31msecret[m = [1;31msecret[ms.[1;31mtoken[m_urlsafe(48)
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m181[m[36m:[m            tenant_id=[1;31mtoken[m_rec.tenant_id,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m186[m[36m:[m            [1;31msecret[m_hash=hash_[1;31msecret[m(agent_[1;31msecret[m),
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m187[m[36m:[m            [1;31msecret[m_enc=encrypt_agent_[1;31msecret[m(agent_[1;31msecret[m),
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m192[m[36m:[m            [1;31msecret[m_rotated_at=None,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m193[m[36m:[m            [1;31msecret[m_version=1,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m198[m[36m:[m        [1;31mtoken[m_rec.used_at = utcnow_iso()
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m206[m[36m:[m            [1;31mtoken[m_rec.tenant_id,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m214[m[36m:[m            agent_[1;31msecret[m=agent_[1;31msecret[m,
[35mbackend/app/api/routes_agents.py[m[36m:[m[32m215[m[36m:[m            tenant_id=[1;31mtoken[m_rec.tenant_id,
[35mbackend/app/api/routes_auth.py[m[36m:[m[32m3[m[36m:[mLogin (brute-force korumalı), 2FA (pending [1;31mtoken[m), refresh [1;31mtoken[m rotation,
[35mbackend/app/api/routes_auth.py[m[36m:[m[32m4[m[36m:[minvite flow (şifresiz), setup-[1;31mpassword[m, change-[1;31mpassword[m, admin reset.
[35mbackend/app/api/routes_auth.py[m[36m:[m[32m9[m[36m:[mimport [1;31msecret[ms
[35mbackend/app/api/routes_auth.py[m[36m:[m[32m20[m[36m:[m    verify_[1;31mpassword[m,
[35mbackend/app/api/routes_auth.py[m[36m:[m[32m21[m[36m:[m    get_[1;31mpassword[m_hash,
[35mbackend/app/api/routes_auth.py[m[36m:[m[32m22[m[36m:[m    create_access_[1;31mtoken[m,
[35mbackend/app/api/routes_auth.py[m[36m:[m[32m23[m[36m:[m    create_refresh_[1;31mtoken[m,
[35mbackend/app/api/routes_auth.py[m[36m:[m[32m24[m[36m:[m    create_pending_2fa_[1;31mtoken[m,
[35mbackend/app/api