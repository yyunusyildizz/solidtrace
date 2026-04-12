use std::num::NonZeroUsize;
use std::sync::{Mutex, OnceLock};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use lru::LruCache;
use serde_json::Value;

use crate::agent_config::AgentConfig;

static NONCE_CACHE: OnceLock<Mutex<LruCache<String, i64>>> = OnceLock::new();

fn nonce_cache() -> &'static Mutex<LruCache<String, i64>> {
    NONCE_CACHE.get_or_init(|| {
        let cfg = AgentConfig::get();
        let size = NonZeroUsize::new(cfg.nonce_cache_size.max(128)).unwrap();
        Mutex::new(LruCache::new(size))
    })
}

#[allow(dead_code)]
pub fn canonicalize_args(args: &Value) -> String {
    match args {
        Value::Null => "{}".to_string(),
        _ => {
            let mut value = args.clone();
            sort_json_value(&mut value);
            serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
        }
    }
}

fn sort_json_value(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let mut items: Vec<(String, Value)> =
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));

            map.clear();
            for (k, mut val) in items {
                sort_json_value(&mut val);
                map.insert(k, val);
            }
        }
        Value::Array(items) => {
            for item in items {
                sort_json_value(item);
            }
        }
        _ => {}
    }
}

#[allow(dead_code)]
pub fn build_command_signing_message(
    version: u8,
    command_id: &str,
    action: &str,
    target_hostname: &str,
    tenant_id: &str,
    issued_at: &str,
    expires_at: &str,
    nonce: &str,
    args: &Value,
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        version,
        command_id.trim(),
        action.trim(),
        target_hostname.trim().to_uppercase(),
        tenant_id.trim(),
        issued_at.trim(),
        expires_at.trim(),
        nonce.trim(),
        canonicalize_args(args),
    )
}

#[allow(dead_code)]
pub fn verify_command_signature(
    public_key_b64: &str,
    message: &str,
    signature_b64: &str,
) -> Result<(), String> {
    let pubkey_bytes = B64
        .decode(public_key_b64.trim())
        .map_err(|e| format!("public key base64 geçersiz: {}", e))?;

    let sig_bytes = B64
        .decode(signature_b64.trim())
        .map_err(|e| format!("signature base64 geçersiz: {}", e))?;

    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "public key 32 byte olmalı".to_string())?;

    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature 64 byte olmalı".to_string())?;

    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| format!("public key hatalı: {}", e))?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| format!("signature doğrulanamadı: {}", e))
}

#[allow(dead_code)]
pub fn validate_timestamps(issued_at: &str, expires_at: &str) -> Result<(), String> {
    let cfg = AgentConfig::get();

    let issued = DateTime::parse_from_rfc3339(issued_at)
        .map_err(|e| format!("issued_at hatalı: {}", e))?
        .with_timezone(&Utc);

    let expires = DateTime::parse_from_rfc3339(expires_at)
        .map_err(|e| format!("expires_at hatalı: {}", e))?
        .with_timezone(&Utc);

    let now = Utc::now();
    let max_skew = Duration::seconds(cfg.command_max_skew_secs as i64);

    if issued > now + max_skew {
        return Err("command future skew çok büyük".to_string());
    }

    if expires < now {
        return Err("command süresi dolmuş".to_string());
    }

    if expires <= issued {
        return Err("expires_at issued_at'ten büyük olmalı".to_string());
    }

    Ok(())
}

#[allow(dead_code)]
pub fn check_and_store_nonce(command_id: &str, nonce: &str) -> Result<(), String> {
    let key = format!("{}:{}", command_id.trim(), nonce.trim());
    let now = Utc::now().timestamp();

    let cache = nonce_cache();
    let mut guard = cache.lock().map_err(|_| "nonce cache lock hatası".to_string())?;

    if guard.contains(&key) {
        return Err("replay attack tespit edildi (nonce tekrarlandı)".to_string());
    }

    guard.put(key, now);
    Ok(())
}