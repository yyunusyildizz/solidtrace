/// agent_config.rs
/// Merkezi yapılandırma — hardcoded const YOK.
/// Öncelik sırası: ENV → agent.conf → derleme zamanı varsayılan
use std::path::PathBuf;
use std::sync::OnceLock;

static CONFIG: OnceLock<AgentConfig> = OnceLock::new();

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AgentConfig {
    /// Backend HTTP(S) adresi   örn: https://soc.firma.com
    pub server_base: String,
    /// Backend WebSocket adresi örn: wss://soc.firma.com/ws/agent
    pub ws_base: String,
    /// Agent kimlik anahtarı (tenant'a özel)
    pub agent_key: String,
    /// YARA kuralları dizini
    pub rules_path: PathBuf,
    /// Disk kuyruğu SQLite dosyası
    pub queue_path: PathBuf,
    /// TLS: server sertifika parmak izi (SHA-256 hex, boşsa pinning kapalı)
    pub tls_fingerprint: Option<String>,
    /// Bounded channel kapasitesi
    pub channel_capacity: usize,
    /// İmzalı komut doğrulama public key'i
    pub command_verify_key: String,
    /// İmzalı komutlar için kabul edilebilir en yüksek zaman sapması (saniye)
    pub command_max_skew_secs: u64,
    /// Tekrar saldırılarını önlemek için nonce önbellek boyutu
    pub nonce_cache_size: usize,
}

impl AgentConfig {
    fn load() -> Self {
        let server_base = env_or("SOLIDTRACE_SERVER", "http://127.0.0.1:8000");

        let ws_base = env_or(
            "SOLIDTRACE_WS",
            &(server_base
                .replace("https://", "wss://")
                .replace("http://", "ws://")
                + "/ws/agent"),
        );

        let agent_key = env_or("SOLIDTRACE_AGENT_KEY", "solidtrace-agent-key-2024");

        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let rules_path = std::env::var("SOLIDTRACE_RULES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| exe_dir.join("rules").join("main.yar"));

        let queue_path = std::env::var("SOLIDTRACE_QUEUE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("SolidTrace")
                    .join("queue.db")
            });

        let tls_fingerprint = std::env::var("SOLIDTRACE_TLS_FP")
            .ok()
            .filter(|s| !s.is_empty());

        let channel_capacity = std::env::var("SOLIDTRACE_CHANNEL_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096);

        let command_verify_key = env_or("SOLIDTRACE_COMMAND_PUBKEY", "");

        let command_max_skew_secs = std::env::var("SOLIDTRACE_COMMAND_MAX_SKEW")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90);

        let nonce_cache_size = std::env::var("SOLIDTRACE_NONCE_CACHE_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096);

        if agent_key == "solidtrace-agent-key-2024" {
            println!(
                "⚠️  [CONFIG] Varsayılan agent key kullanılıyor (geliştirme modu).\n   Production için: set SOLIDTRACE_AGENT_KEY=<tenant-key>"
            );
        }

        if command_verify_key.is_empty() {
            println!("⚠️  [CONFIG] SOLIDTRACE_COMMAND_PUBKEY boş. Agent tüm signed command'ları reddedecek.");
        }

        AgentConfig {
            server_base,
            ws_base,
            agent_key,
            rules_path,
            queue_path,
            tls_fingerprint,
            channel_capacity,
            command_verify_key,
            command_max_skew_secs,
            nonce_cache_size,
        }
    }

    pub fn get() -> &'static AgentConfig {
        CONFIG.get_or_init(Self::load)
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}