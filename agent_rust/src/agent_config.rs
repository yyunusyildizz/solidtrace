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
    /// Backend WebSocket adresi örn: wss://soc.firma.com/ws/alerts
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
}

impl AgentConfig {
    fn load() -> Self {
        // 1. .env veya ortam değişkenlerinden oku
        // Deployment'ta: set SOLIDTRACE_SERVER=https://... && solidtrace_agent.exe
        let server_base = env_or(
            "SOLIDTRACE_SERVER",
            "http://127.0.0.1:8000",
        );

        let ws_base = env_or(
            "SOLIDTRACE_WS",
            &(server_base
                .replace("https://", "wss://")
                .replace("http://", "ws://")
                + "/ws/alerts"),
        );

        // Default: backend'in varsayılan anahtarı (geliştirme/demo ortamı)
        // Production'da: set SOLIDTRACE_AGENT_KEY=<tenant-key>
        let agent_key = env_or("SOLIDTRACE_AGENT_KEY", "solidtrace-agent-key-2024");

        // YARA kuralları: exe yanındaki rules/ klasörü
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let rules_path = std::env::var("SOLIDTRACE_RULES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| exe_dir.join("rules").join("main.yar"));

        // Disk kuyruğu: %APPDATA%\SolidTrace\queue.db
        let queue_path = std::env::var("SOLIDTRACE_QUEUE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("SolidTrace")
                    .join("queue.db")
            });

        let tls_fingerprint = std::env::var("SOLIDTRACE_TLS_FP").ok().filter(|s| !s.is_empty());

        let channel_capacity = std::env::var("SOLIDTRACE_CHANNEL_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096);

        if agent_key == "solidtrace-agent-key-2024" {
            println!(
                "⚠️  [CONFIG] Varsayılan agent key kullanılıyor (geliştirme modu).\
                 \n   Production için: set SOLIDTRACE_AGENT_KEY=<tenant-key>"
            );
        }

        AgentConfig {
            server_base,
            ws_base,
            agent_key,
            rules_path,
            queue_path,
            tls_fingerprint,
            channel_capacity,
        }
    }

    /// Global singleton — thread-safe, bir kez yüklenir
    pub fn get() -> &'static AgentConfig {
        CONFIG.get_or_init(Self::load)
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
