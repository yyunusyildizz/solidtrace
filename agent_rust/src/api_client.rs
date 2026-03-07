#![allow(deprecated)]

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;
use chrono::Local;
use sysinfo::{Pid, ProcessExt, System, SystemExt};
use tokio::sync::mpsc; 
use once_cell::sync::Lazy; 
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{StreamExt, SinkExt};
use url::Url;
use std::sync::Arc;

const SERVER_IP: &str = "127.0.0.1";
const SERVER_BASE: &str = "http://127.0.0.1:8000";
// FIX: /ws/agent endpoint'i — komutlar buraya gelir
const WS_BASE: &str = "ws://127.0.0.1:8000/ws/agent";

const AGENT_KEY: &str = "solidtrace-agent-key-2024";

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(90)) 
        .pool_max_idle_per_host(10)
        .tcp_keepalive(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10)) 
        .build()
        .expect("HTTP Client oluşturulamadı!")
});

#[derive(Serialize, Clone, Debug)]
pub struct SecurityEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub hostname: String,
    pub user: String,
    pub pid: u32,
    pub details: String,
    pub command_line: String,
    pub timestamp: String,
    pub severity: String,
    pub serial: Option<String>,
}

#[derive(Deserialize, Debug)]
struct CommandMessage {
    #[serde(rename = "type")]
    pub msg_type: String,      
    pub action: String,        
    pub target_hostname: String,
    pub target_pid: Option<u32>, 
}

pub struct ApiClient {
    pub hostname: String,
    tx: mpsc::UnboundedSender<SecurityEvent>,
}

impl ApiClient {
    pub fn new() -> Self {
        // FIX: COMPUTERNAME — whoami domain suffix ekleyebilir
        let raw_host = std::env::var("COMPUTERNAME")
            .unwrap_or_else(|_| whoami::fallible::hostname()
                .unwrap_or_else(|_| "Unknown-Host".to_string()));
        
        let host = raw_host
            .split('.')
            .next()
            .unwrap_or(&raw_host)
            .to_uppercase();

        println!("🖥️  [AGENT] Hostname: {}", host);
        
        let (tx, mut rx) = mpsc::unbounded_channel::<SecurityEvent>();

        tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                tokio::select! {
                    Some(event) = rx.recv() => {
                        buffer.push(event);
                        if buffer.len() >= 50 {
                            flush_logs(&buffer).await;
                            buffer.clear();
                        }
                    }
                    _ = interval.tick() => {
                        if !buffer.is_empty() {
                            flush_logs(&buffer).await;
                            buffer.clear();
                        }
                    }
                }
            }
        });

        ApiClient { hostname: host, tx }
    }

    pub async fn send_event(
        &self, 
        event_type: &str, 
        details: &str, 
        severity: &str, 
        pid: u32, 
        serial: Option<String> 
    ) -> Result<(), Box<dyn Error>> {
        let now = Local::now().to_rfc3339(); 
        let username = whoami::username();

        let event = SecurityEvent {
            event_type: event_type.to_string(),
            hostname: self.hostname.clone(),
            user: username,
            pid,
            details: details.to_string(),
            command_line: format!("Severity: {} | Info: {}", severity, details), 
            timestamp: now,
            severity: severity.to_string(),
            serial, 
        };

        if let Err(e) = self.tx.send(event) {
            eprintln!("🔥 [KUYRUK HATASI] Log kuyruğa atılamadı: {}", e);
        }
        Ok(())
    }

    pub async fn report_file_hash(&self, path: &str, hash: &str, pid: u32) -> Result<(), Box<dyn Error>> {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let payload = serde_json::json!({
            "hostname": self.hostname,
            "file_path": path,
            "file_hash": hash,
            "pid": pid
        });
        let url = format!("{}/api/v1/report_hash", SERVER_BASE);
        if let Err(e) = HTTP_CLIENT.post(&url)
            .header("X-Agent-Key", AGENT_KEY)
            .json(&payload)
            .send()
            .await 
        {
            println!("⚠️ Hash Raporlanamadı: {}", e);
        }
        Ok(())
    }

    // --- WEBSOCKET DİNLEME ---
    pub async fn connect_and_listen(&self) {
        let url = Url::parse(WS_BASE).expect("URL Hatasi");
        println!("🎧 [COMMAND] Komuta Merkezi dinleniyor...");
        
        loop {
            match connect_async(url.clone()).await {
                Ok((ws_stream, _)) => {
                    println!("✅ [WS] Bağlantı KURULDU!");
                    let (mut write, mut read) = ws_stream.split();
                    
                    // FIX: Backend'e hostname bildir
                    let register_msg = format!(
                        "{{\"type\":\"register\",\"hostname\":\"{}\"}}",
                        self.hostname
                    );
                    match write.send(Message::Text(register_msg)).await {
                        Ok(_)  => println!("📋 [WS] Kayıt gönderildi: {}", self.hostname),
                        Err(e) => println!("⚠️ [WS] Kayıt gönderilemedi: {}", e),
                    }
                    drop(write);

                    while let Some(message) = read.next().await {
                        if let Ok(Message::Text(text)) = message {
                            if let Ok(cmd) = serde_json::from_str::<CommandMessage>(&text) {
                                if cmd.msg_type == "COMMAND" {
                                    if cmd.target_hostname == self.hostname 
                                        || cmd.target_hostname == "ALL" 
                                    {
                                        self.handle_command(cmd).await;
                                    }
                                }
                            }
                        }
                    }
                    println!("⚠️ [WS] Bağlantı kapandı — yeniden bağlanılıyor...");
                }
                Err(e) => {
                    println!("⚠️  [WS] Bağlanamadı: {} — 5s sonra tekrar.", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn handle_command(&self, cmd: CommandMessage) {
        println!("📩 [EMİR ALINDI] {}", cmd.action);
        match cmd.action.as_str() {
            "KILL_PROCESS" => { 
                if let Some(pid) = cmd.target_pid { 
                    self.kill_process(pid); 
                } 
            },
            "ISOLATE_HOST"   => { crate::isolation_manager::enable_isolation(SERVER_IP); },
            "UNISOLATE_HOST" => { crate::isolation_manager::disable_isolation(); },
            "ANALYZE_HOST" | "SCAN_AND_REPORT_HASH" => {
                let client_new = Arc::new(ApiClient::new());
                tokio::spawn(async move {
                    crate::scanner::run_deep_scan(client_new).await;
                });
            },
            "USB_DISABLE" => {
                println!("🔌 [USB] Devre dışı bırakılıyor...");
                crate::usb_control::disable_usb_storage();
                println!("✅ [USB] USB depolama devre dışı bırakıldı.");
            },
            "USB_ENABLE" => {
                println!("🔌 [USB] Aktif ediliyor...");
                crate::usb_control::enable_usb_storage();
                println!("✅ [USB] USB depolama aktif edildi.");
            },
            _ => println!("❓ Bilinmeyen Emir: {}", cmd.action),
        }
    }

    fn kill_process(&self, pid_u32: u32) {
        let mut sys = System::new_all();
        sys.refresh_all();
        let pid = Pid::from(pid_u32 as usize);
        if let Some(process) = sys.process(pid) {
            if process.kill() {
                println!("✅ [KILL BAŞARILI] PID {} sonlandırıldı.", pid_u32);
            } else {
                println!("🛡️ [KILL BAŞARISIZ] Yetki sorunu.");
            }
        } else {
            println!("❓ [KILL] PID {} bulunamadı.", pid_u32);
        }
    }
}

async fn flush_logs(buffer: &[SecurityEvent]) {
    let url = format!("{}/api/v1/ingest", SERVER_BASE);
    if buffer.is_empty() { return; }
    if let Err(e) = HTTP_CLIENT.post(&url)
        .header("X-Agent-Key", AGENT_KEY)
        .header("Content-Type", "application/json")
        .json(buffer)
        .send()
        .await 
    {
        eprintln!("⚠️ [INGEST HATASI] Loglar gönderilemedi: {}", e);
    }
}
