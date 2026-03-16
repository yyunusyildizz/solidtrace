#![allow(deprecated)]

use crate::agent_config::AgentConfig;
use chrono::{Local, Utc};
use futures_util::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, ProcessExt, System, SystemExt};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;

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

#[derive(Deserialize, Debug, Clone)]
struct CommandMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub action: Option<String>,
    pub target_hostname: Option<String>,
    pub target_pid: Option<u32>,
    pub command_id: Option<String>,
}

#[derive(Serialize, Debug)]
struct RegisterMessage<'a> {
    #[serde(rename = "type")]
    msg_type: &'a str,
    hostname: &'a str,
    capabilities: Vec<&'a str>,
    agent_version: &'a str,
    timestamp: String,
}

#[derive(Serialize, Debug)]
struct CommandAckMessage<'a> {
    #[serde(rename = "type")]
    msg_type: &'a str,
    command_id: String,
    hostname: &'a str,
    action: &'a str,
    status: &'a str,
    timestamp: String,
}

#[derive(Serialize, Debug)]
struct CommandResultMessage<'a> {
    #[serde(rename = "type")]
    msg_type: &'a str,
    command_id: String,
    hostname: &'a str,
    action: &'a str,
    status: &'a str,
    success: bool,
    message: String,
    timestamp: String,
}

#[derive(Debug)]
struct CommandExecutionResult {
    success: bool,
    message: String,
}

pub struct ApiClient {
    pub hostname: String,
    tx: mpsc::UnboundedSender<SecurityEvent>,
}

impl ApiClient {
    pub fn new() -> Self {
        let raw_host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| {
            whoami::fallible::hostname().unwrap_or_else(|_| "Unknown-Host".to_string())
        });

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
        serial: Option<String>,
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
            severity: severity.to_uppercase(),
            serial,
        };

        if let Err(e) = self.tx.send(event) {
            eprintln!("🔥 [KUYRUK HATASI] Log kuyruğa atılamadı: {}", e);
        }

        Ok(())
    }

    pub async fn report_file_hash(
        &self,
        path: &str,
        hash: &str,
        pid: u32,
    ) -> Result<(), Box<dyn Error>> {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let cfg = AgentConfig::get();
        let payload = serde_json::json!({
            "hostname": self.hostname,
            "file_path": path,
            "file_hash": hash,
            "pid": pid
        });

        let url = format!("{}/api/v1/report_hash", cfg.server_base);

        if let Err(e) = HTTP_CLIENT
            .post(&url)
            .header("X-Agent-Key", &cfg.agent_key)
            .json(&payload)
            .send()
            .await
        {
            println!("⚠️ Hash raporlanamadı: {}", e);
        }

        Ok(())
    }

    pub async fn connect_and_listen(&self) {
        let cfg = AgentConfig::get();
        let url = match Url::parse(&cfg.ws_base) {
            Ok(url) => url,
            Err(e) => {
                eprintln!("❌ [WS] Geçersiz WS URL: {} | {}", cfg.ws_base, e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                return;
            }
        };

        println!("🎧 [COMMAND] Komuta merkezi dinleniyor: {}", cfg.ws_base);

        match connect_async(url).await {
            Ok((ws_stream, _)) => {
                println!("✅ [WS] Bağlantı kuruldu");
                let (mut write, mut read) = ws_stream.split();

                let register = RegisterMessage {
                    msg_type: "register",
                    hostname: &self.hostname,
                    capabilities: vec![
                        "KILL_PROCESS",
                        "ISOLATE_HOST",
                        "UNISOLATE_HOST",
                        "USB_DISABLE",
                        "USB_ENABLE",
                        "ANALYZE_HOST",
                        "SCAN_PROCESSES",
                    ],
                    agent_version: env!("CARGO_PKG_VERSION"),
                    timestamp: now_iso(),
                };

                if let Err(e) = write
                    .send(Message::Text(
                        serde_json::to_string(&register).unwrap_or_else(|_| {
                            format!(
                                r#"{{"type":"register","hostname":"{}","timestamp":"{}"}}"#,
                                self.hostname,
                                now_iso()
                            )
                        }),
                    ))
                    .await
                {
                    eprintln!("⚠️ [WS] Register gönderilemedi: {}", e);
                    return;
                }

                println!("📋 [WS] Agent kayıt gönderildi: {}", self.hostname);

                while let Some(message) = read.next().await {
                    match message {
                        Ok(Message::Text(text)) => {
                            let parsed = serde_json::from_str::<CommandMessage>(&text);
                            let cmd = match parsed {
                                Ok(cmd) => cmd,
                                Err(e) => {
                                    eprintln!("⚠️ [WS] Komut parse edilemedi: {} | {}", text, e);
                                    continue;
                                }
                            };

                            if cmd.msg_type != "COMMAND" {
                                continue;
                            }

                            if !self.is_command_for_me(cmd.target_hostname.as_deref()) {
                                continue;
                            }

                            let action = match cmd.action.clone() {
                                Some(a) if !a.trim().is_empty() => a,
                                _ => {
                                    eprintln!("⚠️ [WS] COMMAND mesajında action eksik: {}", text);
                                    continue;
                                }
                            };

                            let command_id = cmd
                                .command_id
                                .clone()
                                .unwrap_or_else(|| self.synthetic_command_id(&action));

                            println!("📩 [EMİR ALINDI] {} ({})", action, command_id);

                            let ack = CommandAckMessage {
                                msg_type: "COMMAND_ACK",
                                command_id: command_id.clone(),
                                hostname: &self.hostname,
                                action: &action,
                                status: "received",
                                timestamp: now_iso(),
                            };

                            if let Err(e) = write
                                .send(Message::Text(
                                    serde_json::to_string(&ack).unwrap_or_default(),
                                ))
                                .await
                            {
                                eprintln!("⚠️ [WS] ACK gönderilemedi: {}", e);
                            }

                            let result = self.handle_command(action.clone(), cmd).await;

                            let result_msg = CommandResultMessage {
                                msg_type: "COMMAND_RESULT",
                                command_id,
                                hostname: &self.hostname,
                                action: &result.0,
                                status: if result.1.success { "completed" } else { "failed" },
                                success: result.1.success,
                                message: result.1.message,
                                timestamp: now_iso(),
                            };

                            if let Err(e) = write
                                .send(Message::Text(
                                    serde_json::to_string(&result_msg).unwrap_or_default(),
                                ))
                                .await
                            {
                                eprintln!("⚠️ [WS] RESULT gönderilemedi: {}", e);
                            }
                        }
                        Ok(Message::Ping(payload)) => {
                            let _ = write.send(Message::Pong(payload)).await;
                        }
                        Ok(Message::Close(_)) => {
                            println!("⚠️ [WS] Sunucu bağlantıyı kapattı");
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("⚠️ [WS] Hata: {}", e);
                            break;
                        }
                    }
                }

                println!("⚠️ [WS] Bağlantı kapandı");
            }
            Err(e) => {
                eprintln!("⚠️ [WS] Bağlanamadı: {} — 5sn sonra tekrar.", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    fn is_command_for_me(&self, target_hostname: Option<&str>) -> bool {
        match target_hostname {
            Some(target) => {
                let target_upper = target.trim().to_uppercase();
                target_upper == "ALL" || target_upper == self.hostname
            }
            None => false,
        }
    }

    fn synthetic_command_id(&self, action: &str) -> String {
        format!(
            "{}-{}-{}",
            self.hostname,
            action.to_lowercase(),
            Utc::now().timestamp_millis()
        )
    }

    async fn handle_command(
        &self,
        action: String,
        cmd: CommandMessage,
    ) -> (String, CommandExecutionResult) {
        let result = match action.as_str() {
            "KILL_PROCESS" => {
                if let Some(pid) = cmd.target_pid {
                    self.kill_process(pid)
                } else {
                    CommandExecutionResult {
                        success: false,
                        message: "target_pid eksik".to_string(),
                    }
                }
            }
            "ISOLATE_HOST" => {
                let server_ip = self.server_ip_for_isolation();
                match crate::isolation_manager::enable_isolation(&server_ip) {
                    Ok(msg) => CommandExecutionResult {
                        success: true,
                        message: msg,
                    },
                    Err(err) => CommandExecutionResult {
                        success: false,
                        message: err,
                    },
                }
            }
            "UNISOLATE_HOST" => match crate::isolation_manager::disable_isolation() {
                Ok(msg) => CommandExecutionResult {
                    success: true,
                    message: msg,
                },
                Err(err) => CommandExecutionResult {
                    success: false,
                    message: err,
                },
            },
            "ANALYZE_HOST" | "SCAN_AND_REPORT_HASH" => {
                let client_new = Arc::new(ApiClient::new());
                tokio::spawn(async move {
                    crate::scanner::run_deep_scan(client_new).await;
                });

                CommandExecutionResult {
                    success: true,
                    message: "Deep scan başlatıldı".to_string(),
                }
            }
            "SCAN_PROCESSES" => CommandExecutionResult {
                success: true,
                message: "Process scan talebi alındı; sonuçlar event akışıyla raporlanacak"
                    .to_string(),
            },
            "USB_DISABLE" => {
                println!("🔌 [USB] Devre dışı bırakılıyor...");
                match crate::usb_control::disable_usb_storage() {
                    Ok(msg) => CommandExecutionResult {
                        success: true,
                        message: msg,
                    },
                    Err(err) => CommandExecutionResult {
                        success: false,
                        message: err,
                    },
                }
            }
            "USB_ENABLE" => {
                println!("🔌 [USB] Aktif ediliyor...");
                match crate::usb_control::enable_usb_storage() {
                    Ok(msg) => CommandExecutionResult {
                        success: true,
                        message: msg,
                    },
                    Err(err) => CommandExecutionResult {
                        success: false,
                        message: err,
                    },
                }
            }
            other => CommandExecutionResult {
                success: false,
                message: format!("Bilinmeyen komut: {}", other),
            },
        };

        (action, result)
    }

    fn kill_process(&self, pid_u32: u32) -> CommandExecutionResult {
        let mut sys = System::new_all();
        sys.refresh_all();

        let pid = Pid::from(pid_u32 as usize);
        if let Some(process) = sys.process(pid) {
            if process.kill() {
                CommandExecutionResult {
                    success: true,
                    message: format!("PID {} sonlandırıldı", pid_u32),
                }
            } else {
                CommandExecutionResult {
                    success: false,
                    message: format!(
                        "PID {} sonlandırılamadı (yetki veya koruma sorunu)",
                        pid_u32
                    ),
                }
            }
        } else {
            CommandExecutionResult {
                success: false,
                message: format!("PID {} bulunamadı", pid_u32),
            }
        }
    }

    fn server_ip_for_isolation(&self) -> String {
        let cfg = AgentConfig::get();

        if let Ok(url) = Url::parse(&cfg.server_base) {
            if let Some(host) = url.host_str() {
                return host.to_string();
            }
        }

        "127.0.0.1".to_string()
    }
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

async fn flush_logs(buffer: &[SecurityEvent]) {
    if buffer.is_empty() {
        return;
    }

    let cfg = AgentConfig::get();
    let url = format!("{}/api/v1/ingest", cfg.server_base);

    if let Err(e) = HTTP_CLIENT
        .post(&url)
        .header("X-Agent-Key", &cfg.agent_key)
        .header("Content-Type", "application/json")
        .json(buffer)
        .send()
        .await
    {
        eprintln!("⚠️ [INGEST HATASI] Loglar gönderilemedi: {}", e);
    }
}