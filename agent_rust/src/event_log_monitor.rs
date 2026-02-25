// event_log_monitor.rs
// Windows Security/System/Application Event Log okuyucu
// QRadar/Splunk'ın temel veri kaynağı olan Windows olaylarını yakalar
//
// Kritik Event ID'ler:
//   4624 — Başarılı oturum açma
//   4625 — Başarısız oturum açma (brute force tespiti için)
//   4648 — Explicit credential ile oturum (pass-the-hash belirtisi)
//   4688 — Yeni process oluşturma (command line dahil)
//   4698 — Zamanlanmış görev oluşturma (persistence)
//   4699 — Zamanlanmış görev silme
//   4702 — Zamanlanmış görev değişikliği
//   4719 — Sistem denetim politikası değişti
//   4720 — Kullanıcı hesabı oluşturuldu
//   4732 — Gruba üye eklendi (Administrators grubuna ekleme = kritik)
//   4768 — Kerberos TGT isteği (golden ticket tespiti için)
//   4769 — Kerberos servis bileti isteği
//   7045 — Yeni servis kuruldu (persistence)
//   1102 — Denetim logu temizlendi (log silme = kritik)

use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use tokio::time::sleep;
use crate::api_client::ApiClient;

// İzlenecek kritik Event ID'leri ve metadata'ları
struct EventDef {
    severity:    &'static str,
    event_type:  &'static str,
    description: &'static str,
}

fn critical_event_ids() -> HashMap<u32, EventDef> {
    let mut m = HashMap::new();

    // Kimlik Doğrulama Olayları
    m.insert(4624, EventDef { severity: "INFO",     event_type: "LOGON_SUCCESS",       description: "Başarılı oturum açma"                  });
    m.insert(4625, EventDef { severity: "HIGH",     event_type: "LOGON_FAILURE",        description: "Başarısız oturum açma"                  });
    m.insert(4648, EventDef { severity: "HIGH",     event_type: "EXPLICIT_CREDENTIAL",  description: "Explicit credential kullanımı (PTH?)"   });
    m.insert(4672, EventDef { severity: "MEDIUM",   event_type: "SPECIAL_LOGON",        description: "Özel ayrıcalıklarla oturum açma"        });

    // Process Olayları
    m.insert(4688, EventDef { severity: "INFO",     event_type: "PROCESS_CREATE_EVT",   description: "Yeni process oluşturuldu"               });
    m.insert(4689, EventDef { severity: "INFO",     event_type: "PROCESS_EXIT",         description: "Process sonlandı"                       });

    // Persistence / Kalıcılık
    m.insert(4698, EventDef { severity: "CRITICAL", event_type: "SCHTASK_CREATED",      description: "Zamanlanmış görev oluşturuldu"          });
    m.insert(4699, EventDef { severity: "HIGH",     event_type: "SCHTASK_DELETED",      description: "Zamanlanmış görev silindi"              });
    m.insert(4702, EventDef { severity: "HIGH",     event_type: "SCHTASK_MODIFIED",     description: "Zamanlanmış görev değiştirildi"         });
    m.insert(7045, EventDef { severity: "CRITICAL", event_type: "SERVICE_INSTALLED",    description: "Yeni Windows servisi kuruldu"           });

    // Hesap Yönetimi
    m.insert(4720, EventDef { severity: "HIGH",     event_type: "ACCOUNT_CREATED",      description: "Kullanıcı hesabı oluşturuldu"           });
    m.insert(4726, EventDef { severity: "HIGH",     event_type: "ACCOUNT_DELETED",      description: "Kullanıcı hesabı silindi"               });
    m.insert(4732, EventDef { severity: "CRITICAL", event_type: "GROUP_MEMBER_ADDED",   description: "Gruba üye eklendi (Admin grubu?)"       });
    m.insert(4756, EventDef { severity: "CRITICAL", event_type: "UNIVERSAL_GROUP_ADD",  description: "Universal gruba üye eklendi"            });

    // Kerberos (Lateral Movement / Golden Ticket)
    m.insert(4768, EventDef { severity: "MEDIUM",   event_type: "KERBEROS_TGT",         description: "Kerberos TGT isteği"                    });
    m.insert(4769, EventDef { severity: "MEDIUM",   event_type: "KERBEROS_SERVICE",     description: "Kerberos servis bileti isteği"          });
    m.insert(4771, EventDef { severity: "HIGH",     event_type: "KERBEROS_PREAUTH_FAIL", description: "Kerberos pre-auth başarısız"           });

    // Politika ve Denetim
    m.insert(4719, EventDef { severity: "CRITICAL", event_type: "AUDIT_POLICY_CHANGED", description: "Sistem denetim politikası değiştirildi" });
    m.insert(1102, EventDef { severity: "CRITICAL", event_type: "LOG_CLEARED",          description: "🚨 Güvenlik logu temizlendi!"            });
    m.insert(4616, EventDef { severity: "HIGH",     event_type: "SYSTEM_TIME_CHANGED",  description: "Sistem saati değiştirildi"              });

    // Ağ Paylaşımı (Lateral Movement)
    m.insert(5140, EventDef { severity: "MEDIUM",   event_type: "SHARE_ACCESS",         description: "Ağ paylaşımına erişim"                  });
    m.insert(5145, EventDef { severity: "HIGH",     event_type: "SHARE_OBJECT_ACCESS",  description: "Paylaşım nesnesi kontrol edildi"        });

    m
}

// Log kanalları — Security en kritik, diğerleri tamamlayıcı
const LOG_CHANNELS: &[&str] = &[
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational", // PowerShell script block logging
    "Microsoft-Windows-Sysmon/Operational",     // Sysmon varsa
    "Microsoft-Windows-TaskScheduler/Operational",
];

pub async fn run_monitor(client: Arc<ApiClient>) {
    println!("📋 [EVTLOG] Windows Event Log İzleyicisi Başlatıldı...");
    println!("📋 [EVTLOG] {} kritik Event ID izleniyor.", critical_event_ids().len());

    // Her kanal için ayrı task başlat
    let mut handles = Vec::new();
    for channel in LOG_CHANNELS {
        let c = client.clone();
        let ch = channel.to_string();
        let handle = tokio::spawn(async move {
            monitor_channel(c, &ch).await;
        });
        handles.push(handle);
    }

    // Tüm task'ları bekle (hiçbiri normalde bitmez)
    for handle in handles {
        let _ = handle.await;
    }
}

async fn monitor_channel(client: Arc<ApiClient>, channel: &str) {
    println!("📂 [EVTLOG] Kanal izleniyor: {}", channel);

    // Son okunan record numarasını tut — başlangıçta sadece yeni olayları oku
    let mut last_record: u32 = get_latest_record_number(channel).await;
    let event_defs = critical_event_ids();

    loop {
        sleep(Duration::from_secs(2)).await;

        let events = read_new_events(channel, last_record).await;

        for event in events {
            // Son record'u güncelle
            if event.record_number > last_record {
                last_record = event.record_number;
            }

            // Bu Event ID bizi ilgilendiriyor mu?
            if let Some(def) = event_defs.get(&event.event_id) {
                let details = format_event(&event, def);
                println!("📋 [EVT-{}] {} | {}", event.event_id, def.description, event.computer);

                let c = client.clone();
                let d = details.clone();
                let sev = def.severity;
                let etype = def.event_type;
                let pid = event.pid;

                tokio::spawn(async move {
                    let _ = c.send_event(etype, &d, sev, pid, None).await;
                });
            }
        }
    }
}

#[derive(Debug, Clone)]
struct WindowsEvent {
    record_number: u32,
    event_id:      u32,
    computer:      String,
    user:          String,
    pid:           u32,
    timestamp:     String,
    channel:       String,
    data:          Vec<String>, // Parametre değerleri
}

fn format_event(event: &WindowsEvent, def: &EventDef) -> String {
    let params = if event.data.is_empty() {
        String::new()
    } else {
        format!(" | Parametreler: {}", event.data.join(", "))
    };

    format!(
        "EventID:{} | {} | Bilgisayar:{} | Kullanıcı:{} | Zaman:{} | Kanal:{}{}",
        event.event_id,
        def.description,
        event.computer,
        event.user,
        event.timestamp,
        event.channel,
        params,
    )
}

// Windows Event Log API'sini doğrudan kullanmak yerine
// wevtutil veya PowerShell üzerinden okuma — daha stabil ve yetki gerektirmez
async fn read_new_events(channel: &str, after_record: u32) -> Vec<WindowsEvent> {
    // XPath sorgusu ile sadece ilgilendiğimiz Event ID'leri filtrele
    let event_id_filter = critical_event_ids()
        .keys()
        .map(|id| format!("EventID={}", id))
        .collect::<Vec<_>>()
        .join(" or ");

    let xpath = format!(
        "*[System[({}) and EventRecordID > {}]]",
        event_id_filter, after_record
    );

    let ps_cmd = format!(
        r#"
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $OutputEncoding = [System.Text.Encoding]::UTF8
        try {{
            $events = Get-WinEvent -LogName '{channel}' -FilterXPath '{xpath}' -MaxEvents 50 -ErrorAction Stop
            $events | ForEach-Object {{
                $msg = $_.Message
                if (-not $msg) {{ $msg = ($_ | Format-List | Out-String) }}
                $msg = $msg -replace "`r`n", " " -replace "`n", " " -replace "`r", "" -replace "  +", " "
                $props = @{{
                    RecordId    = $_.RecordId
                    Id          = $_.Id
                    Computer    = $_.MachineName
                    UserId      = if ($_.UserId) {{ $_.UserId.Value }} else {{ 'N/A' }}
                    Pid         = $_.ProcessId
                    TimeCreated = $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')
                    Message     = $msg
                }}
                [PSCustomObject]$props
            }} | ConvertTo-Json -Depth 2 -Compress
        }} catch [System.Exception] {{
            if ($_.Exception.Message -notmatch 'No events') {{
                Write-Error $_.Exception.Message
            }}
        }}
        "#,
        channel = channel,
        xpath = xpath,
    );

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-NonInteractive",
                "-OutputFormat", "Text",
                "-Command", &ps_cmd,
            ])
            .env("PYTHONIOENCODING", "utf-8")  // genel encoding hint
            .output()
    })
    .await;

    match output {
        Ok(Ok(o)) => {
            // PowerShell çıktısını önce UTF-8, başarısız olursa Windows-1254 (Türkçe) ile oku
            let text = if let Ok(s) = std::str::from_utf8(&o.stdout) {
                s.to_string()
            } else {
                // UTF-8 decode başarısız — Windows-1254 CP olarak byte-by-byte çevir
                o.stdout.iter()
                    .map(|&b| {
                        // Temel Latin + Windows-1254 Türkçe harfler
                        match b {
                            0x00..=0x7F => b as char,
                            0xC7 => 'Ç', 0xE7 => 'ç',
                            0xD0 => 'Ğ', 0xF0 => 'ğ',
                            0xDD => 'İ', 0xFD => 'ı',
                            0xD6 => 'Ö', 0xF6 => 'ö',
                            0xDE => 'Ş', 0xFE => 'ş',
                            0xDC => 'Ü', 0xFC => 'ü',
                            _ => char::REPLACEMENT_CHARACTER,
                        }
                    })
                    .collect()
            };
            parse_powershell_events(&text, channel)
        },
        _ => Vec::new(),
    }
}

fn parse_powershell_events(json_str: &str, channel: &str) -> Vec<WindowsEvent> {
    let trimmed = json_str.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Array veya tek obje
    let values: Vec<serde_json::Value> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).unwrap_or_default()
    } else if trimmed.starts_with('{') {
        serde_json::from_str::<serde_json::Value>(trimmed)
            .map(|v| vec![v])
            .unwrap_or_default()
    } else {
        return Vec::new();
    };

    values.into_iter().map(|v| WindowsEvent {
            record_number: v["RecordId"].as_u64().unwrap_or(0u64) as u32,
            event_id:      v["Id"].as_u64().unwrap_or(0u64) as u32,
            computer:      v["Computer"].as_str().unwrap_or("Unknown").to_string(),
            user:          v["UserId"].as_str().unwrap_or("N/A").to_string(),
            pid:           v["Pid"].as_u64().unwrap_or(0u64) as u32,
            timestamp:     v["TimeCreated"].as_str().unwrap_or("").to_string(),
            channel:       channel.to_string(),
            data:          vec![
                v["Message"].as_str().unwrap_or("").chars().take(500).collect()
            ],
    }).collect()
}

async fn get_latest_record_number(channel: &str) -> u32 {
    let ch = channel.to_string();
    let ps_cmd = format!(
        "try {{ (Get-WinEvent -LogName '{}' -MaxEvents 1 -ErrorAction Stop).RecordId }} catch {{ 0 }}",
        ch
    );

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .output()
    })
    .await;

    match output {
        Ok(Ok(o)) => {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u32>()
                .unwrap_or(0)
        }
        _ => 0,
    }
}