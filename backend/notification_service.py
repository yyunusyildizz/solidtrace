"""
SolidTrace Notification Service - v2.0 (REVISED)
Düzeltmeler:
  - Slack timestamp: string replace zinciri → datetime.timestamp() ile düzeltildi
  - requests → httpx (async bağlam uyumu için)
  - HTML email'de XSS riski: command_line html.escape() ile temizleniyor
  - to_emails boş string filtresi eklendi
  - logging entegrasyonu (print yerine)
"""

import os
import html
import smtplib
import logging
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("SolidTraceAPI")

# ==========================================
# EMAIL
# ==========================================
class EmailNotifier:

    def __init__(self):
        self.smtp_server  = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port    = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user    = os.getenv("SMTP_USER")
        self.smtp_password= os.getenv("SMTP_PASSWORD")
        self.from_email   = os.getenv("FROM_EMAIL", self.smtp_user)
        # FIX: Boş string filtresi — "".split(",") → [""] sorununu önler
        self.to_emails    = [e.strip() for e in os.getenv("ALERT_EMAILS", "").split(",") if e.strip()]

    def send_alert(self, alert: Dict) -> bool:
        if not self.smtp_user or not self.smtp_password:
            logger.warning("⚠ Email yapılandırılmamış (SMTP_USER/SMTP_PASSWORD eksik)")
            return False

        if not self.to_emails:
            logger.warning("⚠ Alıcı email adresi tanımlı değil (ALERT_EMAILS)")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 SolidTrace Alert - {alert['risk']['level']} Risk"
            msg["From"]    = self.from_email
            msg["To"]      = ", ".join(self.to_emails)

            # FIX: HTML injection / XSS — command_line ve diğer user-controlled alanlar escape ediliyor
            safe_cmd      = html.escape(str(alert["event"].get("command_line", "N/A")))
            safe_hostname = html.escape(str(alert["event"].get("hostname", "Unknown")))
            safe_user     = html.escape(str(alert["event"].get("user", "Unknown")))

            findings_html = "".join([
                f'<li style="background:#1e293b;padding:10px;margin:5px 0;border-left:3px solid #ef4444;">'
                f'• {html.escape(f["rule"])} (Confidence: {int(f.get("confidence", 0) * 100)}%)</li>'
                for f in alert.get("findings", [])
            ])

            mitre_html = "".join([
                f'<li style="background:#1e293b;padding:10px;margin:5px 0;">'
                f'<strong>{html.escape(m["technique"])}</strong> - {html.escape(m["tactic"])}</li>'
                for m in alert.get("mitre", [])
            ])

            html_body = f"""
            <html>
            <body style="font-family:Arial,sans-serif;background:#1e293b;color:#fff;padding:20px;">
              <div style="max-width:600px;margin:0 auto;background:#0f172a;border:1px solid #334155;border-radius:10px;padding:30px;">
                <h1 style="color:#ef4444;margin:0 0 20px 0;">🚨 Security Alert</h1>

                <div style="background:#1e293b;padding:15px;border-radius:5px;margin-bottom:20px;">
                  <h2 style="margin:0 0 10px 0;color:#f97316;">Risk Level: {alert['risk']['level']}</h2>
                  <p style="margin:0;font-size:24px;font-weight:bold;">{alert['risk']['score']}/100</p>
                </div>

                <div style="margin-bottom:20px;">
                  <h3 style="color:#60a5fa;">Event Details</h3>
                  <p><strong>Hostname:</strong> {safe_hostname}</p>
                  <p><strong>User:</strong> {safe_user}</p>
                  <p><strong>Command:</strong>
                    <code style="background:#000;padding:5px;border-radius:3px;">{safe_cmd}</code>
                  </p>
                  <p><strong>Timestamp:</strong> {alert.get('timestamp', 'Unknown')}</p>
                </div>

                <div style="margin-bottom:20px;">
                  <h3 style="color:#60a5fa;">Findings ({len(alert.get('findings', []))})</h3>
                  <ul style="list-style:none;padding:0;">{findings_html}</ul>
                </div>

                <div>
                  <h3 style="color:#60a5fa;">MITRE ATT&CK</h3>
                  <ul style="list-style:none;padding:0;">{mitre_html}</ul>
                </div>

                <div style="margin-top:30px;padding-top:20px;border-top:1px solid #334155;text-align:center;color:#64748b;">
                  <p>SolidTrace Security Operations Center</p>
                </div>
              </div>
            </body>
            </html>
            """

            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            logger.info(f"✓ Email gönderildi → {len(self.to_emails)} alıcı")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("⚠ Email hatası: Kimlik doğrulama başarısız (şifre/uygulama şifresi kontrol edin)")
            return False
        except Exception as e:
            logger.error(f"⚠ Email hatası: {e}")
            return False


# ==========================================
# SLACK
# ==========================================
class SlackNotifier:

    def __init__(self):
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL")

    def send_alert(self, alert: Dict) -> bool:
        if not self.webhook_url:
            logger.warning("⚠ Slack yapılandırılmamış (SLACK_WEBHOOK_URL eksik)")
            return False

        try:
            color_map = {
                "CRITICAL": "#dc2626",
                "HIGH":     "#f97316",
                "MEDIUM":   "#facc15",
                "LOW":      "#22c55e"
            }
            color = color_map.get(alert["risk"]["level"], "#64748b")

            # FIX: Timestamp — string replace zinciri yerine datetime.timestamp()
            try:
                ts = int(datetime.fromisoformat(
                    alert["timestamp"].replace("Z", "+00:00")
                ).timestamp())
            except Exception:
                ts = int(datetime.utcnow().timestamp())

            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"🚨 Security Alert - {alert['risk']['level']} Risk",
                    "text":  f"Risk Score: *{alert['risk']['score']}/100*",
                    "fields": [
                        {"title": "Hostname", "value": alert["event"].get("hostname", "Unknown"), "short": True},
                        {"title": "User",     "value": alert["event"].get("user", "Unknown"),     "short": True},
                        {"title": "Command",  "value": f"`{alert['event'].get('command_line', 'N/A')}`", "short": False},
                        {"title": "Findings", "value": "\n".join(
                            [f"• {f['rule']}" for f in alert.get("findings", [])]
                        ), "short": False},
                        {"title": "MITRE Techniques", "value": ", ".join(
                            [m["technique"] for m in alert.get("mitre", [])]
                        ), "short": False},
                    ],
                    "footer": "SolidTrace SOC",
                    "ts": ts   # FIX: Doğru Unix timestamp
                }]
            }

            # FIX: requests → httpx (async bağlamda block etmemesi için sync httpx kullanılıyor)
            response = httpx.post(self.webhook_url, json=payload, timeout=5)

            if response.status_code == 200:
                logger.info("✓ Slack bildirimi gönderildi")
                return True
            else:
                logger.error(f"⚠ Slack hatası: HTTP {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"⚠ Slack hatası: {e}")
            return False


# ==========================================
# WEBHOOK
# ==========================================
class WebhookNotifier:

    def __init__(self):
        # FIX: Boş string filtresi
        self.webhook_urls = [u.strip() for u in os.getenv("WEBHOOK_URLS", "").split(",") if u.strip()]

    def send_alert(self, alert: Dict) -> bool:
        if not self.webhook_urls:
            return False

        success = True
        for url in self.webhook_urls:
            try:
                # FIX: requests → httpx
                response = httpx.post(
                    url,
                    json=alert,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                if response.status_code not in (200, 201, 204):
                    logger.error(f"⚠ Webhook hatası ({url}): HTTP {response.status_code}")
                    success = False
            except Exception as e:
                logger.error(f"⚠ Webhook hatası ({url}): {e}")
                success = False

        return success


# ==========================================
# NOTIFICATION MANAGER
# ==========================================
class NotificationManager:

    def __init__(self):
        self.email   = EmailNotifier()
        self.slack   = SlackNotifier()
        self.webhook = WebhookNotifier()
        self.min_risk = int(os.getenv("MIN_ALERT_RISK", "50"))

    def send_all(self, alert: Dict) -> Dict[str, bool]:
        """Tüm yapılandırılmış kanallara bildirim gönder."""
        risk_score = alert.get("risk", {}).get("score", 0)

        if risk_score < self.min_risk:
            logger.debug(f"⏭ Alert eşik altında ({risk_score} < {self.min_risk}), atlandı")
            return {"skipped": True}

        results = {
            "email":   self.email.send_alert(alert),
            "slack":   self.slack.send_alert(alert),
            "webhook": self.webhook.send_alert(alert),
        }
        return results


# ==========================================
# TEST
# ==========================================
if __name__ == "__main__":
    test_alert = {
        "timestamp": "2026-02-21T10:30:00Z",
        "event": {
            "hostname":    "WORKSTATION-001",
            "user":        "admin",
            "command_line":"powershell.exe -enc SGVsbG8gV29ybGQ="
        },
        "findings": [{"rule": "Encoded Command", "confidence": 0.8}],
        "mitre":    [{"technique": "T1027", "tactic": "Defense Evasion"}],
        "risk":     {"score": 75, "level": "HIGH"}
    }

    notifier = NotificationManager()
    results  = notifier.send_all(test_alert)

    print("\n📧 Bildirim Sonuçları:")
    for channel, result in results.items():
        print(f"   {'✓' if result else '✗'} {channel.capitalize()}")