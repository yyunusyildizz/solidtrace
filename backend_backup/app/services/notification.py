"""
app.services.notification
=========================
Bildirim kanalları: E-posta (SMTP), Slack, Webhook.
Tüm ayarlar .env üzerinden okunur — kod içinde key/şifre yok.
"""

from __future__ import annotations

import os
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("SolidTrace.Notification")


# ---------------------------------------------------------------------------
# E-POSTA
# ---------------------------------------------------------------------------

class EmailNotifier:
    """SMTP üzerinden HTML e-posta alert gönderimi."""

    def __init__(self):
        self.smtp_server   = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port     = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user     = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.from_email    = os.getenv("FROM_EMAIL", self.smtp_user)
        self.to_emails     = [e for e in os.getenv("ALERT_EMAILS", "").split(",") if e.strip()]

    def send_alert(self, alert: Dict) -> bool:
        if not self.smtp_user or not self.smtp_password or not self.to_emails:
            logger.debug("E-posta yapılandırılmamış — atlanıyor.")
            return False
        try:
            msg            = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 SolidTrace Alert - {alert['risk']['level']} Risk"
            msg["From"]    = self.from_email
            msg["To"]      = ", ".join(self.to_emails)

            findings_html = "".join([
                f'<li style="background:#1e293b;padding:10px;margin:5px 0;border-left:3px solid #ef4444;">'
                f'• {f["rule"]} (Güven: {int(f["confidence"] * 100)}%)</li>'
                for f in alert.get("findings", [])
            ])
            mitre_html = "".join([
                f'<li style="background:#1e293b;padding:10px;margin:5px 0;">'
                f'<strong>{m["technique"]}</strong> - {m["tactic"]}</li>'
                for m in alert.get("mitre", [])
            ])

            html = f"""
            <html><body style="font-family:Arial,sans-serif;background:#1e293b;color:#fff;padding:20px;">
              <div style="max-width:600px;margin:0 auto;background:#0f172a;border:1px solid #334155;border-radius:10px;padding:30px;">
                <h1 style="color:#ef4444;margin:0 0 20px 0;">🚨 Security Alert</h1>
                <div style="background:#1e293b;padding:15px;border-radius:5px;margin-bottom:20px;">
                  <h2 style="margin:0 0 10px 0;color:#f97316;">Risk: {alert['risk']['level']}</h2>
                  <p style="margin:0;font-size:24px;font-weight:bold;">{alert['risk']['score']}/100</p>
                </div>
                <p><strong>Hostname:</strong> {alert.get('event', {}).get('hostname', 'Unknown')}</p>
                <p><strong>User:</strong> {alert.get('event', {}).get('user', 'Unknown')}</p>
                <p><strong>Command:</strong> <code>{alert.get('event', {}).get('command_line', 'N/A')}</code></p>
                <p><strong>Timestamp:</strong> {alert.get('timestamp', '')}</p>
                <h3 style="color:#60a5fa;">Bulgular</h3>
                <ul style="list-style:none;padding:0;">{findings_html}</ul>
                <h3 style="color:#60a5fa;">MITRE ATT&CK</h3>
                <ul style="list-style:none;padding:0;">{mitre_html}</ul>
              </div>
            </body></html>
            """
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as s:
                s.starttls()
                s.login(self.smtp_user, self.smtp_password)
                s.send_message(msg)

            logger.info(f"✅ E-posta gönderildi → {len(self.to_emails)} alıcı")
            return True
        except Exception as e:
            logger.error(f"E-posta hatası: {e}")
            return False

    def send_invite(self, to_email: str, username: str, temp_password: str) -> bool:
        """Kullanıcı davet e-postası."""
        if not self.smtp_user or not self.smtp_password:
            return False
        server_url = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")[0]
        try:
            msg            = MIMEMultipart("alternative")
            msg["Subject"] = "SolidTrace — Hesabınız Hazır"
            msg["From"]    = self.from_email
            msg["To"]      = to_email

            html = f"""
            <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#0d0d14;color:#e0e0e0;border-radius:12px;overflow:hidden">
              <div style="background:#1a1a2e;padding:28px 32px;border-bottom:1px solid #ffffff10">
                <h1 style="margin:0;font-size:20px;color:#fff">🛡 SolidTrace</h1>
              </div>
              <div style="padding:28px 32px">
                <h2 style="font-size:16px;color:#fff;margin-top:0">Hesabınız Oluşturuldu</h2>
                <div style="background:#ffffff08;border:1px solid #ffffff12;border-radius:8px;padding:16px;margin:16px 0">
                  <p style="margin:0 0 8px;font-size:12px;color:#888">Kullanıcı Adı</p>
                  <code style="font-size:15px;color:#60a5fa">{username}</code>
                  <p style="margin:12px 0 8px;font-size:12px;color:#888">Geçici Şifre</p>
                  <code style="font-size:15px;color:#34d399">{temp_password}</code>
                </div>
                <a href="{server_url}" style="display:inline-block;background:#3b82f6;color:#fff;text-decoration:none;padding:10px 24px;border-radius:8px;font-size:13px;font-weight:bold">
                  Platforma Giriş Yap →
                </a>
              </div>
            </div>
            """
            msg.attach(MIMEText(html, "html"))
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as s:
                s.starttls()
                s.login(self.smtp_user, self.smtp_password)
                s.sendmail(self.smtp_user, to_email, msg.as_string())
            logger.info(f"📧 Davet e-postası → {to_email}")
            return True
        except Exception as e:
            logger.error(f"Davet e-postası hatası: {e}")
            return False


# ---------------------------------------------------------------------------
# SLACK
# ---------------------------------------------------------------------------

class SlackNotifier:
    """Slack Incoming Webhook üzerinden bildirim."""

    def __init__(self):
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL")

    def send_alert(self, alert: Dict) -> bool:
        if not self.webhook_url:
            return False
        color_map = {"CRITICAL": "#dc2626", "HIGH": "#f97316",
                     "MEDIUM": "#facc15", "LOW": "#22c55e"}
        try:
            payload = {
                "attachments": [{
                    "color": color_map.get(alert["risk"]["level"], "#64748b"),
                    "title": f"🚨 Security Alert - {alert['risk']['level']} Risk",
                    "text":  f"Risk Score: *{alert['risk']['score']}/100*",
                    "fields": [
                        {"title": "Hostname", "value": alert.get("event", {}).get("hostname", "?"), "short": True},
                        {"title": "User",     "value": alert.get("event", {}).get("user", "?"),     "short": True},
                        {"title": "Command",  "value": f"`{alert.get('event', {}).get('command_line', 'N/A')}`", "short": False},
                        {"title": "Findings", "value": "\n".join([f"• {f['rule']}" for f in alert.get("findings", [])]), "short": False},
                    ],
                    "footer": "SolidTrace SOC",
                }]
            }
            r = requests.post(self.webhook_url, json=payload, timeout=5)
            return r.status_code == 200
        except Exception as e:
            logger.error(f"Slack hatası: {e}")
            return False


# ---------------------------------------------------------------------------
# WEBHOOK
# ---------------------------------------------------------------------------

class WebhookNotifier:
    """Özel webhook URL'lerine JSON POST."""

    def __init__(self):
        raw = os.getenv("WEBHOOK_URLS", "")
        self.webhook_urls = [u.strip() for u in raw.split(",") if u.strip()]

    def send_alert(self, alert: Dict) -> bool:
        if not self.webhook_urls:
            return False
        success = True
        for url in self.webhook_urls:
            try:
                r = requests.post(url, json=alert,
                                  headers={"Content-Type": "application/json"}, timeout=5)
                if r.status_code not in (200, 201, 204):
                    logger.warning(f"Webhook hatası {url}: {r.status_code}")
                    success = False
            except Exception as e:
                logger.error(f"Webhook hatası {url}: {e}")
                success = False
        return success


# ---------------------------------------------------------------------------
# MERKEZ YÖNETİCİ
# ---------------------------------------------------------------------------

class NotificationManager:
    """Tüm bildirim kanallarını tek noktadan yönetir."""

    def __init__(self):
        self.email   = EmailNotifier()
        self.slack   = SlackNotifier()
        self.webhook = WebhookNotifier()
        self.min_risk = int(os.getenv("MIN_ALERT_RISK", "50"))

    def send_all(self, alert: Dict) -> Dict[str, bool]:
        if alert.get("risk", {}).get("score", 0) < self.min_risk:
            return {"skipped": True}
        return {
            "email":   self.email.send_alert(alert),
            "slack":   self.slack.send_alert(alert),
            "webhook": self.webhook.send_alert(alert),
        }
