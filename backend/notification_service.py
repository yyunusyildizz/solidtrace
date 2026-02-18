"""
SolidTrace Notification Service
Email + Slack + Webhook alerts
"""

import os
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List
from dotenv import load_dotenv

load_dotenv()

# ==========================================
# EMAIL CONFIGURATION
# ==========================================
class EmailNotifier:
    """Send email alerts via SMTP"""
    
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.from_email = os.getenv("FROM_EMAIL", self.smtp_user)
        self.to_emails = os.getenv("ALERT_EMAILS", "").split(",")
    
    def send_alert(self, alert: Dict) -> bool:
        """Send email alert"""
        if not self.smtp_user or not self.smtp_password:
            print("⚠ Email not configured")
            return False
        
        try:
            # Create email
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 SolidTrace Alert - {alert['risk']['level']} Risk"
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)
            
            # HTML body
            html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #1e293b; color: #fff; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 30px;">
                    <h1 style="color: #ef4444; margin: 0 0 20px 0;">🚨 Security Alert</h1>
                    
                    <div style="background: #1e293b; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                        <h2 style="margin: 0 0 10px 0; color: #f97316;">Risk Level: {alert['risk']['level']}</h2>
                        <p style="margin: 0; font-size: 24px; font-weight: bold;">{alert['risk']['score']}/100</p>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: #60a5fa;">Event Details</h3>
                        <p><strong>Hostname:</strong> {alert['event'].get('hostname', 'Unknown')}</p>
                        <p><strong>User:</strong> {alert['event'].get('user', 'Unknown')}</p>
                        <p><strong>Command:</strong> <code style="background: #000; padding: 5px; border-radius: 3px;">{alert['event'].get('command_line', 'N/A')}</code></p>
                        <p><strong>Timestamp:</strong> {alert['timestamp']}</p>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: #60a5fa;">Findings ({len(alert['findings'])})</h3>
                        <ul style="list-style: none; padding: 0;">
                            {''.join([f'<li style="background: #1e293b; padding: 10px; margin: 5px 0; border-left: 3px solid #ef4444;">• {f["rule"]} (Confidence: {int(f["confidence"]*100)}%)</li>' for f in alert['findings']])}
                        </ul>
                    </div>
                    
                    <div>
                        <h3 style="color: #60a5fa;">MITRE ATT&CK</h3>
                        <ul style="list-style: none; padding: 0;">
                            {''.join([f'<li style="background: #1e293b; padding: 10px; margin: 5px 0;"><strong>{m["technique"]}</strong> - {m["tactic"]}</li>' for m in alert['mitre']])}
                        </ul>
                    </div>
                    
                    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #334155; text-align: center; color: #64748b;">
                        <p>SolidTrace Security Operations Center</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, "html"))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            print(f"✓ Email sent to {len(self.to_emails)} recipients")
            return True
            
        except Exception as e:
            print(f"⚠ Email error: {e}")
            return False

# ==========================================
# SLACK NOTIFICATION
# ==========================================
class SlackNotifier:
    """Send alerts to Slack channel"""
    
    def __init__(self):
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    
    def send_alert(self, alert: Dict) -> bool:
        """Send Slack notification"""
        if not self.webhook_url:
            print("⚠ Slack not configured")
            return False
        
        try:
            # Risk color
            color_map = {
                "CRITICAL": "#dc2626",
                "HIGH": "#f97316",
                "MEDIUM": "#facc15",
                "LOW": "#22c55e"
            }
            color = color_map.get(alert['risk']['level'], "#64748b")
            
            # Slack message
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"🚨 Security Alert - {alert['risk']['level']} Risk",
                        "text": f"Risk Score: *{alert['risk']['score']}/100*",
                        "fields": [
                            {
                                "title": "Hostname",
                                "value": alert['event'].get('hostname', 'Unknown'),
                                "short": True
                            },
                            {
                                "title": "User",
                                "value": alert['event'].get('user', 'Unknown'),
                                "short": True
                            },
                            {
                                "title": "Command",
                                "value": f"`{alert['event'].get('command_line', 'N/A')}`",
                                "short": False
                            },
                            {
                                "title": "Findings",
                                "value": "\n".join([f"• {f['rule']}" for f in alert['findings']]),
                                "short": False
                            },
                            {
                                "title": "MITRE Techniques",
                                "value": ", ".join([m['technique'] for m in alert['mitre']]),
                                "short": False
                            }
                        ],
                        "footer": "SolidTrace SOC",
                        "ts": int(alert['timestamp'].replace('Z', '').replace('T', ' ').replace('-', '').replace(':', '').replace('.', '')[:14])
                    }
                ]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            
            if response.status_code == 200:
                print("✓ Slack notification sent")
                return True
            else:
                print(f"⚠ Slack error: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"⚠ Slack error: {e}")
            return False

# ==========================================
# WEBHOOK NOTIFICATION
# ==========================================
class WebhookNotifier:
    """Send alerts to custom webhook"""
    
    def __init__(self):
        self.webhook_urls = os.getenv("WEBHOOK_URLS", "").split(",")
    
    def send_alert(self, alert: Dict) -> bool:
        """Send webhook notification"""
        if not self.webhook_urls or not self.webhook_urls[0]:
            return False
        
        success = True
        for url in self.webhook_urls:
            try:
                response = requests.post(
                    url.strip(),
                    json=alert,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                if response.status_code not in [200, 201, 204]:
                    print(f"⚠ Webhook error: {response.status_code}")
                    success = False
                    
            except Exception as e:
                print(f"⚠ Webhook error: {e}")
                success = False
        
        return success

# ==========================================
# NOTIFICATION MANAGER
# ==========================================
class NotificationManager:
    """Central notification manager"""
    
    def __init__(self):
        self.email = EmailNotifier()
        self.slack = SlackNotifier()
        self.webhook = WebhookNotifier()
        
        # Minimum risk threshold
        self.min_risk = int(os.getenv("MIN_ALERT_RISK", "50"))
    
    def send_all(self, alert: Dict) -> Dict[str, bool]:
        """Send alert through all configured channels"""
        
        # Check risk threshold
        if alert['risk']['score'] < self.min_risk:
            print(f"⏭ Alert below threshold ({alert['risk']['score']} < {self.min_risk})")
            return {"skipped": True}
        
        results = {
            "email": self.email.send_alert(alert),
            "slack": self.slack.send_alert(alert),
            "webhook": self.webhook.send_alert(alert)
        }
        
        return results

# ==========================================
# USAGE EXAMPLE
# ==========================================
if __name__ == "__main__":
    # Test notification
    test_alert = {
        "timestamp": "2026-01-27T10:30:00Z",
        "event": {
            "hostname": "WORKSTATION-001",
            "user": "admin",
            "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ="
        },
        "findings": [
            {"rule": "Encoded Command", "confidence": 0.8}
        ],
        "mitre": [
            {"technique": "T1027", "tactic": "Defense Evasion"}
        ],
        "risk": {
            "score": 75,
            "level": "HIGH"
        }
    }
    
    notifier = NotificationManager()
    results = notifier.send_all(test_alert)
    
    print(f"\n📧 Notification Results:")
    for channel, success in results.items():
        status = "✓" if success else "✗"
        print(f"   {status} {channel.capitalize()}")
