import os
import smtplib
import threading
import socket
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("EmailAlertManager")

class EmailAlertManager:
    def __init__(self):
        self.sent_alert_ids = set()
        self.lock = threading.Lock()

    def get_smtp_config(self):
        env_dict = {}
        env_file = os.path.join(os.path.dirname(__file__), '.env')
        if os.path.exists(env_file):
            try:
                with open(env_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            k, v = line.split('=', 1)
                            env_dict[k.strip()] = v.strip()
            except Exception:
                pass

        return {
            'host': env_dict.get('SMARTLOG_SMTP_HOST') or os.environ.get('SMARTLOG_SMTP_HOST', ''),
            'port': int(env_dict.get('SMARTLOG_SMTP_PORT') or os.environ.get('SMARTLOG_SMTP_PORT', '587')),
            'username': env_dict.get('SMARTLOG_SMTP_USERNAME') or os.environ.get('SMARTLOG_SMTP_USERNAME', ''),
            'password': env_dict.get('SMARTLOG_SMTP_PASSWORD') or os.environ.get('SMARTLOG_SMTP_PASSWORD', ''),
            'to_email': env_dict.get('SMARTLOG_ALERT_EMAIL') or os.environ.get('SMARTLOG_ALERT_EMAIL', '')
        }

    def is_configured(self):
        cfg = self.get_smtp_config()
        return bool(cfg['host'] and cfg['username'] and cfg['password'] and cfg['to_email'])

    def _generate_alert_id(self, event_data):
        computer = str(event_data.get('hostname') or 'LOCAL-PC').strip()
        channel = str(event_data.get('service') or 'System').strip()
        log_id = str(event_data.get('log_id') or event_data.get('id') or event_data.get('timestamp') or '').strip()
        return f"{computer}:{channel}:{log_id}"

    def send_alert_async(self, event_data):
        """Dispatches email alert in a background thread to prevent blocking main execution."""
        alert_id = self._generate_alert_id(event_data)
        with self.lock:
            if alert_id in self.sent_alert_ids:
                logger.info(f"Duplicate alert skipped for ID: {alert_id}")
                return False
            self.sent_alert_ids.add(alert_id)

        thread = threading.Thread(
            target=self._send_email_worker,
            args=(event_data,),
            daemon=True
        )
        thread.start()
        return True

    def _send_email_worker(self, event_data):
        cfg = self.get_smtp_config()
        if not self.is_configured():
            logger.warning("Email Alert: FAILED - SMTP configuration incomplete or missing in environment variables.")
            return False

        try:
            computer_name = event_data.get('hostname') or socket.gethostname()
            subject_prefix = f"[SMART-LOG ALERT] Anomaly Detected on {computer_name}"

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject_prefix
            msg["From"] = cfg['username']
            msg["To"] = cfg['to_email']

            local_ip = "127.0.0.1"
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                local_ip = "127.0.0.1"

            timestamp = event_data.get('timestamp', 'N/A')
            channel = event_data.get('service', 'System')
            event_id = event_data.get('event_type', 'SYSTEM_EVENT')
            provider = event_data.get('service', 'Windows Event Log')
            severity = event_data.get('severity', 'High')
            what_happened = event_data.get('what_happened') or event_data.get('message') or 'Suspicious system log activity recorded.'
            why_suspicious = event_data.get('why_suspicious') or event_data.get('natural_explanation') or 'Behavioral anomaly detected by Isolation Forest model.'
            recommended_action = event_data.get('recommended_action') or 'Investigate event origin and verify authorization.'

            top_reasons = event_data.get('top_3_human_reasons') or []
            if isinstance(top_reasons, str):
                import json
                try:
                    top_reasons = json.loads(top_reasons)
                except Exception:
                    top_reasons = [top_reasons]

            shap_text = ""
            if top_reasons:
                for idx, reason in enumerate(top_reasons[:3], 1):
                    shap_text += f"{idx}. {reason}\n"
            else:
                shap_text = "1. Event frequency or error sequence length deviated from baseline.\n"

            # Plain text body
            text_body = f"""SMART-LOG SECURITY ALERT

Computer:
{computer_name}

IP Address:
{local_ip}

Time:
{timestamp}

Log Channel:
{channel}

Event ID:
{event_id}

Provider:
{provider}

Severity:
{severity}

What happened:
{what_happened}

Why it was detected:
{why_suspicious}

Top SHAP contributors:
{shap_text}
Recommended action:
{recommended_action}
"""

            msg.attach(MIMEText(text_body, "plain"))

            # HTML formatted body
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background-color: #050816; color: #ffffff; padding: 20px;">
              <div style="max-width: 600px; margin: auto; background-color: #081225; border: 1px solid #EF4444; border-radius: 12px; padding: 24px;">
                <h2 style="color: #EF4444; margin-top: 0;">🚨 SMART-LOG SECURITY ALERT</h2>
                <hr style="border: 0; border-top: 1px solid #1E293B;" />
                <table style="width: 100%; font-size: 13px; color: #CBD5E1; border-collapse: collapse;">
                  <tr><td style="padding: 6px 0; color: #94A3B8;">Computer:</td><td style="font-weight: bold; color: #FFFFFF;">{computer_name}</td></tr>
                  <tr><td style="padding: 6px 0; color: #94A3B8;">IP Address:</td><td style="color: #00E5FF;">{local_ip}</td></tr>
                  <tr><td style="padding: 6px 0; color: #94A3B8;">Time:</td><td>{timestamp}</td></tr>
                  <tr><td style="padding: 6px 0; color: #94A3B8;">Log Channel:</td><td style="color: #C084FC;">{channel}</td></tr>
                  <tr><td style="padding: 6px 0; color: #94A3B8;">Event ID:</td><td>{event_id}</td></tr>
                  <tr><td style="padding: 6px 0; color: #94A3B8;">Severity:</td><td style="color: #EF4444; font-weight: bold;">{severity}</td></tr>
                </table>
                <div style="margin-top: 16px; padding: 12px; background-color: #050816; border-left: 4px solid #EF4444; border-radius: 6px;">
                  <strong style="color: #F87171;">What happened:</strong>
                  <p style="margin: 4px 0 0 0; font-size: 12px; color: #E2E8F0;">{what_happened}</p>
                </div>
                <div style="margin-top: 12px; padding: 12px; background-color: #050816; border-left: 4px solid #F59E0B; border-radius: 6px;">
                  <strong style="color: #FBBF24;">Why it was detected:</strong>
                  <p style="margin: 4px 0 0 0; font-size: 12px; color: #E2E8F0;">{why_suspicious}</p>
                </div>
                <div style="margin-top: 12px; padding: 12px; background-color: #050816; border-left: 4px solid #00E5FF; border-radius: 6px;">
                  <strong style="color: #38BDF8;">Top SHAP Contributors:</strong>
                  <pre style="margin: 4px 0 0 0; font-size: 11px; color: #CBD5E1; font-family: monospace; white-space: pre-wrap;">{shap_text}</pre>
                </div>
                <div style="margin-top: 12px; padding: 12px; background-color: #050816; border-left: 4px solid #10B981; border-radius: 6px;">
                  <strong style="color: #34D399;">Recommended Action:</strong>
                  <p style="margin: 4px 0 0 0; font-size: 12px; color: #E2E8F0;">{recommended_action}</p>
                </div>
              </div>
            </body>
            </html>
            """
            msg.attach(MIMEText(html_body, "html"))

            # Connect to SMTP server
            server = smtplib.SMTP(cfg['host'], cfg['port'], timeout=10)
            server.ehlo()
            server.starttls()
            server.login(cfg['username'], cfg['password'])
            server.sendmail(cfg['username'], [cfg['to_email']], msg.as_string())
            server.quit()

            logger.info(f"Email Alert: SUCCESS - Sent anomaly alert for {computer_name} ({alert_id})")
            return True

        except Exception as e:
            logger.error(f"Email Alert: FAILED - {str(e)}")
            return False

# Global Singleton Instance
email_alert_manager = EmailAlertManager()
