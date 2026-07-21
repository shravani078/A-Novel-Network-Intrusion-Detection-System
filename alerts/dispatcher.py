"""
alerts/dispatcher.py
====================
Sends automated alerts via:
  • Email  — plain SMTP (works with Gmail, Outlook, any SMTP server)
  • SMS    — Twilio API (optional; silently skipped if not configured)

Fired when a detected attack has risk >= 70 (HIGH or above).
Includes attack type, timestamp, risk score, and remediation link.
"""

import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from datetime             import datetime


# How long to wait before re-alerting for the same attack type (seconds)
COOLDOWN_SECONDS = 300  # 5 minutes


class AlertDispatcher:
    """
    Thread-safe alert dispatcher with cooldown to prevent alert storms.

    Parameters
    ----------
    smtp_host     : SMTP server host (e.g. "smtp.gmail.com")
    smtp_port     : SMTP port (587 for TLS, 465 for SSL)
    smtp_user     : Your email address (sender)
    smtp_password : App password (Gmail: use App Passwords, not your real password)
    alert_email   : Destination email for security alerts
    twilio_sid    : Twilio Account SID (leave empty to disable SMS)
    twilio_token  : Twilio Auth Token
    twilio_from   : Twilio phone number (format: "+1XXXXXXXXXX")
    alert_phone   : Destination phone number for SMS
    dashboard_url : URL shown in alert body (e.g. "https://yourcompany.shieldai.com")
    """

    def __init__(
        self,
        smtp_host:     str = "smtp.gmail.com",
        smtp_port:     int = 587,
        smtp_user:     str = "",
        smtp_password: str = "",
        alert_email:   str = "",
        twilio_sid:    str = "",
        twilio_token:  str = "",
        twilio_from:   str = "",
        alert_phone:   str = "",
        dashboard_url: str = "http://localhost:5000",
    ):
        self.smtp_host     = smtp_host
        self.smtp_port     = smtp_port
        self.smtp_user     = smtp_user
        self.smtp_password = smtp_password
        self.alert_email   = alert_email
        self.twilio_sid    = twilio_sid
        self.twilio_token  = twilio_token
        self.twilio_from   = twilio_from
        self.alert_phone   = alert_phone
        self.dashboard_url = dashboard_url

        # Cooldown tracker: attack_type -> last_alerted_timestamp
        self._cooldowns: dict[str, float] = {}
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────

    def dispatch(self, result: dict) -> None:
        """
        Fire email + SMS alerts for a detection result in a background thread.
        Respects cooldown — same attack type won't re-alert for COOLDOWN_SECONDS.

        Parameters
        ----------
        result : dict with keys: attack, risk, risk_label, confidence,
                 anomaly_score, timestamp
        """
        attack = result.get("attack", "UNKNOWN")

        # Check cooldown
        import time
        with self._lock:
            last = self._cooldowns.get(attack, 0)
            if time.time() - last < COOLDOWN_SECONDS:
                return  # Still in cooldown — skip
            self._cooldowns[attack] = time.time()

        # Fire in background so it doesn't block the prediction pipeline
        t = threading.Thread(
            target=self._send_all,
            args=(result,),
            daemon=True,
        )
        t.start()

    # ── Internal ──────────────────────────────────────────────────

    def _send_all(self, result: dict) -> None:
        """Send email and SMS. Called in a background thread."""
        self._send_email(result)
        self._send_sms(result)

    def _build_email_body(self, result: dict) -> str:
        """Generate an HTML email body for the alert."""
        attack    = result.get("attack",      "UNKNOWN")
        risk      = result.get("risk",        0)
        risk_lbl  = result.get("risk_label",  "Unknown")
        conf      = result.get("confidence",  0)
        ts        = result.get("timestamp",   datetime.now().strftime("%H:%M:%S"))
        anomaly   = result.get("anomaly_score", 0)

        color_map = {
            "Critical":       "#dc2626",
            "High":           "#f97316",
            "Medium":         "#eab308",
            "Unknown Threat": "#f97316",
            "Safe":           "#22c55e",
        }
        color = color_map.get(risk_lbl, "#ef4444")

        return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 0">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.08)">
      <!-- Header -->
      <tr>
        <td style="background:#040d1a;padding:24px 32px;text-align:center">
          <p style="color:#00d4ff;font-size:24px;font-weight:bold;margin:0">🛡️ ShieldAI</p>
          <p style="color:#94a3b8;font-size:13px;margin:6px 0 0">Enterprise Intrusion Detection System</p>
        </td>
      </tr>
      <!-- Alert banner -->
      <tr>
        <td style="background:{color};padding:16px 32px;text-align:center">
          <p style="color:#fff;font-size:22px;font-weight:bold;margin:0">
            ⚠️ {risk_lbl.upper()} THREAT DETECTED
          </p>
          <p style="color:rgba(255,255,255,0.85);font-size:14px;margin:6px 0 0">
            Detected at {ts}
          </p>
        </td>
      </tr>
      <!-- Details -->
      <tr>
        <td style="padding:32px">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="padding:8px 0;border-bottom:1px solid #e2e8f0">
                <span style="color:#64748b;font-size:13px">Attack Type</span><br>
                <span style="color:#1e293b;font-size:18px;font-weight:bold">{attack}</span>
              </td>
            </tr>
            <tr>
              <td style="padding:8px 0;border-bottom:1px solid #e2e8f0">
                <span style="color:#64748b;font-size:13px">Risk Score</span><br>
                <span style="color:{color};font-size:18px;font-weight:bold">{risk}/100</span>
              </td>
            </tr>
            <tr>
              <td style="padding:8px 0;border-bottom:1px solid #e2e8f0">
                <span style="color:#64748b;font-size:13px">AI Confidence</span><br>
                <span style="color:#1e293b;font-size:18px;font-weight:bold">{conf}%</span>
              </td>
            </tr>
            <tr>
              <td style="padding:8px 0">
                <span style="color:#64748b;font-size:13px">Anomaly Score</span><br>
                <span style="color:#1e293b;font-size:16px;font-family:monospace">{anomaly}</span>
              </td>
            </tr>
          </table>

          <div style="margin-top:24px;text-align:center">
            <a href="{self.dashboard_url}" 
               style="background:#040d1a;color:#00d4ff;padding:14px 32px;text-decoration:none;border-radius:8px;font-size:14px;font-weight:bold;display:inline-block">
              View Full Analysis &amp; Remediation →
            </a>
          </div>
        </td>
      </tr>
      <!-- Footer -->
      <tr>
        <td style="background:#f8fafc;padding:16px 32px;text-align:center;border-top:1px solid #e2e8f0">
          <p style="color:#94a3b8;font-size:12px;margin:0">
            ShieldAI IDS · Automated security alert · Do not reply to this email
          </p>
        </td>
      </tr>
    </table>
  </td></tr>
</table>
</body>
</html>
"""

    def _send_email(self, result: dict) -> None:
        """Send alert email via SMTP."""
        if not self.smtp_user or not self.alert_email:
            print("ℹ️  Email alert skipped (SMTP not configured)")
            return

        attack   = result.get("attack", "UNKNOWN")
        risk_lbl = result.get("risk_label", "Unknown")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 ShieldAI Alert: {risk_lbl} Threat — {attack}"
        msg["From"]    = f"ShieldAI IDS <{self.smtp_user}>"
        msg["To"]      = self.alert_email

        # Plain text fallback
        plain = (
            f"ShieldAI Security Alert\n\n"
            f"Attack: {attack}\n"
            f"Risk: {result.get('risk', 0)}/100 ({risk_lbl})\n"
            f"Confidence: {result.get('confidence', 0)}%\n"
            f"Timestamp: {result.get('timestamp', '')}\n\n"
            f"View full analysis: {self.dashboard_url}\n"
        )
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(self._build_email_body(result), "html"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.smtp_user, self.alert_email, msg.as_string())
            print(f"✅ Email alert sent → {self.alert_email} [{attack}]")
        except Exception as e:
            print(f"❌ Email alert failed: {e}")

    def _send_sms(self, result: dict) -> None:
        """Send SMS alert via Twilio (optional — skipped if not configured)."""
        if not all([self.twilio_sid, self.twilio_token, self.twilio_from, self.alert_phone]):
            print("ℹ️  SMS alert skipped (Twilio not configured)")
            return

        attack   = result.get("attack", "UNKNOWN")
        risk     = result.get("risk", 0)
        risk_lbl = result.get("risk_label", "Unknown")
        conf     = result.get("confidence", 0)

        body = (
            f"🚨 ShieldAI ALERT\n"
            f"Attack: {attack}\n"
            f"Risk: {risk}/100 ({risk_lbl})\n"
            f"Confidence: {conf}%\n"
            f"Dashboard: {self.dashboard_url}"
        )

        try:
            from twilio.rest import Client
            client = Client(self.twilio_sid, self.twilio_token)
            client.messages.create(
                body=body,
                from_=self.twilio_from,
                to=self.alert_phone,
            )
            print(f"✅ SMS alert sent → {self.alert_phone} [{attack}]")
        except ImportError:
            print("ℹ️  Twilio not installed. Run: pip install twilio")
        except Exception as e:
            print(f"❌ SMS alert failed: {e}")
