"""
AutoShield - Alert System
WhatsApp via Twilio + Email via SMTP for CRITICAL attack notifications.
Zero cost: Twilio free trial (WhatsApp sandbox) + Gmail SMTP (free).
"""

import smtplib
import logging
import os
import time
import threading
from datetime import datetime
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger("AutoShield.Alerts")

# ─── Config — set via env vars or pass directly ───────────────────────────────
# WhatsApp (Twilio)
TWILIO_SID          = os.getenv("TWILIO_SID",   "")
TWILIO_AUTH_TOKEN   = os.getenv("TWILIO_TOKEN",  "")
TWILIO_FROM_WHATSAPP= os.getenv("TWILIO_FROM",   "whatsapp:+14155238886")  # sandbox number
ALERT_WHATSAPP_TO   = os.getenv("ALERT_WA_TO",   "")   # whatsapp:+91XXXXXXXXXX

# Email (Gmail SMTP)
SMTP_HOST           = os.getenv("SMTP_HOST",     "smtp.gmail.com")
SMTP_PORT           = int(os.getenv("SMTP_PORT",  "587"))
SMTP_USER           = os.getenv("SMTP_USER",      "")   # your@gmail.com
SMTP_PASS           = os.getenv("SMTP_PASS",      "")   # App Password (not account password)
ALERT_EMAIL_TO      = os.getenv("ALERT_EMAIL_TO", "")   # recipient

# Alert throttle — one alert per IP per N seconds
ALERT_COOLDOWN = 120   # seconds

# ─── Throttle tracker ─────────────────────────────────────────────────────────
_last_alerted: dict[str, float] = {}
_alert_lock = threading.Lock()


def _throttled(ip: str) -> bool:
    """Return True if this IP was alerted recently."""
    with _alert_lock:
        last = _last_alerted.get(ip, 0)
        if time.time() - last < ALERT_COOLDOWN:
            return True
        _last_alerted[ip] = time.time()
        return False


# ─── Message builders ─────────────────────────────────────────────────────────

def _build_whatsapp_msg(event: dict) -> str:
    cve = event.get("cve_hints", ["?"])[0]
    return (
        f"🚨 *AutoShield ALERT*\n\n"
        f"*Attack:* {event.get('attack_type')} [{event.get('severity')}]\n"
        f"*Source IP:* {event.get('src_ip')}\n"
        f"*Action:* {event.get('action','PENDING')}\n"
        f"*CVE Match:* {cve}\n"
        f"*Confidence:* {event.get('confidence',0)}%\n"
        f"*Time:* {event.get('timestamp','')[-19:-3]}\n\n"
        f"AutoShield has auto-blocked the attacker. Check dashboard for details."
    )


def _build_email_html(event: dict) -> str:
    cve      = event.get("cve_hints", ["?"])[0]
    sev      = event.get("severity","?")
    sev_color= {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308"}.get(sev,"#ef4444")

    return f"""
    <html><body style="font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px;">
      <div style="max-width:600px;margin:0 auto;">
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;">
          <h2 style="color:{sev_color};margin:0 0 16px">🚨 AutoShield Security Alert</h2>
          <table style="width:100%;border-collapse:collapse;">
            <tr style="border-bottom:1px solid #30363d">
              <td style="color:#8b949e;padding:8px 0">Attack Type</td>
              <td style="color:{sev_color};font-weight:700">{event.get('attack_type')}</td>
            </tr>
            <tr style="border-bottom:1px solid #30363d">
              <td style="color:#8b949e;padding:8px 0">Severity</td>
              <td style="color:{sev_color};font-weight:700">{sev}</td>
            </tr>
            <tr style="border-bottom:1px solid #30363d">
              <td style="color:#8b949e;padding:8px 0">Source IP</td>
              <td style="color:#e6edf3;font-family:monospace">{event.get('src_ip')}</td>
            </tr>
            <tr style="border-bottom:1px solid #30363d">
              <td style="color:#8b949e;padding:8px 0">Action Taken</td>
              <td style="color:#22c55e;font-weight:700">{event.get('action','PENDING')}</td>
            </tr>
            <tr style="border-bottom:1px solid #30363d">
              <td style="color:#8b949e;padding:8px 0">CVE Match</td>
              <td style="color:#f87171">{cve}</td>
            </tr>
            <tr style="border-bottom:1px solid #30363d">
              <td style="color:#8b949e;padding:8px 0">Confidence</td>
              <td style="color:#e6edf3">{event.get('confidence',0)}%</td>
            </tr>
            <tr>
              <td style="color:#8b949e;padding:8px 0">Timestamp</td>
              <td style="color:#e6edf3">{event.get('timestamp','')[:19]}</td>
            </tr>
          </table>
          <div style="margin-top:16px;background:#1c1407;border:1px solid #f97316;
                      border-radius:6px;padding:12px;font-size:13px;color:#8b949e;">
            <b style="color:#f97316">Payload snippet:</b><br/>
            <code style="color:#e6edf3">{event.get('payload_snip','')[:100]}</code>
          </div>
          <div style="margin-top:16px;font-size:12px;color:#8b949e;">
            AutoShield AI has automatically blocked the attacker IP via iptables.
            Check the dashboard for full incident details and CVE intelligence.
          </div>
        </div>
        <div style="text-align:center;margin-top:12px;font-size:11px;color:#8b949e;">
          AutoShield AI — Real-Time Attack Detection &amp; Auto-Defense
        </div>
      </div>
    </body></html>
    """


# ─── Senders ──────────────────────────────────────────────────────────────────

def send_whatsapp(event: dict) -> dict:
    """Send WhatsApp alert via Twilio. Returns status dict."""
    if not TWILIO_SID or not TWILIO_AUTH_TOKEN or not ALERT_WHATSAPP_TO:
        return {"status": "SKIPPED", "reason": "Twilio credentials not configured"}

    try:
        from twilio.rest import Client
        client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
        msg = client.messages.create(
            from_=TWILIO_FROM_WHATSAPP,
            body=_build_whatsapp_msg(event),
            to=ALERT_WHATSAPP_TO,
        )
        log.info(f"WhatsApp alert sent: SID={msg.sid}")
        return {"status": "SENT", "sid": msg.sid, "channel": "whatsapp"}
    except ImportError:
        return {"status": "FAILED", "reason": "twilio package not installed (pip install twilio)"}
    except Exception as e:
        log.error(f"WhatsApp send failed: {e}")
        return {"status": "FAILED", "reason": str(e)}


def send_email(event: dict) -> dict:
    """Send email alert via SMTP. Returns status dict."""
    if not SMTP_USER or not SMTP_PASS or not ALERT_EMAIL_TO:
        return {"status": "SKIPPED", "reason": "Email credentials not configured"}

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 [AutoShield] {event.get('severity')} {event.get('attack_type')} Attack from {event.get('src_ip')}"
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL_TO

        # Plain text fallback
        plain = (
            f"AutoShield Alert\n"
            f"Attack: {event.get('attack_type')} [{event.get('severity')}]\n"
            f"IP: {event.get('src_ip')}\n"
            f"Action: {event.get('action','?')}\n"
            f"CVE: {event.get('cve_hints',['?'])[0]}\n"
            f"Time: {event.get('timestamp','')[:19]}"
        )
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(_build_email_html(event), "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg.as_string())

        log.info(f"Email alert sent to {ALERT_EMAIL_TO}")
        return {"status": "SENT", "to": ALERT_EMAIL_TO, "channel": "email"}

    except smtplib.SMTPAuthenticationError:
        return {"status": "FAILED", "reason": "SMTP auth failed — check credentials / use App Password"}
    except Exception as e:
        log.error(f"Email send failed: {e}")
        return {"status": "FAILED", "reason": str(e)}


# ─── Main alert dispatcher ────────────────────────────────────────────────────

def fire_alert(event: dict, force: bool = False) -> dict:
    """
    Send all configured alerts for an event.
    Only fires for CRITICAL/HIGH. Throttled per IP.
    force=True bypasses throttle (for testing).
    """
    severity = event.get("severity","LOW")
    ip       = event.get("src_ip","?")

    if severity not in ("CRITICAL","HIGH") and not force:
        return {"status": "SKIPPED", "reason": f"Severity {severity} below threshold"}

    if not force and _throttled(ip):
        return {"status": "THROTTLED", "reason": f"Already alerted for {ip} recently"}

    results = {}

    # Fire both in parallel
    def _wa():  results["whatsapp"] = send_whatsapp(event)
    def _em():  results["email"]    = send_email(event)

    t1 = threading.Thread(target=_wa, daemon=True)
    t2 = threading.Thread(target=_em, daemon=True)
    t1.start(); t2.start()
    t1.join(timeout=10); t2.join(timeout=10)

    log.info(f"Alert fired for {ip}: {results}")
    return {"status": "FIRED", "channels": results}


def test_alerts(test_event: dict | None = None) -> dict:
    """Send a test alert to verify config."""
    if test_event is None:
        test_event = {
            "src_ip":       "192.168.1.1",
            "attack_type":  "SQLi",
            "severity":     "CRITICAL",
            "action":       "BLOCKED",
            "confidence":   75,
            "cve_hints":    ["CVE-2023-23752"],
            "payload_snip": "GET /login?user=' OR 1=1-- HTTP/1.1",
            "timestamp":    datetime.now().isoformat(),
        }
    return fire_alert(test_event, force=True)


def alert_config_status() -> dict:
    """Check what's configured — show in dashboard settings."""
    return {
        "whatsapp": {
            "configured": bool(TWILIO_SID and TWILIO_AUTH_TOKEN and ALERT_WHATSAPP_TO),
            "to": ALERT_WHATSAPP_TO or "not set",
        },
        "email": {
            "configured": bool(SMTP_USER and SMTP_PASS and ALERT_EMAIL_TO),
            "to": ALERT_EMAIL_TO or "not set",
        },
    }


# ─── Self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Alert System Self-Test ===\n")
    print("Config status:", alert_config_status())
    print("\nAttempting test alert (will skip if not configured)...")
    result = test_alerts()
    print("Result:", result)
