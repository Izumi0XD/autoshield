"""
AutoShield — Webhook / SIEM Integration Manager
Fires real-time alerts to:
  - Splunk HEC (HTTP Event Collector)
  - IBM QRadar
  - Elastic SIEM / Logstash
  - Slack
  - Microsoft Teams
  - PagerDuty
  - Generic webhook (SIEM, custom)
  - Telegram

All fire async in background threads. Failure is logged and retried (3 attempts).
HMAC-SHA256 signing on request body when secret is set.
"""

import hmac
import hashlib
import json
import logging
import threading
import time
import os
from datetime import datetime
from typing import Optional
from urllib.request import urlopen, Request as URLRequest
from urllib.error   import URLError, HTTPError

log = logging.getLogger("AutoShield.Webhooks")

MAX_RETRIES    = 3
RETRY_BACKOFF  = [1, 3, 10]   # seconds
REQUEST_TIMEOUT= 5


# ─── Payload builders ─────────────────────────────────────────────────────────

def _build_splunk_hec(event: dict, index: str = "autoshield") -> dict:
    """Splunk HEC format."""
    return {
        "time":       _ts_to_epoch(event.get("timestamp","")),
        "index":      index,
        "sourcetype": "autoshield:attack",
        "source":     "autoshield",
        "event": {
            "attack_type": event.get("attack_type"),
            "severity":    event.get("severity"),
            "src_ip":      event.get("src_ip"),
            "action":      event.get("action"),
            "confidence":  event.get("confidence"),
            "cve":         event.get("cve_hints",[""])[0],
            "payload":     event.get("payload_snip","")[:200],
            "timestamp":   event.get("timestamp"),
        }
    }


def _build_elastic(event: dict) -> dict:
    """Elastic Common Schema (ECS) format for SIEM."""
    return {
        "@timestamp":        event.get("timestamp", datetime.now().isoformat()),
        "event.kind":        "alert",
        "event.category":    ["intrusion_detection"],
        "event.type":        ["denied" if event.get("action")=="BLOCKED" else "info"],
        "event.severity":    _sev_to_int(event.get("severity","HIGH")),
        "event.module":      "autoshield",
        "event.dataset":     "autoshield.attack",
        "threat.technique.id": event.get("cve_hints",[""])[0],
        "source.ip":         event.get("src_ip"),
        "destination.ip":    event.get("dst_ip"),
        "rule.name":         event.get("attack_type"),
        "rule.description":  f"{event.get('attack_type')} attack detected",
        "message":           f"[AutoShield] {event.get('severity')} {event.get('attack_type')} from {event.get('src_ip')}",
        "autoshield": {
            "confidence":    event.get("confidence"),
            "payload_snip":  event.get("payload_snip","")[:200],
            "action":        event.get("action"),
        }
    }


def _build_qradar(event: dict) -> dict:
    """IBM QRadar LEEF/JSON format."""
    return {
        "deviceVendor":   "AutoShield",
        "deviceProduct":  "AutoShield AI",
        "deviceVersion":  "2.0",
        "deviceEventClassId": event.get("attack_type","ATTACK"),
        "name":           f"{event.get('attack_type')} Attack Detected",
        "severity":       _sev_to_int(event.get("severity","HIGH")),
        "src":            event.get("src_ip"),
        "dst":            event.get("dst_ip"),
        "outcome":        event.get("action","DETECTED"),
        "msg":            event.get("payload_snip","")[:200],
        "startTime":      event.get("timestamp",""),
        "cve":            ",".join(event.get("cve_hints",[])),
        "confidence":     event.get("confidence",0),
    }


def _build_cef(event: dict) -> str:
    """CEF (ArcSight) syslog format — returned as string."""
    sev = {"CRITICAL":10,"HIGH":8,"MEDIUM":5,"LOW":2}.get(event.get("severity","HIGH"),5)
    ext = (
        f"src={event.get('src_ip')} "
        f"dst={event.get('dst_ip','-')} "
        f"act={event.get('action','DETECTED')} "
        f"msg={event.get('payload_snip','')[:100].replace('=','\\=')} "
        f"cs1={event.get('attack_type')} cs1Label=AttackType "
        f"cs2={event.get('cve_hints',[''])[0]} cs2Label=CVE "
        f"cn1={event.get('confidence',0)} cn1Label=Confidence"
    )
    return (f"CEF:0|AutoShield|AutoShield AI|2.0|{event.get('attack_type','ATTACK')}|"
            f"{event.get('attack_type')} attack detected|{sev}|{ext}")


def _build_slack(event: dict) -> dict:
    """Slack Block Kit message."""
    sev   = event.get("severity","HIGH")
    atype = event.get("attack_type","?")
    src   = event.get("src_ip","?")
    action= event.get("action","DETECTED")
    cve   = event.get("cve_hints",["?"])[0]
    colors = {"CRITICAL":"#ff3d57","HIGH":"#ff6b35","MEDIUM":"#ffd60a","LOW":"#00e676"}
    return {
        "text": f":shield: AutoShield Alert: {sev} {atype} from {src}",
        "attachments": [{
            "color": colors.get(sev,"#ff3d57"),
            "blocks": [
                {
                    "type": "header",
                    "text": {"type":"plain_text","text": f"🚨 {sev} Attack Detected"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type":"mrkdwn","text":f"*Attack Type*\n{atype}"},
                        {"type":"mrkdwn","text":f"*Severity*\n{sev}"},
                        {"type":"mrkdwn","text":f"*Source IP*\n`{src}`"},
                        {"type":"mrkdwn","text":f"*Action*\n{action}"},
                        {"type":"mrkdwn","text":f"*CVE Match*\n{cve}"},
                        {"type":"mrkdwn","text":f"*Confidence*\n{event.get('confidence',0)}%"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type":"mrkdwn","text": f"*Payload snippet:*\n```{event.get('payload_snip','')[:120]}```"}
                },
                {
                    "type": "context",
                    "elements": [
                        {"type":"mrkdwn","text": f"AutoShield AI | {event.get('timestamp','')[:19]}"}
                    ]
                }
            ]
        }]
    }


def _build_teams(event: dict) -> dict:
    """Microsoft Teams Adaptive Card."""
    sev   = event.get("severity","HIGH")
    colors = {"CRITICAL":"attention","HIGH":"warning","MEDIUM":"accent","LOW":"good"}
    return {
        "type":        "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema":  "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":     "AdaptiveCard",
                "version":  "1.4",
                "body": [
                    {
                        "type":   "TextBlock",
                        "text":   f"🛡️ AutoShield Alert — {sev} {event.get('attack_type')}",
                        "weight": "bolder",
                        "size":   "medium",
                        "color":  colors.get(sev,"attention"),
                    },
                    {
                        "type":    "FactSet",
                        "facts": [
                            {"title":"Attack",    "value": event.get("attack_type")},
                            {"title":"Severity",  "value": sev},
                            {"title":"Source IP", "value": event.get("src_ip")},
                            {"title":"Action",    "value": event.get("action")},
                            {"title":"CVE",       "value": event.get("cve_hints",["?"])[0]},
                            {"title":"Confidence","value": f"{event.get('confidence',0)}%"},
                        ]
                    },
                    {
                        "type": "TextBlock",
                        "text": f"Payload: `{event.get('payload_snip','')[:100]}`",
                        "wrap": True,
                        "size": "small",
                    }
                ]
            }
        }]
    }


def _build_pagerduty(event: dict, routing_key: str) -> dict:
    """PagerDuty Events API v2."""
    sev_map = {"CRITICAL":"critical","HIGH":"error","MEDIUM":"warning","LOW":"info"}
    return {
        "routing_key":  routing_key,
        "event_action": "trigger",
        "dedup_key":    f"autoshield_{event.get('src_ip','')}_{event.get('attack_type','')}",
        "payload": {
            "summary":   f"[AutoShield] {event.get('severity')} {event.get('attack_type')} from {event.get('src_ip')}",
            "source":    event.get("src_ip","unknown"),
            "severity":  sev_map.get(event.get("severity","HIGH"),"error"),
            "timestamp": event.get("timestamp",""),
            "custom_details": {
                "attack_type": event.get("attack_type"),
                "cve":         event.get("cve_hints",[""])[0],
                "confidence":  event.get("confidence",0),
                "payload":     event.get("payload_snip","")[:200],
                "action":      event.get("action"),
            }
        }
    }


def _build_telegram(event: dict, chat_id: str) -> dict:
    """Telegram Bot API sendMessage."""
    sev  = event.get("severity","HIGH")
    emoji= {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(sev,"⚠️")
    text = (
        f"{emoji} *AutoShield Alert*\n\n"
        f"*Attack:* `{event.get('attack_type')}`\n"
        f"*Severity:* `{sev}`\n"
        f"*Source:* `{event.get('src_ip')}`\n"
        f"*Action:* `{event.get('action')}`\n"
        f"*CVE:* `{event.get('cve_hints',['?'])[0]}`\n"
        f"*Confidence:* `{event.get('confidence',0)}%`\n\n"
        f"```{event.get('payload_snip','')[:100]}```"
    )
    return {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}


# ─── HTTP sender ──────────────────────────────────────────────────────────────

def _send_http(url: str, payload, headers: dict = None,
               secret: str = None, retries: int = MAX_RETRIES) -> bool:
    """Send webhook payload. Returns True on success."""
    if isinstance(payload, dict):
        body = json.dumps(payload).encode()
        content_type = "application/json"
    elif isinstance(payload, str):
        body = payload.encode()
        content_type = "text/plain"
    else:
        body = payload
        content_type = "application/octet-stream"

    hdrs = {"Content-Type": content_type, "User-Agent": "AutoShield/2.0"}
    if headers: hdrs.update(headers)

    # HMAC signing
    if secret:
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        hdrs["X-AutoShield-Signature"] = f"sha256={sig}"

    for attempt in range(retries):
        try:
            req  = URLRequest(url, data=body, headers=hdrs, method="POST")
            resp = urlopen(req, timeout=REQUEST_TIMEOUT)
            if 200 <= resp.status < 300:
                return True
            log.warning(f"Webhook {url} returned {resp.status}")
        except HTTPError as e:
            log.error(f"Webhook HTTP error {url}: {e.code} {e.reason}")
        except URLError as e:
            log.error(f"Webhook URL error {url}: {e.reason}")
        except Exception as e:
            log.error(f"Webhook error {url}: {e}")

        if attempt < retries - 1:
            time.sleep(RETRY_BACKOFF[attempt])

    return False


# ─── Webhook Manager ──────────────────────────────────────────────────────────

class WebhookManager:
    def __init__(self):
        self._pool = threading.BoundedSemaphore(20)    # max 20 concurrent fires

    def fire(self, webhook: dict, event: dict) -> bool:
        """Synchronous fire. Returns success."""
        url    = webhook.get("url","")
        secret = webhook.get("secret")
        name   = webhook.get("name","webhook")

        try:
            payload, extra_headers = self._build_payload(webhook, event)
        except Exception as e:
            log.error(f"Payload build error for {name}: {e}")
            return False

        return _send_http(url, payload, extra_headers, secret)

    def fire_async(self, webhook: dict, event: dict,
                   callback=None):
        """Non-blocking fire in background thread."""
        def _run():
            with self._pool:
                success = self.fire(webhook, event)
                if callback: callback(webhook.get("id"), success)
        threading.Thread(target=_run, daemon=True).start()

    def _build_payload(self, webhook: dict, event: dict):
        """Detect webhook type from URL and build appropriate payload."""
        url     = webhook.get("url","").lower()
        name    = webhook.get("name","").lower()
        headers = {}

        # Splunk HEC
        if "splunk" in url or "hec" in name:
            token = webhook.get("secret","")
            headers["Authorization"] = f"Splunk {token}"
            return _build_splunk_hec(event), headers

        # Elastic
        if "elastic" in url or "logstash" in url or "elasticsearch" in url:
            return _build_elastic(event), headers

        # QRadar
        if "qradar" in url or "ibm" in name:
            return _build_qradar(event), headers

        # Slack
        if "slack.com" in url or "hooks.slack" in url:
            return _build_slack(event), headers

        # Teams
        if "teams.microsoft" in url or "outlook.office" in url:
            return _build_teams(event), headers

        # PagerDuty
        if "pagerduty" in url:
            rk = webhook.get("secret","")
            return _build_pagerduty(event, rk), headers

        # Telegram
        if "telegram" in url or "t.me" in url:
            # URL format: https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={CHAT_ID}
            # Extract chat_id from URL or use secret
            chat_id = webhook.get("secret","-100000")
            bot_token = url.split("/bot")[-1].split("/")[0] if "/bot" in url else ""
            final_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload   = _build_telegram(event, chat_id)
            # Override URL for Telegram
            return payload, {"_override_url": final_url}

        # CEF/syslog
        if "syslog" in name or "cef" in name or "arcsight" in name:
            return _build_cef(event), {"Content-Type": "text/plain"}

        # Generic JSON webhook (default)
        return {
            "source":      "autoshield",
            "timestamp":   event.get("timestamp",""),
            "attack_type": event.get("attack_type"),
            "severity":    event.get("severity"),
            "src_ip":      event.get("src_ip"),
            "action":      event.get("action"),
            "confidence":  event.get("confidence"),
            "cve":         event.get("cve_hints",[""])[0],
            "payload":     event.get("payload_snip","")[:200],
        }, headers

    def fire_all(self, event: dict, webhooks: list, severity_filter: list = None):
        """Fire all configured webhooks for an event, filtered by severity."""
        sev = event.get("severity","")
        for wh in webhooks:
            if not wh.get("enabled", True): continue
            wh_events = wh.get("events", ["CRITICAL","HIGH"])
            if severity_filter and sev not in severity_filter: continue
            if sev not in wh_events: continue
            self.fire_async(wh, event)


# ─── Environment-based config (zero-config for common services) ───────────────

def get_env_webhooks() -> list[dict]:
    """
    Auto-configure webhooks from environment variables.
    Operators just set env vars — no dashboard config needed.
    """
    webhooks = []

    if os.environ.get("SLACK_WEBHOOK_URL"):
        webhooks.append({
            "id":      "env_slack",
            "name":    "Slack (env)",
            "url":     os.environ["SLACK_WEBHOOK_URL"],
            "events":  ["CRITICAL","HIGH"],
            "enabled": True,
        })

    if os.environ.get("TEAMS_WEBHOOK_URL"):
        webhooks.append({
            "id":      "env_teams",
            "name":    "Teams (env)",
            "url":     os.environ["TEAMS_WEBHOOK_URL"],
            "events":  ["CRITICAL","HIGH"],
            "enabled": True,
        })

    if os.environ.get("PAGERDUTY_ROUTING_KEY"):
        webhooks.append({
            "id":      "env_pd",
            "name":    "PagerDuty (env)",
            "url":     "https://events.pagerduty.com/v2/enqueue",
            "secret":  os.environ["PAGERDUTY_ROUTING_KEY"],
            "events":  ["CRITICAL"],
            "enabled": True,
        })

    if os.environ.get("SPLUNK_HEC_URL"):
        webhooks.append({
            "id":      "env_splunk",
            "name":    "Splunk HEC (env)",
            "url":     os.environ["SPLUNK_HEC_URL"],
            "secret":  os.environ.get("SPLUNK_HEC_TOKEN",""),
            "events":  ["CRITICAL","HIGH","MEDIUM"],
            "enabled": True,
        })

    if os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
        webhooks.append({
            "id":      "env_telegram",
            "name":    "Telegram (env)",
            "url":     f"https://api.telegram.org/bot{os.environ['TELEGRAM_BOT_TOKEN']}/sendMessage",
            "secret":  os.environ["TELEGRAM_CHAT_ID"],
            "events":  ["CRITICAL","HIGH"],
            "enabled": True,
        })

    if os.environ.get("ELASTIC_WEBHOOK_URL"):
        webhooks.append({
            "id":      "env_elastic",
            "name":    "Elastic SIEM (env)",
            "url":     os.environ["ELASTIC_WEBHOOK_URL"],
            "events":  ["CRITICAL","HIGH","MEDIUM","LOW"],
            "enabled": True,
        })

    return webhooks


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ts_to_epoch(ts: str) -> float:
    try: return datetime.fromisoformat(ts).timestamp()
    except Exception: return time.time()

def _sev_to_int(sev: str) -> int:
    return {"CRITICAL":100,"HIGH":75,"MEDIUM":50,"LOW":25}.get(sev,50)


# ─── Singleton ────────────────────────────────────────────────────────────────

_manager: Optional[WebhookManager] = None

def get_webhook_manager() -> WebhookManager:
    global _manager
    if _manager is None:
        _manager = WebhookManager()
    return _manager


# ─── Quick test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mgr = WebhookManager()
    test_event = {
        "timestamp":   datetime.now().isoformat(),
        "src_ip":      "192.168.1.100",
        "dst_ip":      "10.0.0.1",
        "attack_type": "SQLi",
        "severity":    "CRITICAL",
        "action":      "BLOCKED",
        "confidence":  75,
        "cve_hints":   ["CVE-2023-23752"],
        "payload_snip": "GET /login?user=' OR 1=1-- HTTP/1.1",
    }
    # Test payload builders
    print("=== Slack payload ===")
    print(json.dumps(_build_slack(test_event), indent=2)[:500])
    print("\n=== Elastic ECS payload ===")
    print(json.dumps(_build_elastic(test_event), indent=2)[:500])
    print("\n=== CEF payload ===")
    print(_build_cef(test_event))
    print("\n=== Env webhooks ===")
    for wh in get_env_webhooks():
        print(f"  {wh['name']}: {wh['url'][:50]}")