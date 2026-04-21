"""
AutoShield — Log Agent (Ultimate Enterprise Edition)
Tails nginx / Apache / Caddy access logs in real time.
Features: 
- Async Threat Scoring & Burst-flood protection
- SQLite state persistence & Auto-expiring blocks
- ipset integration for O(1) firewall scalability
- Sliding-window rate limiting
- Dynamic whitelists & API Observability hooks

Usage:
    sudo python nginx_agent.py --log /var/log/nginx/access.log --api http://localhost:8503 --key as_xxx
"""

import re
import os
import sys
import json
import time
import logging
import sqlite3
import argparse
import threading
import subprocess
import queue
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus
from collections import deque, defaultdict
from typing import Optional

log = logging.getLogger("AutoShield.Agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    log.warning("requests not installed — running in test/detect-only mode")

# ─── Log format parsers ───────────────────────────────────────────────────────
NGINX_COMBINED = re.compile(r"(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<time>[^\]]+)\]\s+" r'"(?P<method>\S+)\s+(?P<path>[^\s"]+)[^"]*"\s+' r"(?P<status>\d+)\s+(?P<bytes>\S+)" r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?')
APACHE_COMMON = re.compile(r"(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<time>[^\]]+)\]\s+" r'"(?P<method>\S+)\s+(?P<path>[^\s"]+)[^"]*"\s+' r"(?P<status>\d+)\s+(?P<bytes>\S+)")
AUTOSHIELD_PIPE = re.compile(r'(?P<ip>[^|]+)\|(?P<time>[^|]+)\|\"(?P<method>\S+)\s+(?P<path>[^\"]+)\"\|(?P<status>\d+)\|(?P<bytes>\d+)')
HAPROXY = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+):\d+\s+.*?\s+(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<path>\S+)")
GENERIC = re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"(?:GET|POST|PUT|DELETE)\s+(?P<path>[^\s"]+)')

PARSERS = {
    "nginx": ("combined", NGINX_COMBINED), "autoshield": ("pipe", AUTOSHIELD_PIPE),
    "apache": ("combined", APACHE_COMMON), "apache_common": ("common", APACHE_COMMON),
    "haproxy": ("haproxy", HAPROXY), "generic": ("generic", GENERIC),
}

def parse_line(line: str, fmt: str = "nginx") -> Optional[dict]:
    line = line.strip()
    if not line: return None
    _, pattern = PARSERS.get(fmt, PARSERS["nginx"])
    m = pattern.search(line)
    if not m: return None
    groups = m.groupdict()
    ip, path, method, status, ua = groups.get("ip", "0.0.0.0"), unquote_plus(groups.get("path", "/")), groups.get("method", "GET"), int(groups.get("status", 200) or 200), groups.get("ua", "")
    if method in ("OPTIONS", "HEAD") or path.endswith((".ico", ".png", ".jpg", ".css", ".js", ".woff", ".woff2", ".ttf")): return None
    return {"ip": ip, "method": method, "path": path, "status": status, "ua": ua, "raw": f"{method} {path}"}

# ─── Local detection ──────────────────────────────────────────────────────────
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from scapy_engine import AttackDetector
    _local_detector = AttackDetector()
    LOCAL_DETECT = True
except ImportError:
    LOCAL_DETECT = False

def detect_locally(payload: str) -> Optional[dict]:
    if not LOCAL_DETECT: return None
    return _local_detector.classify(payload)

# ─── Rate Limiter ─────────────────────────────────────────────────────────────
class RateLimiter:
    """Sliding window rate limiter to detect brute-force and volumetric floods."""
    def __init__(self, max_req_per_sec=20, window=1.0):
        self.max_req = max_req_per_sec
        self.window = window
        self.history = defaultdict(list)
        self.lock = threading.Lock()

    def check_and_update(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            # Keep only timestamps within the sliding window
            self.history[ip] = [t for t in self.history[ip] if now - t < self.window]
            self.history[ip].append(now)
            return len(self.history[ip]) > self.max_req

# ─── Active Defense Manager (ipset, Dynamic Config, Threat Scoring) ───────────
class ActiveDefenseManager:
    def __init__(self, api_client=None, db_path="autoshield_agent.db", block_duration=3600, score_limit=100):
        self.api_client = api_client
        self.db_path = db_path
        self.block_duration = block_duration
        self.score_limit = score_limit
        self.whitelist_file = "whitelist.txt"
        self.whitelist = set()
        
        self.scores = defaultdict(int)
        self.blocked_ips = {}
        self.action_queue = queue.Queue()
        self.server_ip = _get_server_ip()
        
        self._init_ipset()
        self._init_db()
        self._sync_state()
        self._reload_whitelist()
        
        threading.Thread(target=self._worker_loop, daemon=True).start()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        threading.Thread(target=self._whitelist_loop, daemon=True).start()

    def _init_ipset(self):
        """Sets up scalable ipset hashes instead of standard iptables."""
        try:
            subprocess.run(["sudo", "ipset", "create", "autoshield_blocks", "hash:ip"], capture_output=True)
            # Ensure iptables uses the ipset
            res = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-m", "set", "--match-set", "autoshield_blocks", "src", "-j", "DROP"], capture_output=True)
            if res.returncode != 0:
                subprocess.run(["sudo", "iptables", "-I", "INPUT", "-m", "set", "--match-set", "autoshield_blocks", "src", "-j", "DROP"], capture_output=True)
        except Exception as e:
            log.error(f"Failed to initialize ipset: {e}")

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, unblock_at REAL, reason TEXT)")

    def _sync_state(self):
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT ip, unblock_at FROM blocked_ips")
            for ip, unblock_at in c.fetchall():
                if unblock_at > now:
                    self.blocked_ips[ip] = unblock_at
                    self.action_queue.put(("BLOCK", ip))
                else:
                    c.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
            conn.commit()

    def _reload_whitelist(self):
        new_whitelist = {"127.0.0.1", "0.0.0.0", "localhost"}
        try:
            if Path(self.whitelist_file).exists():
                with open(self.whitelist_file) as f:
                    new_whitelist.update({line.strip() for line in f if line.strip() and not line.startswith("#")})
            self.whitelist = new_whitelist
        except Exception as e:
            log.warning(f"Whitelist reload failed: {e}")

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def record_offense(self, ip: str, severity: str, attack_type: str):
        if ip in self.whitelist or ip in self.blocked_ips:
            return

        points = {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 20, "LOW": 10, "INFO": 0}.get(severity.upper(), 10)
        self.scores[ip] += points
        
        if self.scores[ip] >= self.score_limit:
            log.warning(f"🛡️ THREAT LIMIT: {ip} scored {self.scores[ip]}. Initiating ipset block.")
            self._trigger_block(ip, reason=attack_type)
            del self.scores[ip]

    def _trigger_block(self, ip: str, reason: str):
        unblock_at = time.time() + self.block_duration
        self.blocked_ips[ip] = unblock_at
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO blocked_ips VALUES (?, ?, ?)", (ip, unblock_at, reason))
        self.action_queue.put(("BLOCK", ip))
        
        # Distributed Awareness / Observability Hook
        if self.api_client:
            event = {
                "src_ip": ip, "dst_ip": self.server_ip, "timestamp": datetime.now().isoformat(),
                "action": "SYSTEM_BLOCK", "attack_type": reason, "severity": "CRITICAL"
            }
            self.api_client.enqueue(event)

    def _trigger_unblock(self, ip: str):
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
        self.action_queue.put(("UNBLOCK", ip))

    def _worker_loop(self):
        """Async execution using scalable ipset commands."""
        while True:
            action, ip = self.action_queue.get()
            try:
                if action == "BLOCK":
                    res = subprocess.run(["sudo", "ipset", "test", "autoshield_blocks", ip], capture_output=True)
                    if res.returncode != 0: # Not in set
                        subprocess.run(["sudo", "ipset", "add", "autoshield_blocks", ip], capture_output=True)
                        log.info(f"🔒 Added {ip} to ipset.")
                elif action == "UNBLOCK":
                    subprocess.run(["sudo", "ipset", "del", "autoshield_blocks", ip], capture_output=True)
                    log.info(f"🔓 Removed {ip} from ipset (Expired).")
            except Exception as e:
                log.error(f"Active Defense fail-safe triggered for {ip}: {e}")
            finally:
                self.action_queue.task_done()

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            now = time.time()
            for ip in [ip for ip, unblock_at in self.blocked_ips.items() if now > unblock_at]:
                self._trigger_unblock(ip)
                
    def _whitelist_loop(self):
        while True:
            time.sleep(300) # Reload config every 5 minutes
            self._reload_whitelist()

# ─── API Client & File Tailer (Untouched from previous iteration) ─────────────
class AutoShieldClient:
    def __init__(self, api_url: str, api_key: str, batch_size: int = 20, flush_interval: float = 2.0):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._queue = deque(maxlen=10000) 
        self._lock = threading.Lock()
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
        self._stats = {"sent": 0, "errors": 0, "detections": 0}

    def enqueue(self, event: dict):
        with self._lock: self._queue.append(event)

    def _flush_loop(self):
        while True:
            time.sleep(self.flush_interval)
            self._flush()

    def _flush(self):
        with self._lock:
            if not self._queue: return
            batch = [self._queue.popleft() for _ in range(min(len(self._queue), self.batch_size))]

        if not batch or not REQUESTS_OK: return

        try:
            resp = requests.post(f"{self.api_url}/events/batch", json={"events": batch}, headers={"X-AutoShield-Key": self.api_key}, timeout=5)
            resp.raise_for_status()
            self._stats["sent"] += len(batch)
            self._stats["detections"] += sum(1 for r in resp.json().get("results", []) if r.get("decision") != "ALLOW")
        except Exception as e:
            self._stats["errors"] += 1
            with self._lock:
                for ev in reversed(batch[:100]): self._queue.appendleft(ev)

    def stop(self):
        while True:
            with self._lock:
                if not self._queue: break
            self._flush()

    def send_telemetry(self, metrics: dict):
        if not REQUESTS_OK: return
        try: requests.post(f"{self.api_url}/telemetry", json=metrics, headers={"X-AutoShield-Key": self.api_key}, timeout=2)
        except Exception: pass

    def scan_inline(self, payload: str, src_ip: str) -> Optional[dict]:
        if not REQUESTS_OK: return None
        try:
            resp = requests.post(f"{self.api_url}/scan", json={"payload": payload, "src_ip": src_ip}, headers={"X-AutoShield-Key": self.api_key}, timeout=0.1)
            return resp.json()
        except Exception: return None

class LogTailer:
    def __init__(self, path: str, poll_interval: float = 0.25):
        self.path = Path(path)
        self.poll_interval = poll_interval
        self._inode = None
        self._pos = 0

    def tail(self):
        if self.path.exists():
            with open(self.path) as f:
                f.seek(0, 2)
                self._pos = f.tell()
                self._inode = self.path.stat().st_ino

        while True:
            time.sleep(self.poll_interval)
            try:
                stat = self.path.stat()
                if stat.st_ino != self._inode:
                    self._inode = stat.st_ino
                    self._pos = 0
                with open(self.path) as f:
                    f.seek(self._pos)
                    while True:
                        line = f.readline()
                        if not line: break
                        self._pos = f.tell()
                        yield line
            except FileNotFoundError: time.sleep(2)
            except Exception: time.sleep(1)

# ─── Main agent loop ──────────────────────────────────────────────────────────
class NginxAgent:
    def __init__(self, log_paths, api_url, api_key, fmt="nginx", inline_mode=False, test_only=False, server_ip=None):
        self.log_paths = [Path(p) for p in log_paths]
        self.fmt = fmt
        self.inline = inline_mode
        self.test_only = test_only
        self.server_ip = server_ip or _get_server_ip()
        self._stats = {"lines_read": 0, "parsed": 0, "detections": 0, "skipped": 0}
        self._client = AutoShieldClient(api_url, api_key) if not test_only else None
        
        self.defense = ActiveDefenseManager(api_client=self._client)
        self.rate_limiter = RateLimiter(max_req_per_sec=30) # Penalize >30 req/sec

    def run(self):
        log.info(f"AutoShield Agent starting | format={self.fmt}")
        threads = [threading.Thread(target=self._tail_file, args=(p,), daemon=True) for p in self.log_paths]
        for t in threads: t.start()
        threading.Thread(target=self._telemetry_loop, daemon=True).start()
        for t in threads: t.join()
        if self._client: self._client.stop()

    def _telemetry_loop(self):
        while True:
            try:
                import psutil
                mem = psutil.virtual_memory()
                metrics = {
                    "cpu": psutil.cpu_percent(interval=1), "memory": mem.percent, "disk": psutil.disk_usage("/").percent,
                    "details": {"mem_used_gb": round(mem.used / (1024**3), 2)}
                }
                if self._client: self._client.send_telemetry(metrics)
            except Exception: pass
            time.sleep(14)

    def _tail_file(self, path: Path):
        for line in LogTailer(str(path)).tail():
            self._stats["lines_read"] += 1
            self._process_line(line)

    def _process_line(self, line: str):
        parsed = parse_line(line, self.fmt)
        if not parsed:
            self._stats["skipped"] += 1
            return
        
        ip = parsed["ip"]
        if self.defense.is_blocked(ip):
            return
            
        self._stats["parsed"] += 1
        payload = f"{parsed['method']} {parsed['path']}"

        # RATE LIMITING CHECK
        if self.rate_limiter.check_and_update(ip):
            self.defense.record_offense(ip, "HIGH", "Volumetric/Rate Limit Exceeded")

        # INLINE MODE (API Sync)
        if self.inline and self._client:
            api_resp = self._client.scan_inline(payload, ip)
            if api_resp and api_resp.get("decision") != "ALLOW":
                self.defense.record_offense(ip, "CRITICAL", api_resp.get('attack_type', 'API Global Block'))

        # LOCAL DETECT
        detection = detect_locally(payload) or {"attack_type": "Benign", "severity": "INFO", "confidence": 0, "matched_rules": []}

        if detection["attack_type"] != "Benign":
            self._stats["detections"] += 1
            self.defense.record_offense(ip, detection["severity"], detection["attack_type"])
            log.warning(f"[{detection['severity']}] {detection['attack_type']} from {ip} | {payload[:80]}")

        if self.test_only:
            print(json.dumps({"ip": ip, "attack_type": detection["attack_type"], "severity": detection["severity"], "payload": payload[:100]}))
            return

        if self._client:
            event = {
                "src_ip": ip, "dst_ip": self.server_ip, "payload": payload,
                "timestamp": datetime.now().isoformat(), "ingestion_source": "nginx_agent",
                "attack_type": detection.get("attack_type", "Unknown"), "severity": detection.get("severity", "INFO"), 
                "confidence": detection.get("confidence", 0), "payload_snip": payload[:300],
            }
            if detection["attack_type"] != "Benign":
                event["action"] = "DETECTED"
                event["status"] = "FLAGGED"
            self._client.enqueue(event)

def _get_server_ip() -> str:
    try:
        import socket
        return socket.gethostbyname(socket.gethostname())
    except Exception: return "0.0.0.0"

# ─── CLI ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoShield Log Agent (Ultimate)")
    parser.add_argument("--log", nargs="+", default=["test_website/access.log"])
    parser.add_argument("--api", default="http://localhost:8503")
    parser.add_argument("--key", default=os.environ.get("AUTOSHIELD_API_KEY", "as_demo_key"))
    parser.add_argument("--format", default="nginx", choices=["nginx", "apache", "apache_common", "caddy", "haproxy", "generic", "autoshield"])
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--inline", action="store_true")
    args = parser.parse_args()

    import glob
    paths = [p for pat in args.log for p in (glob.glob(pat) or [pat])]
    if not paths:
        sys.exit(1)

    NginxAgent(paths, args.api, args.key, args.format, args.inline, args.test).run()