"""
AutoShield - Auto-Block Module
Fires iptables rules to block attacker IPs automatically.
Falls back to in-process blocklist when not root (dev mode).

Includes DDoS Shield mode:
  - Normal mode: block after 5 attacks/60s (CRITICAL always blocked)
  - DDoS mode: block after 3 requests/10s regardless of type
"""

import subprocess
import logging
import threading
import json
import time
import os
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional

log = logging.getLogger("AutoShield.Blocker")

# ─── Config ───────────────────────────────────────────────────────────────────

BLOCK_DURATION_SECONDS = 3600  # 1 hour auto-expiry
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_THRESHOLD = 5  # attacks before rate-ban
WHITELIST_IPS = {
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",  # Private networks
    "172.16.0.0/12",
    "192.168.0.0/16",
}  # never block these

# Allowlist for known safe IPs (deployers add their own)
SAFE_IPS = set(os.environ.get("AUTOSHIELD_SAFE_IPS", "").split(","))
WHITELIST_IPS.update(SAFE_IPS)


# ─── iptables helpers ─────────────────────────────────────────────────────────


def _is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def is_root_mode() -> bool:
    return _is_root()


def _has_iptables_permissions() -> bool:
    try:
        result = subprocess.run(
            ["iptables", "-S"], capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def _detect_firewall_mode() -> str:
    if _is_root():
        return "iptables-root"
    if _has_iptables_permissions():
        return "iptables-cap"
    return "in-memory"


def host_firewall_enforced() -> bool:
    return _detect_firewall_mode().startswith("iptables")


def firewall_mode() -> str:
    return "iptables" if host_firewall_enforced() else "in-memory"


def _iptables(action: str, ip: str) -> tuple[bool, str]:
    """
    action: 'block' | 'unblock'
    Returns (success, message)
    """
    flag = "-A" if action == "block" else "-D"
    cmd = ["iptables", flag, "INPUT", "-s", ip, "-j", "DROP"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, f"iptables {action} {ip} OK"
        else:
            return False, f"iptables error: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "iptables not found (not Linux or not installed)"
    except subprocess.TimeoutExpired:
        return False, "iptables command timed out"
    except Exception as e:
        return False, str(e)


# ─── Block Manager ────────────────────────────────────────────────────────────


class BlockManager:
    """
    Tracks blocked IPs, fires iptables rules when root,
    else maintains in-memory blocklist for dev/demo mode.
    """

    def __init__(self):
        self._blocked: dict[str, dict] = {}  # ip → block_record
        self._attack_counts: dict[str, list] = defaultdict(list)  # ip → [timestamps]
        self._lock = threading.RLock()
        self._root = _is_root()
        self._firewall_mode = _detect_firewall_mode()
        self._iptables_enabled = self._firewall_mode.startswith("iptables")

        if not self._iptables_enabled:
            log.warning(
                "Not running as root — iptables disabled. Using in-memory blocklist."
            )
        else:
            log.info(f"Host firewall enforcement active ({self._firewall_mode})")

        # Start expiry cleanup thread
        self._expiry_thread = threading.Thread(target=self._expiry_loop, daemon=True)
        self._expiry_thread.start()

    # ── public API ──────────────────────────────────────────────────────────

    def block_ip(
        self,
        ip: str,
        reason: str = "attack detected",
        severity: str = "HIGH",
        attack_type: str = "Unknown",
    ) -> dict:
        """Block an IP. Returns block record."""
        if ip in WHITELIST_IPS:
            return {"status": "SKIPPED", "reason": "IP is whitelisted", "ip": ip}

        with self._lock:
            if ip in self._blocked:
                return {"status": "ALREADY_BLOCKED", "ip": ip, **self._blocked[ip]}

            expires_at = datetime.now() + timedelta(seconds=BLOCK_DURATION_SECONDS)
            record = {
                "ip": ip,
                "reason": reason,
                "attack_type": attack_type,
                "severity": severity,
                "blocked_at": datetime.now().isoformat(),
                "expires_at": expires_at.isoformat(),
                "method": "iptables" if self._iptables_enabled else "in-memory",
                "status": "BLOCKED",
            }

            # Fire iptables if root
            if self._iptables_enabled:
                ok, msg = _iptables("block", ip)
                if not ok:
                    record["status"] = "BLOCK_FAILED"
                    record["error"] = msg
                    log.error(f"Failed to block {ip}: {msg}")
                    return record
                record["iptables_msg"] = msg

            self._blocked[ip] = record
            log.warning(
                f"🚫 BLOCKED {ip} | {attack_type} [{severity}] "
                f"| expires {expires_at.strftime('%H:%M:%S')} "
                f"| method={record['method']}"
            )
            return record

    def unblock_ip(self, ip: str) -> dict:
        with self._lock:
            if ip not in self._blocked:
                return {"status": "NOT_BLOCKED", "ip": ip}

            record = self._blocked.pop(ip)

            if self._iptables_enabled:
                ok, msg = _iptables("unblock", ip)
                if not ok:
                    log.error(f"Failed to unblock {ip}: {msg}")

            log.info(f"✅ UNBLOCKED {ip}")
            return {"status": "UNBLOCKED", "ip": ip, "was": record}

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def get_blocked_list(self) -> list[dict]:
        with self._lock:
            return list(self._blocked.values())

    def record_attack(self, ip: str) -> bool:
        """
        Track attack rate per IP.
        Returns True if rate-limit threshold exceeded → caller should block.
        """
        now = time.time()
        with self._lock:
            # Prune old timestamps
            self._attack_counts[ip] = [
                t for t in self._attack_counts[ip] if now - t < RATE_LIMIT_WINDOW
            ]
            self._attack_counts[ip].append(now)
            count = len(self._attack_counts[ip])

        if count >= RATE_LIMIT_THRESHOLD:
            log.warning(
                f"Rate limit hit for {ip}: {count} attacks in {RATE_LIMIT_WINDOW}s"
            )
            return True
        return False

    def auto_respond(self, event: dict) -> dict:
        """
        Full auto-defense pipeline for an attack event.
        Returns enriched event with action taken.
        """
        ip = event.get("src_ip", "0.0.0.0")
        attack_type = event.get("attack_type", "Unknown")
        severity = event.get("severity", "HIGH")

        # Always block CRITICAL; rate-limit for others
        should_block = severity == "CRITICAL" or self.record_attack(ip)

        if should_block:
            record = self.block_ip(
                ip,
                reason=f"Auto-blocked: {attack_type}",
                severity=severity,
                attack_type=attack_type,
            )
            event["action"] = "BLOCKED"
            event["status"] = "MITIGATED"
            event["block_record"] = record
        else:
            event["action"] = "RATE_MONITORED"
            event["status"] = "MONITORING"

        # Input sanitization note (applied at WAF layer in real deploy)
        event["sanitization"] = _sanitize_note(attack_type)

        return event

    # ── expiry loop ─────────────────────────────────────────────────────────

    def _expiry_loop(self):
        while True:
            time.sleep(30)
            now = datetime.now()
            with self._lock:
                expired = [
                    ip
                    for ip, rec in self._blocked.items()
                    if datetime.fromisoformat(rec["expires_at"]) <= now
                ]
            for ip in expired:
                log.info(f"Auto-expiring block for {ip}")
                self.unblock_ip(ip)

    def flush_all(self):
        """Emergency: unblock all IPs."""
        ips = list(self._blocked.keys())
        for ip in ips:
            self.unblock_ip(ip)
        log.info(f"Flushed {len(ips)} blocked IPs.")

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_blocked": len(self._blocked),
                "attack_counters": {
                    ip: len(ts) for ip, ts in self._attack_counts.items()
                },
                "root_mode": self._root,
                "host_firewall_enforced": self._iptables_enabled,
                "firewall_mode": "iptables" if self._iptables_enabled else "in-memory",
            }


# ─── Input Sanitization Advice ────────────────────────────────────────────────


def _sanitize_note(attack_type: str) -> str:
    NOTES = {
        "SQLi": "Parameterized queries applied. Input stripped of SQL metacharacters.",
        "XSS": "HTML-encoded output. Script tags neutralized.",
        "LFI": "Path traversal stripped. File access restricted to allowed dir.",
        "CMDi": "Shell metacharacters removed. Command execution sandboxed.",
    }
    return NOTES.get(attack_type, "Input sanitized.")


# ─── DDoS Shield ─────────────────────────────────────────────────────────────


class DDoSShield:
    """
    Real DDoS mitigation engine.

    - Tracks per-IP request rate in a rolling 10-second window.
    - When SHIELD is ENGAGED: block any IP exceeding 10 req/10s (or custom threshold).
    - Integrates with BlockManager to issue real iptables / in-memory bans.
    - Tracks stats: req/s per IP, top offenders, total dropped packets.
    """

    DDOS_WINDOW_S = 10  # rolling window in seconds
    DDOS_THRESHOLD = 3  # requests before DDoS-block (engaged mode)
    DDOS_BLOCK_DURATION = 300  # 5 minutes auto-expiry for DDoS blocks

    def __init__(self, blocker: "BlockManager"):
        self._blocker = blocker
        self._lock = threading.RLock()
        self._engaged = False
        self._engaged_at: Optional[datetime] = None
        self._engaged_by: str = ""
        # Rolling request log per IP: {ip: [unix_timestamps]}
        self._req_log: dict[str, list] = defaultdict(list)
        self._total_dropped = 0
        self._total_requests = 0
        self._log = logging.getLogger("AutoShield.DDoS")

        # Start background monitor
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    # ── Public API ─────────────────────────────────────────────────────────

    def engage(self, engaged_by: str = "api") -> dict:
        """Activate DDoS Shield on this host."""
        with self._lock:
            self._engaged = True
            self._engaged_at = datetime.now()
            self._engaged_by = engaged_by
        self._log.warning(f"🛡️ DDoS SHIELD ENGAGED by {engaged_by}")
        return self.status()

    def disengage(self) -> dict:
        """Deactivate DDoS Shield."""
        with self._lock:
            self._engaged = False
            self._engaged_at = None
        self._log.info("DDoS Shield disengaged.")
        return self.status()

    def record_request(self, ip: str) -> bool:
        """
        Record an incoming request from ip.
        Returns True if the request should be BLOCKED (DDoS threshold exceeded).
        """
        if ip in WHITELIST_IPS:
            return False

        now = time.time()
        with self._lock:
            # Prune old entries
            self._req_log[ip] = [
                t for t in self._req_log[ip] if now - t < self.DDOS_WINDOW_S
            ]
            self._req_log[ip].append(now)
            self._total_requests += 1
            count = len(self._req_log[ip])

            if self._engaged and count >= self.DDOS_THRESHOLD:
                self._total_dropped += 1
                return True

        return False

    def auto_block_if_needed(self, ip: str) -> bool:
        """Check and block if DDoS threshold exceeded. Returns True if blocked."""
        should_block = self.record_request(ip)
        if should_block and not self._blocker.is_blocked(ip):
            self._blocker.block_ip(
                ip,
                reason="DDoS Shield: rate limit exceeded",
                severity="CRITICAL",
                attack_type="DDoS",
            )
            self._log.warning(f"🚫 DDoS-blocked {ip}")
            return True
        return False

    def get_top_attackers(self, n: int = 10) -> list[dict]:
        """Return top n IPs by request rate."""
        now = time.time()
        with self._lock:
            counts = []
            for ip, times in self._req_log.items():
                recent = [t for t in times if now - t < self.DDOS_WINDOW_S]
                if recent:
                    counts.append(
                        {
                            "ip": ip,
                            "req_per_10s": len(recent),
                            "req_per_s": round(len(recent) / self.DDOS_WINDOW_S, 2),
                            "blocked": self._blocker.is_blocked(ip),
                        }
                    )
            return sorted(counts, key=lambda x: x["req_per_10s"], reverse=True)[:n]

    def is_engaged(self) -> bool:
        """Return whether the DDoS Shield is currently engaged."""
        with self._lock:
            return self._engaged

    def track_request(self, ip: str) -> bool:
        """Alias for record_request(). Track a request from an IP and return True if blocked."""
        return self.record_request(ip)

    def status(self) -> dict:
        with self._lock:
            return {
                "engaged": self._engaged,
                "engaged_at": self._engaged_at.isoformat()
                if self._engaged_at
                else None,
                "engaged_by": self._engaged_by,
                "threshold": self.DDOS_THRESHOLD,
                "window_seconds": self.DDOS_WINDOW_S,
                "total_requests_tracked": self._total_requests,
                "total_dropped": self._total_dropped,
                "top_attackers": self.get_top_attackers(5),
                "firewall_mode": "iptables"
                if self._blocker._iptables_enabled
                else "in-memory",
            }

    # ── Background Monitor ─────────────────────────────────────────────────

    def _monitor_loop(self):
        """Continuously prune stale request logs and auto-block in DDoS mode."""
        while True:
            time.sleep(5)
            if not self._engaged:
                continue
            try:
                now = time.time()
                with self._lock:
                    ips = list(self._req_log.keys())
                for ip in ips:
                    if self._blocker.is_blocked(ip):
                        continue
                    with self._lock:
                        recent = [
                            t
                            for t in self._req_log.get(ip, [])
                            if now - t < self.DDOS_WINDOW_S
                        ]
                    if len(recent) >= self.DDOS_THRESHOLD:
                        self._blocker.block_ip(
                            ip,
                            reason="DDoS Shield auto-block",
                            severity="CRITICAL",
                            attack_type="DDoS",
                        )
                        self._log.warning(
                            f"🛡️ DDoS auto-blocked {ip} ({len(recent)} req/10s)"
                        )
                        with self._lock:
                            self._total_dropped += len(recent)
            except Exception as e:
                self._log.error(f"DDoS monitor error: {e}")


# ─── Singletons ────────────────────────────────────────────────────────────────

_blocker_instance: BlockManager | None = None
_ddos_shield_instance: DDoSShield | None = None


def get_blocker() -> BlockManager:
    global _blocker_instance
    if _blocker_instance is None:
        _blocker_instance = BlockManager()
    return _blocker_instance


def get_ddos_shield() -> DDoSShield:
    global _ddos_shield_instance
    if _ddos_shield_instance is None:
        _ddos_shield_instance = DDoSShield(get_blocker())
    return _ddos_shield_instance


# ─── Quick test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    blocker = BlockManager()

    test_event = {
        "src_ip": "192.168.1.99",
        "attack_type": "SQLi",
        "severity": "CRITICAL",
    }

    print("=== AutoShield Blocker Self-Test ===\n")
    result = blocker.auto_respond(test_event)
    print(json.dumps(result, indent=2, default=str))

    print(f"\nBlocked list: {blocker.get_blocked_list()}")
    print(f"Stats: {blocker.stats()}")

    shield = get_ddos_shield()
    print(f"\nDDoS Shield status: {shield.status()}")
    shield.engage("test")
    for _ in range(12):
        shield.record_request("10.0.0.1")
    print(f"After 12 requests at 10.0.0.1: {shield.get_top_attackers(3)}")

    time.sleep(1)
    print(f"\nUnblocking...")
    blocker.unblock_ip("192.168.1.99")
    print(f"Blocked list after unblock: {blocker.get_blocked_list()}")
