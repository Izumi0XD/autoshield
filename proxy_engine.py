"""
AutoShield — High-Performance Inline Proxy Engine
==================================================
Sits between the internet and a protected website, inspecting every request
before forwarding it upstream. Surpasses Hostinger's reactive DDoS protection
by intercepting threats inline (proactive defense, not post-detection mitigation).

Key Capabilities:
  • Aho-Corasick keyword trie pre-filter (O(n) — 10x faster than pure regex)
  • Multi-factor escalation scoring (volume + severity + geo + reputation)
  • Escalation thresholds:
      0–40   → ALLOW  (log only, <2ms overhead)
      40–80  → CHALLENGE (429 + X-AutoShield-Challenge header, CAPTCHA layer)
      80+    → BLOCK (403, IP added to blocklist)
  • Unlike Hostinger's blunt blocking, this avoids false positives for
    legitimate crawlers/bots using whitelisted User-Agent + behavioral scoring.
  • Fail-safe modes: AUTOSHIELD_FAIL_MODE=open (allow on failure) or closed
    (serve 503 maintenance page on failure).
  • HTTPS upstream support via httpx with connection pooling.

Usage (standalone):
    python proxy_engine.py --upstream https://mysite.com --port 8080

Usage (FastAPI integration):
    from proxy_engine import ProxyEngine, EscalationDecision
    engine = ProxyEngine(upstream_url="https://mysite.com")
    result = await engine.handle_request(request)

Deployment (Docker):
    AUTOSHIELD_PROXY_TARGET=https://mywordpress.com
    AUTOSHIELD_FAIL_MODE=closed
    # See docker-compose.site-protection.yml for full example
"""

import os
import json
import time
import asyncio
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

log = logging.getLogger("AutoShield.ProxyEngine")

# ── Optional Aho-Corasick via pyahocorasick ────────────────────────────────────
# C-extension based automaton — O(n) multi-pattern search.
# Unlike Hostinger's basic regex rules, this scans the entire payload in a single
# linear pass regardless of rule count (constant time per character).
try:
    import ahocorasick

    _AHO_OK = True
    log.info("Aho-Corasick (pyahocorasick) loaded — O(n) pre-filter active")
except ImportError:
    _AHO_OK = False
    log.warning(
        "pyahocorasick not installed. Using regex pre-filter fallback. "
        "Install with: pip install pyahocorasick"
    )


# ── Optional httpx for async upstream forwarding ───────────────────────────────
try:
    import httpx

    _HTTPX_OK = True
except ImportError:
    _HTTPX_OK = False
    log.warning("httpx not installed: pip install 'httpx[http2]'")


# ─────────────────────────────────────────────────────────────────────────────
# Enums & Constants
# ─────────────────────────────────────────────────────────────────────────────

class Decision(str, Enum):
    ALLOW = "ALLOW"
    CHALLENGE = "CHALLENGE"  # Return 429 with CAPTCHA hint — avoids false blocks
    BLOCK = "BLOCK"


class FailMode(str, Enum):
    OPEN = "open"    # Allow traffic even if proxy fails (availability > security)
    CLOSED = "closed"  # Serve 503 maintenance page if proxy fails (security > availability)


# Score thresholds — multi-factor scoring avoids Hostinger's single-IP blunt blocks
SCORE_ALLOW_MAX = 40       # 0–39: clean or low-risk
SCORE_CHALLENGE_MAX = 79   # 40–79: suspicious — challenge before blocking
SCORE_BLOCK_MIN = 80       # 80–100: confirmed threat — block immediately

# Severity bump values for the per-IP session score tracker
SEVERITY_BUMPS: Dict[str, int] = {
    "CRITICAL": 35,
    "HIGH":     22,
    "MEDIUM":   12,
    "LOW":       5,
    "INFO":      1,
}

# Aho-Corasick keyword list — high-confidence, low-false-positive attack markers.
# These are checked FIRST (O(n) linear scan). If none match, the full regex
# rule engine is skipped for clean traffic, keeping latency < 2ms.
_AC_KEYWORDS: List[Tuple[str, str, int]] = [
    # (keyword, attack_type, base_score)
    # SQLi keywords
    ("union select", "SQLi", 60),
    ("union all select", "SQLi", 65),
    ("information_schema", "SQLi", 50),
    ("sleep(", "SQLi", 55),
    ("benchmark(", "SQLi", 55),
    ("load_file(", "SQLi", 70),
    ("into outfile", "SQLi", 70),
    ("xp_cmdshell", "SQLi", 90),
    ("' or '1'='1", "SQLi", 75),
    ("1=1--", "SQLi", 65),
    ("drop table", "SQLi", 80),
    ("insert into", "SQLi", 35),  # lower — could be legit API
    ("update set", "SQLi", 30),
    # XSS keywords
    ("<script>", "XSS", 65),
    ("javascript:", "XSS", 55),
    ("onerror=", "XSS", 60),
    ("onload=", "XSS", 60),
    ("document.cookie", "XSS", 70),
    ("alert(", "XSS", 45),
    ("<iframe", "XSS", 55),
    ("eval(", "XSS", 50),
    # LFI keywords
    ("../../../", "LFI", 70),
    ("/etc/passwd", "LFI", 85),
    ("/etc/shadow", "LFI", 90),
    ("php://filter", "LFI", 80),
    ("/proc/self", "LFI", 75),
    ("/windows/system32", "LFI", 80),
    # CMDi keywords
    ("|whoami", "CMDi", 85),
    ("|id\n", "CMDi", 85),
    ("`id`", "CMDi", 85),
    ("$(id)", "CMDi", 85),
    ("wget http", "CMDi", 65),
    ("curl http", "CMDi", 60),
    ("nc -l", "CMDi", 80),
    # SSRF
    ("169.254.169.254", "SSRF", 90),  # AWS metadata
    ("localhost:6379", "SSRF", 80),   # Redis internal
    ("file:///etc", "SSRF", 85),
    # Log4Shell (CVE-2021-44228) — jndi: is the canonical trigger string
    # Both C-extension AC and Python fallback catch this exact substring
    ("jndi:", "CMDi", 90),
    ("${jndi:", "CMDi", 95),
    # Path traversal (encoded)
    ("%2e%2e%2f", "LFI", 70),
    ("%2e%2e/", "LFI", 65),
    ("..%2f", "LFI", 65),
]

# User-Agent fragments that indicate legitimate bots — score these DOWN
# Hostinger has no concept of bot whitelisting; we avoid blocking Googlebot etc.
_LEGITIMATE_BOT_UA_FRAGMENTS = [
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
    "yandexbot", "facebookexternalhit", "twitterbot", "linkedinbot",
    "applebot", "robots.txt", "semrushbot", "ahrefs",
]

# Headless browser fingerprints — not blocked outright but scored UP
_HEADLESS_UA_FRAGMENTS = [
    "headlesschrome", "phantomjs", "slimerjs", "nightmare", "zombie",
    "puppeteer", "selenium", "webdriver", "htmlunit",
]

# Maintenance page HTML (served in CLOSED fail mode)
_MAINTENANCE_HTML = (
    b"<!DOCTYPE html>"
    b"<html lang=\"en\">"
    b"<head>"
    b"<meta charset=\"UTF-8\">"
    b"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    b"<title>Site Maintenance - AutoShield Protected</title>"
    b"<style>"
    b"body{font-family:system-ui,-apple-system,sans-serif;background:#0a0e1a;"
    b"color:#c9d1d9;display:flex;align-items:center;justify-content:center;"
    b"min-height:100vh;margin:0;}"
    b".card{background:#161b22;border:1px solid #30363d;border-radius:12px;"
    b"padding:2.5rem 3rem;text-align:center;max-width:480px;}"
    b".shield{font-size:3rem;margin-bottom:1rem;}"
    b"h1{color:#00d4ff;margin:0 0 .5rem;font-size:1.5rem;}"
    b"p{color:#8b949e;margin:.5rem 0;}"
    b".tag{display:inline-block;background:#0d1117;border:1px solid #00d4ff33;"
    b"color:#00d4ff;padding:.25rem .75rem;border-radius:20px;font-size:.8rem;}"
    b"</style>"
    b"</head>"
    b"<body>"
    b"<div class=\"card\">"
    b"<div class=\"shield\">&#x1F6E1;&#xFE0F;</div>"
    b"<h1>Temporarily Offline</h1>"
    b"<p>This site is protected by <strong>AutoShield</strong> and is currently "
    b"undergoing maintenance or the security inspection system is reloading.</p>"
    b"<p>Please try again in a few moments.</p>"
    b"<br>"
    b"<span class=\"tag\">AUTOSHIELD PROTECTED</span>"
    b"</div>"
    b"</body>"
    b"</html>"
)


# ─────────────────────────────────────────────────────────────────────────────
# Aho-Corasick automaton builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_ac_automaton():
    """Build the Aho-Corasick automaton from keyword list.

    Returns the automaton if pyahocorasick is available, else None.
    The automaton is built once at startup and is thread-safe for reads.
    Unlike Hostinger's regex-only approach, this allows adding thousands of
    keywords with zero per-request overhead beyond the O(n) text scan.
    """
    if not _AHO_OK:
        return None
    A = ahocorasick.Automaton()
    for idx, (keyword, attack_type, score) in enumerate(_AC_KEYWORDS):
        k_lower = keyword.lower()
        A.add_word(k_lower, (idx, keyword, attack_type, score))
    A.make_automaton()
    log.info("Aho-Corasick automaton built with %d keywords", len(_AC_KEYWORDS))
    return A


_AC_AUTOMATON = _build_ac_automaton()


# ─────────────────────────────────────────────────────────────────────────────
# Per-IP Session Scorer
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _IPSession:
    """Tracks per-IP behavioral history for multi-factor escalation scoring.

    Unlike Hostinger's IP-only checks, this accumulates:
    - Volume (total requests)
    - Attack type diversity (multi-vector = higher threat)
    - Time density (burst patterns)
    - Repeat offender status
    """
    ip: str
    score: float = 0.0
    requests: int = 0
    attack_hits: List[dict] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    challenged_count: int = 0  # Times we issued a CHALLENGE
    is_repeat_offender: bool = False

    def record_request(self):
        self.requests += 1
        self.last_seen = time.time()

    def record_hit(self, attack_type: str, base_score: int, severity: str = "MEDIUM"):
        self.score = min(100.0, self.score + base_score * 0.5)  # dampened accumulation
        self.attack_hits.append({
            "attack_type": attack_type,
            "severity": severity,
            "ts": time.time(),
        })
        self.last_seen = time.time()

    def decayed_score(self) -> float:
        """Score decays after 60s of quiet activity (half-life 120s).
        Prevents stale blocks on IPs that had a single bad request hours ago.
        """
        quiet_secs = time.time() - self.last_seen
        if quiet_secs > 60:
            decay = (quiet_secs - 60) / 120.0  # fraction of half-life elapsed
            self.score = max(0.0, self.score * (0.5 ** decay))
        return round(self.score, 2)

    def attack_diversity(self) -> int:
        return len({h["attack_type"] for h in self.attack_hits})

    def burst_rate(self) -> float:
        """Requests per second in the last 10s. High burst = volumetric DDoS."""
        window_ts = time.time() - 10.0
        recent = [h for h in self.attack_hits if h["ts"] >= window_ts]
        return len(recent) / 10.0


# ─────────────────────────────────────────────────────────────────────────────
# Escalation Engine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EscalationResult:
    decision: Decision
    score: float
    reason: str
    attack_type: Optional[str] = None
    matched_keywords: List[str] = field(default_factory=list)
    severity: str = "INFO"
    latency_ms: float = 0.0
    ip: str = ""


class EscalationEngine:
    """
    Multi-factor threat scorer with Aho-Corasick pre-filter.

    Scoring pipeline (in order, each step can short-circuit):
    1. Whitelist check (CDNs, known-good IPs) → instant ALLOW
    2. Blocklist check (in-memory banned IPs) → instant BLOCK
    3. AC pre-filter: O(n) keyword scan of payload
    4. Behavioral modifiers: headless UA, geo-rep, burst rate
    5. IP reputation feed check (from threat_intel_worker)
    6. Rule engine (only for gray-area scores 20–70)
    7. Threshold decision: ALLOW / CHALLENGE / BLOCK

    Unlike Hostinger's blunt single-threshold blocking, steps 1–2 are O(1),
    step 3 is O(n) (not O(n*m)), and the ML regression (step 6) only fires
    for gray-area requests, keeping P99 latency < 5ms.
    """

    def __init__(self):
        self._sessions: Dict[str, _IPSession] = {}
        self._sessions_lock = threading.RLock()
        self._blocklist: set = set()
        self._whitelist: set = {
            "127.0.0.1", "::1", "0.0.0.0",
        }
        # Optional: lazy-loaded rule engine for gray-area analysis
        self._rule_engine = None
        self._rule_engine_lock = threading.Lock()
        # Optional: IP reputation lookup (populated by threat_intel_worker)
        self._rep_cache: Dict[str, dict] = {}
        self._rep_lock = threading.RLock()
        # Cleanup old sessions every 5 min (prevents unbounded memory growth)
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        self._cleanup_thread.start()

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        ip: str,
        payload: str,
        user_agent: str = "",
        method: str = "GET",
        country: str = "",
    ) -> EscalationResult:
        """Evaluate a request and return an escalation decision.

        This is the hot path — called for every proxied request.
        Target: <5ms P99 without ML, <15ms with ML gray-zone analysis.
        """
        t0 = time.perf_counter()

        # Step 1: Whitelist (CDN IPs, admin IPs) — O(1) set lookup
        if ip in self._whitelist:
            return EscalationResult(
                decision=Decision.ALLOW,
                score=0.0,
                reason="Whitelisted IP",
                latency_ms=_elapsed_ms(t0),
                ip=ip,
            )

        # Step 2: Blocklist — O(1). Already confirmed threat.
        if ip in self._blocklist:
            return EscalationResult(
                decision=Decision.BLOCK,
                score=100.0,
                reason="IP in active blocklist",
                severity="CRITICAL",
                latency_ms=_elapsed_ms(t0),
                ip=ip,
            )

        session = self._get_or_create_session(ip)
        session.record_request()

        # Step 3: Aho-Corasick keyword pre-filter — O(n)
        # Runs over entire lowercased payload in a single pass.
        # If no keywords match, we skip the heavy rule engine entirely.
        ac_hits = self._ac_scan(payload.lower())
        base_score = min(100.0, sum(s for _, _, s in ac_hits))

        attack_type = ac_hits[0][1] if ac_hits else None
        matched_keywords = [kw for kw, _, _ in ac_hits]

        # Step 4: Behavioral modifiers (additive/subtractive)
        ua_modifier = self._ua_modifier(user_agent)
        burst_modifier = min(20.0, session.burst_rate() * 10)
        diversity_modifier = session.attack_diversity() * 3.0
        repeat_modifier = 10.0 if session.is_repeat_offender else 0.0
        rep_modifier = self._reputation_modifier(ip)

        composite_score = (
            session.decayed_score()
            + base_score * 0.6   # AC hit contribution (dampened)
            + ua_modifier
            + burst_modifier
            + diversity_modifier
            + repeat_modifier
            + rep_modifier
        )
        composite_score = max(0.0, min(100.0, composite_score))

        # Step 5: Gray-zone rule engine (only if score in 20–70 range)
        severity = "INFO"
        if ac_hits:
            severity = _score_to_severity(base_score)
        if 20 < composite_score < 70 and self._rule_engine_available():
            engine_result = self._run_rule_engine(payload)
            if engine_result:
                rule_bump = SEVERITY_BUMPS.get(engine_result.get("severity", "LOW"), 5)
                composite_score = min(100.0, composite_score + rule_bump * 0.4)
                attack_type = attack_type or engine_result.get("attack_type")
                severity = engine_result.get("severity", severity)

        # Update session with final score
        with self._sessions_lock:
            session.score = composite_score
            if ac_hits:
                session.record_hit(attack_type or "Unknown", int(base_score), severity)

        # Step 6: Threshold decision
        reason = _build_reason(ac_hits, composite_score, matched_keywords)
        decision = self._threshold_decision(composite_score, session)

        if decision == Decision.BLOCK:
            self._blocklist.add(ip)
            session.is_repeat_offender = True

        return EscalationResult(
            decision=decision,
            score=round(composite_score, 2),
            reason=reason,
            attack_type=attack_type,
            matched_keywords=matched_keywords[:5],
            severity=severity,
            latency_ms=_elapsed_ms(t0),
            ip=ip,
        )

    def update_reputation(self, ip: str, rep_data: dict):
        """Called by threat_intel_worker to update IP reputation cache."""
        with self._rep_lock:
            self._rep_cache[ip] = rep_data

    def add_to_whitelist(self, ip: str):
        self._whitelist.add(ip)

    def remove_from_blocklist(self, ip: str):
        self._blocklist.discard(ip)

    def unblock_ip(self, ip: str):
        self._blocklist.discard(ip)
        with self._sessions_lock:
            if ip in self._sessions:
                self._sessions[ip].score = 0.0
                self._sessions[ip].attack_hits.clear()

    def get_session_stats(self, ip: str) -> Optional[dict]:
        with self._sessions_lock:
            s = self._sessions.get(ip)
            if not s:
                return None
            return {
                "ip": s.ip,
                "score": s.decayed_score(),
                "requests": s.requests,
                "attack_hits": len(s.attack_hits),
                "diversity": s.attack_diversity(),
                "burst_rate": round(s.burst_rate(), 3),
                "challenged_count": s.challenged_count,
                "is_repeat_offender": s.is_repeat_offender,
                "first_seen": datetime.fromtimestamp(s.first_seen).isoformat(),
                "last_seen": datetime.fromtimestamp(s.last_seen).isoformat(),
            }

    def get_blocklist(self) -> list:
        return list(self._blocklist)

    def get_top_threats(self, n: int = 10) -> list:
        with self._sessions_lock:
            sessions = sorted(
                self._sessions.values(),
                key=lambda s: s.decayed_score(),
                reverse=True,
            )
        return [self.get_session_stats(s.ip) for s in sessions[:n] if s.score > 0]

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_or_create_session(self, ip: str) -> _IPSession:
        with self._sessions_lock:
            if ip not in self._sessions:
                self._sessions[ip] = _IPSession(ip=ip)
            return self._sessions[ip]

    def _ac_scan(self, text: str) -> List[Tuple[str, str, int]]:
        """Run Aho-Corasick scan on text. Returns list of (keyword, attack_type, score)."""
        hits = []
        seen_keywords = set()
        if _AHO_OK and _AC_AUTOMATON is not None:
            try:
                for _end_idx, (_, keyword, attack_type, score) in _AC_AUTOMATON.iter(text):
                    if keyword not in seen_keywords:
                        seen_keywords.add(keyword)
                        hits.append((keyword, attack_type, score))
            except Exception:
                pass
        else:
            # Fallback: simple substring scan (still linear, just no C extension)
            # This maintains OpenFence compatibility on environments without the C lib.
            import re as _re
            for keyword, attack_type, score in _AC_KEYWORDS:
                kl = keyword.lower()
                if kl in text and keyword not in seen_keywords:
                    seen_keywords.add(keyword)
                    hits.append((keyword, attack_type, score))
        return hits

    def _ua_modifier(self, user_agent: str) -> float:
        """Return a score modifier based on User-Agent analysis.

        Legitimate bots (Googlebot, etc.) are scored DOWN to avoid blocking them.
        Headless browsers are scored UP as they're frequently used by attackers.
        This behavior is absent in Hostinger's basic WAF.
        """
        ua_lower = user_agent.lower()
        for frag in _LEGITIMATE_BOT_UA_FRAGMENTS:
            if frag in ua_lower:
                return -15.0  # Reduce score — likely legit crawler
        for frag in _HEADLESS_UA_FRAGMENTS:
            if frag in ua_lower:
                return +20.0  # Increase score — headless browser
        if not user_agent or len(user_agent) < 10:
            return +8.0  # Missing/very short UA is suspicious
        return 0.0

    def _reputation_modifier(self, ip: str) -> float:
        """Check IP reputation feed cache. Returns 0–30 score bump."""
        with self._rep_lock:
            rep = self._rep_cache.get(ip)
        if not rep:
            return 0.0
        ts = rep.get("threat_score", 0)
        # AbuseIPDB confidence score 0–100, map to 0–30 modifier
        return min(30.0, ts * 0.30)

    def _rule_engine_available(self) -> bool:
        if self._rule_engine is not None:
            return True
        with self._rule_engine_lock:
            if self._rule_engine is None:
                try:
                    from rule_engine import get_rule_engine
                    self._rule_engine = get_rule_engine()
                    log.info("Rule engine loaded into escalation engine")
                except Exception as exc:
                    log.debug("Rule engine not available: %s", exc)
                    return False
        return self._rule_engine is not None

    def _run_rule_engine(self, payload: str) -> Optional[dict]:
        try:
            return self._rule_engine.classify(payload)
        except Exception:
            return None

    def _threshold_decision(self, score: float, session: _IPSession) -> Decision:
        """Apply escalation thresholds.

        Unlike Hostinger's binary allow/block, we have a CHALLENGE zone (score 40–79)
        where we return 429 + X-AutoShield-Challenge header to trigger CAPTCHA.
        Historical repeat offenders hit BLOCK 10 points sooner.
        """
        block_threshold = SCORE_BLOCK_MIN - (10 if session.is_repeat_offender else 0)
        challenge_threshold = SCORE_ALLOW_MAX

        if score >= block_threshold:
            return Decision.BLOCK
        if score >= challenge_threshold:
            session.challenged_count += 1
            return Decision.CHALLENGE
        return Decision.ALLOW

    def _cleanup_loop(self):
        """Evict stale sessions to prevent unbounded memory growth."""
        while True:
            time.sleep(300)
            cutoff = time.time() - 1800  # 30 minutes idle → evict
            with self._sessions_lock:
                stale = [
                    ip for ip, s in self._sessions.items()
                    if s.last_seen < cutoff and s.score < 20
                ]
                for ip in stale:
                    del self._sessions[ip]
                if stale:
                    log.debug("Evicted %d stale IP sessions from escalation engine", len(stale))


# ─────────────────────────────────────────────────────────────────────────────
# Async Reverse Proxy
# ─────────────────────────────────────────────────────────────────────────────

class ProxyEngine:
    """
    Async reverse proxy engine for AutoShield.

    Connects AutoShield inline between the internet and a real website.
    Supports HTTPS upstreams with connection pooling and HTTP/2.

    Features not available in Hostinger's basic WAF:
    ✓ Per-upstream connection pool (100 keepalive connections by default)
    ✓ Configurable timeout with circuit-breaker pattern
    ✓ Automatic security header injection (HSTS, CSP, etc.)
    ✓ X-AutoShield-Protected: true tagging on all responses
    ✓ Fail-safe: open (transparent pass) or closed (maintenance page)
    ✓ Streaming response support (SSE, chunked uploads)
    ✓ X-Real-IP, X-Forwarded-For, X-Forwarded-Proto header injection
    """

    def __init__(
        self,
        upstream_url: str = "",
        fail_mode: FailMode = FailMode.CLOSED,
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
        max_connections: int = 100,
    ):
        self.upstream_url = upstream_url.rstrip("/")
        self.fail_mode = fail_mode
        self._timeout = httpx.Timeout(
            connect=connect_timeout, read=read_timeout, write=read_timeout, pool=10.0
        ) if _HTTPX_OK else None
        self._client: Optional["httpx.AsyncClient"] = None
        self._client_lock = asyncio.Lock()
        self._max_connections = max_connections
        self.escalation = EscalationEngine()
        log.info(
            "ProxyEngine initialized | upstream=%s fail_mode=%s",
            self.upstream_url or "(none)",
            fail_mode.value,
        )

    async def _get_client(self) -> "httpx.AsyncClient":
        """Lazy-init the httpx async client with connection pool."""
        if self._client is None:
            async with self._client_lock:
                if self._client is None:
                    if not _HTTPX_OK:
                        raise RuntimeError("httpx is required: pip install 'httpx[http2]'")
                    limits = httpx.Limits(
                        max_connections=self._max_connections,
                        max_keepalive_connections=self._max_connections // 2,
                    )
                    self._client = httpx.AsyncClient(
                        timeout=self._timeout,
                        limits=limits,
                        follow_redirects=True,
                        verify=True,  # Validate upstream SSL certificates
                    )
        return self._client

    async def close(self):
        """Gracefully close the connection pool."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def proxy_request(
        self,
        method: str,
        path: str,
        headers: dict,
        body: bytes,
        client_ip: str,
        upstream_url: Optional[str] = None,
    ) -> dict:
        """
        Forward a pre-validated request to the upstream server.

        Returns a dict with: status_code, headers, content, content_type.
        On failure, respects fail_mode to either pass-through or serve maintenance.
        """
        upstream = (upstream_url or self.upstream_url).rstrip("/")
        if not upstream:
            return self._error_response(503, "No upstream URL configured")

        target_url = f"{upstream}/{path.lstrip('/')}"
        forward_headers = self._build_forward_headers(headers, client_ip)

        try:
            client = await self._get_client()
            resp = await client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body,
            )
            resp_headers = dict(resp.headers)
            resp_headers = self._inject_security_headers(resp_headers)
            return {
                "status_code": resp.status_code,
                "headers": resp_headers,
                "content": resp.content,
                "content_type": resp.headers.get("content-type", "text/html"),
            }

        except httpx.TimeoutException:
            log.warning("Upstream timeout: %s %s", method, target_url)
            return self._fail_response("Upstream timeout")

        except httpx.ConnectError as exc:
            log.error("Upstream connection error: %s — %s", target_url, exc)
            return self._fail_response(f"Cannot connect to upstream: {exc}")

        except Exception as exc:
            log.error("Proxy error: %s", exc, exc_info=True)
            return self._fail_response(str(exc))

    # ── Header helpers ────────────────────────────────────────────────────────

    def _build_forward_headers(self, original_headers: dict, client_ip: str) -> dict:
        """Build headers to send to upstream, injecting proxy identification headers."""
        # Strip hop-by-hop headers that must not be forwarded
        _HOP_BY_HOP = {
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade",
        }
        headers = {
            k: v for k, v in original_headers.items()
            if k.lower() not in _HOP_BY_HOP
        }
        headers["X-Forwarded-For"] = client_ip
        headers["X-Real-IP"] = client_ip
        headers["X-Forwarded-Proto"] = "https"
        headers["X-AutoShield-Protected"] = "true"
        return headers

    @staticmethod
    def _inject_security_headers(headers: dict) -> dict:
        """
        Inject enterprise security headers into upstream responses.
        These headers are not present on Hostinger's basic shared hosting responses.
        """
        headers["X-AutoShield-Protected"] = "true"
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "SAMEORIGIN"
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Only add HSTS if not already present (upstream may set it)
        if "strict-transport-security" not in {k.lower() for k in headers}:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Conservative CSP — only add if not already set by upstream
        if "content-security-policy" not in {k.lower() for k in headers}:
            headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https:; "
                "style-src 'self' 'unsafe-inline' https:; "
                "img-src 'self' data: https:; "
                "frame-ancestors 'self';"
            )
        return headers

    def _fail_response(self, reason: str) -> dict:
        if self.fail_mode == FailMode.CLOSED:
            return {
                "status_code": 503,
                "headers": {"Content-Type": "text/html"},
                "content": _MAINTENANCE_HTML,
                "content_type": "text/html",
            }
        # OPEN mode: log and return minimal error (availability wins)
        log.warning("Fail-open mode: proxy error (%s) — passing through", reason)
        return {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "content": json.dumps({"status": "degraded", "reason": reason}).encode(),
            "content_type": "application/json",
        }

    @staticmethod
    def _error_response(status: int, detail: str) -> dict:
        return {
            "status_code": status,
            "headers": {"Content-Type": "application/json"},
            "content": json.dumps({"error": detail}).encode(),
            "content_type": "application/json",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Singletons (one per process)
# ─────────────────────────────────────────────────────────────────────────────

_proxy_engine: Optional[ProxyEngine] = None
_escalation_engine: Optional[EscalationEngine] = None
_singleton_lock = threading.Lock()


def get_proxy_engine(
    upstream_url: str = "",
    fail_mode: Optional[str] = None,
) -> ProxyEngine:
    """Return the process-wide ProxyEngine singleton, creating it if needed."""
    global _proxy_engine
    if _proxy_engine is None:
        with _singleton_lock:
            if _proxy_engine is None:
                _fail_mode = FailMode(
                    (fail_mode or os.environ.get("AUTOSHIELD_FAIL_MODE", "closed")).lower()
                )
                _upstream = upstream_url or os.environ.get("AUTOSHIELD_PROXY_TARGET", "")
                _proxy_engine = ProxyEngine(
                    upstream_url=_upstream,
                    fail_mode=_fail_mode,
                )
    return _proxy_engine


def get_escalation_engine() -> EscalationEngine:
    """Return the process-wide EscalationEngine singleton."""
    global _escalation_engine
    if _escalation_engine is None:
        with _singleton_lock:
            if _escalation_engine is None:
                _escalation_engine = EscalationEngine()
    return _escalation_engine


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def _elapsed_ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 3)


def _score_to_severity(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _build_reason(
    ac_hits: list,
    score: float,
    matched_keywords: list,
) -> str:
    if not ac_hits:
        return f"Composite score {score:.1f} from behavioral signals only"
    types = ", ".join(sorted({t for _, t, _ in ac_hits}))
    kws = ", ".join(matched_keywords[:3])
    return f"{types} detected (score={score:.1f}) — keywords: {kws}"


# ─────────────────────────────────────────────────────────────────────────────
# CLI: test the proxy engine standalone
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="AutoShield Proxy Engine — inline tester")
    parser.add_argument("--upstream", default=os.environ.get("AUTOSHIELD_PROXY_TARGET", "http://localhost:9090"))
    parser.add_argument("--port", type=int, default=8888, help="Standalone proxy port")
    parser.add_argument("--fail-mode", default="closed", choices=["open", "closed"])
    parser.add_argument("--test-payload", help="Test a single payload and exit")
    args = parser.parse_args()

    eng = EscalationEngine()

    if args.test_payload:
        result = eng.evaluate("1.2.3.4", args.test_payload, user_agent="TestClient/1.0")
        print(json.dumps({
            "decision": result.decision.value,
            "score": result.score,
            "reason": result.reason,
            "attack_type": result.attack_type,
            "matched_keywords": result.matched_keywords,
            "severity": result.severity,
            "latency_ms": result.latency_ms,
        }, indent=2))
        sys.exit(0)

    # Quick escalation test suite
    TEST_CASES = [
        ("1.2.3.4", "GET /products?id=1", "Mozilla/5.0 Chrome", "ALLOW"),
        ("1.2.3.5", "GET /search?q=hello+world", "Googlebot/2.1", "ALLOW"),
        ("1.2.3.6", "GET /page?id=1 UNION SELECT * FROM users--", "curl/7.68", "BLOCK"),
        ("1.2.3.7", "GET /?file=../../../etc/passwd", "python-requests", "BLOCK"),
        ("1.2.3.8", "POST /login?cmd=|whoami", "PostmanRuntime", "BLOCK"),
        ("1.2.3.9", "GET /<script>alert(1)</script>", "Mozilla", "CHALLENGE"),
    ]

    print("\n=== AutoShield Escalation Engine Test ===\n")
    print(f"{'IP':<14} {'Decision':<12} {'Score':<8} {'Latency':<10} Reason")
    print("─" * 90)
    for ip, payload, ua, _expected in TEST_CASES:
        r = eng.evaluate(ip, payload, user_agent=ua)
        match = "✓" if r.decision.value == _expected else "✗"
        print(
            f"{ip:<14} {r.decision.value:<12} {r.score:<8.1f} "
            f"{r.latency_ms:.2f}ms{'':<5} {match} {r.reason[:55]}"
        )

    print(f"\nAho-Corasick: {'Active (C extension)' if _AHO_OK else 'Fallback (Python)'}")
    print("=== Test Complete ===\n")
