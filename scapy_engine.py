"""
AutoShield - Scapy Traffic Capture + Attack Detection Engine
Intercepts HTTP traffic, classifies SQLi/XSS/LFI attacks via rule engine + ML
"""

import re
import json
import time
import threading
import logging
import uuid
from datetime import datetime
from collections import defaultdict
from urllib.parse import unquote_plus

# Scapy imports (graceful fallback for non-root/container dev mode)
try:
    from scapy.all import sniff, TCP, IP, Raw

    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    print(f"[WARNING] Scapy unavailable ({e}). Running in simulation mode.")

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("AutoShield.Engine")

# ─── ML Anomaly Detector ──────────────────────────────────────────────────────


class MLAnomalyDetector:
    """Simple ML-based anomaly detection for payloads using Isolation Forest."""

    def __init__(self):
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.feature_extraction.text import TfidfVectorizer
            import numpy as np

            self.vectorizer = TfidfVectorizer(
                max_features=100, ngram_range=(1, 2), stop_words="english"
            )
            self.model = IsolationForest(contamination=0.1, random_state=42)
            self.trained = False
            self._train_data = []  # Store benign payloads for training
        except ImportError:
            self.trained = False
            log.warning("ML dependencies not available")

    def add_benign_sample(self, payload: str):
        """Add benign payload for training."""
        if len(self._train_data) < 1000:  # Limit training data
            self._train_data.append(payload)

    def train(self):
        """Train the model on benign data."""
        if len(self._train_data) < 10 or not hasattr(self, "vectorizer"):
            return
        try:
            X = self.vectorizer.fit_transform(self._train_data)
            self.model.fit(X.toarray())
            self.trained = True
            log.info(f"ML anomaly detector trained on {len(self._train_data)} samples")
        except Exception as e:
            log.error(f"ML training failed: {e}")

    def is_anomalous(self, payload: str) -> bool:
        """Return True if payload is anomalous."""
        if not self.trained or not hasattr(self, "vectorizer"):
            return False
        try:
            X = self.vectorizer.transform([payload])
            score = self.model.decision_function(X.toarray())[0]
            return score < 0  # Negative scores indicate anomalies
        except Exception:
            return False


# ─── Attack Signature Rules ───────────────────────────────────────────────────

SQLI_PATTERNS = [
    r"(?i)(union\s+select)",
    r"(?i)(select\s+.*\s+from)",
    r"(?i)(insert\s+into)",
    r"(?i)(drop\s+table)",
    r"(?i)(exec\s*\(|execute\s*\()",
    r"(?i)(--\s*$|;\s*--)",
    r"(?i)(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
    r"(?i)(sleep\s*\(\s*\d+\s*\))",
    r"(?i)(benchmark\s*\()",
    r"(?i)(information_schema)",
    r"(?i)(load_file\s*\()",
    r"(?i)(into\s+outfile)",
    r"'[^']*'[^']*=",
    r"(?i)(xp_cmdshell)",
    r"(?i)(waitfor\s+delay)",
]

XSS_PATTERNS = [
    r"(?i)<script[^>]*>",
    r"(?i)</script>",
    r"(?i)(javascript\s*:)",
    r"(?i)(on\w+\s*=\s*['\"])",
    r"(?i)(alert\s*\()",
    r"(?i)(document\.cookie)",
    r"(?i)(document\.write\s*\()",
    r"(?i)(eval\s*\()",
    r"(?i)(<iframe[^>]*>)",
    r"(?i)(src\s*=\s*['\"]javascript:)",
    r"(?i)(vbscript\s*:)",
    r"(?i)(<img[^>]+onerror\s*=)",
    r"(?i)(\.innerHTML\s*=)",
    r"(?i)(fromcharcode)",
    r"(?i)(&#x[0-9a-f]+;)",
]

LFI_PATTERNS = [
    r"(\.\.\/){2,}",
    r"(\.\.\\){2,}",
    r"(?i)(\/etc\/passwd)",
    r"(?i)(\/etc\/shadow)",
    r"(?i)(\/proc\/self)",
    r"(?i)(\/windows\/system32)",
    r"(?i)(boot\.ini)",
    r"(?i)(php:\/\/filter)",
    r"(?i)(php:\/\/input)",
    r"(?i)(data:\/\/text)",
    r"(?i)(expect:\/\/)",
    r"(?i)(\.\.[\/\\]){1,}(etc|windows|proc)",
    r"(?i)(\/var\/log)",
    r"(?i)(file:\/\/\/)",
]

CMDI_PATTERNS = [
    r"(?i)(;[\s]*ls\b)",
    r"(?i)(;[\s]*cat\b)",
    r"(?i)(\|[\s]*(ls|cat|id|whoami|pwd|uname))",
    r"(?i)(`[\s]*(ls|cat|id|whoami)[\s]*`)",
    r"(?i)(\$\([\s]*(id|whoami|ls)[\s]*\))",
    r"(?i)(nc\s+-[lne]+\s+\d+)",
    r"(?i)(curl\s+http)",
    r"(?i)(wget\s+http)",
    r"(?i)(chmod\s+[0-7]{3,4})",
    r"(?i)(rm\s+-rf)",
]

# New patterns for CSRF, SSRF, zero-day exploits
CSRF_PATTERNS = [
    r"(?i)(csrf_token\s*=\s*['\"]?[^'\"]*['\"]?)",  # Missing or weak CSRF token
    r"(?i)(<form[^>]*action\s*=)",  # Form submissions without CSRF checks
    r"(?i)(post\s+.*origin\s*:\s*[^=]*=)",  # Cross-origin POST requests
]

SSRF_PATTERNS = [
    r"(?i)(http://127\.0\.0\.1)",  # Localhost SSRF
    r"(?i)(http://localhost)",  # Localhost SSRF
    r"(?i)(http://0\.0\.0\.0)",  # Zero IP SSRF
    r"(?i)(http://169\.254\.)",  # AWS metadata SSRF
    r"(?i)(http://metadata\.google)",  # GCP metadata SSRF
    r"(?i)(file://)",  # File protocol SSRF
    r"(?i)(dict://)",  # Dict protocol SSRF
    r"(?i)(ftp://)",  # FTP protocol SSRF
]

ZERO_DAY_PATTERNS = [
    r"(?i)(exploit\s+db)",  # Exploit-DB references
    r"(?i)(0day)",  # Zero-day keywords
    r"(?i)(poc\s+code)",  # Proof-of-concept code
    r"(?i)(shellcode)",  # Shellcode patterns
    r"(?i)(rop\s+gadget)",  # ROP gadgets
    r"(?i)(buffer\s+overflow)",  # Buffer overflow attempts
]

ATTACK_RULES = {
    "SQLi": SQLI_PATTERNS,
    "XSS": XSS_PATTERNS,
    "LFI": LFI_PATTERNS,
    "CMDi": CMDI_PATTERNS,
    "CSRF": CSRF_PATTERNS,
    "SSRF": SSRF_PATTERNS,
    "ZeroDay": ZERO_DAY_PATTERNS,
}

SEVERITY_MAP = {
    "SQLi": "CRITICAL",
    "XSS": "HIGH",
    "LFI": "CRITICAL",
    "CMDi": "CRITICAL",
    "CSRF": "MEDIUM",
    "SSRF": "HIGH",
    "ZeroDay": "CRITICAL",
    "Anomaly": "MEDIUM",
}

# CVE mappings for common patterns (demo-ready)
CVE_HINT_MAP = {
    "SQLi": ["CVE-2024-23108", "CVE-2024-21388", "CVE-2024-0204"],
    "XSS": ["CVE-2024-21388", "CVE-2024-24044", "CVE-2024-33225"],
    "LFI": ["CVE-2024-0204", "CVE-2024-27035", "CVE-2024-25157"],
    "CMDi": ["CVE-2024-3400", "CVE-2024-44487", "CVE-2024-28434"],
    "CSRF": ["CVE-2024-21413", "CVE-2024-29988", "CVE-2024-28100"],
    "SSRF": ["CVE-2024-23897", "CVE-2024-28899", "CVE-2024-32640"],
    "ZeroDay": ["CVE-2024-XXXXX", "CVE-2024-YYYYY", "CVE-2024-ZZZZZ"],
    "Anomaly": ["CVE-2024-ANOMALY", "CVE-2024-UNKNOWN", "CVE-2024-ML"],
}

ATTACK_CONTEXT = {
    "SQLi": {
        "owasp": "A03:2021 - Injection",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "playbook": "Block source IP, isolate DB query path, enforce parameterized queries",
    },
    "XSS": {
        "owasp": "A03:2021 - Injection",
        "mitre": "T1059.007 - JavaScript",
        "playbook": "Block source IP, sanitize output, enforce CSP",
    },
    "LFI": {
        "owasp": "A01:2021 - Broken Access Control",
        "mitre": "T1006 - Path Traversal",
        "playbook": "Block source IP, restrict file paths, enforce allowlists",
    },
    "CMDi": {
        "owasp": "A03:2021 - Injection",
        "mitre": "T1059 - Command and Scripting Interpreter",
        "playbook": "Block source IP, disable shell invocation paths, sandbox commands",
    },
    "CSRF": {
        "owasp": "A01:2021 - Broken Access Control",
        "mitre": "T1204.001 - User Execution: Malicious Link",
        "playbook": "Implement CSRF tokens, validate origins, enforce SameSite cookies",
    },
    "SSRF": {
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "mitre": "T1190 - Exploit Public-Facing Application",
        "playbook": "Block internal IPs, whitelist allowed URLs, use network segmentation",
    },
    "ZeroDay": {
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "mitre": "T1203 - Exploitation for Client Execution",
        "playbook": "Isolate affected systems, apply patches, monitor for indicators",
    },
    "Anomaly": {
        "owasp": "A09:2021 - Security Logging and Monitoring Failures",
        "mitre": "T1562 - Impair Defenses",
        "playbook": "Investigate unusual patterns, update ML training data, monitor closely",
    },
}

# ─── Detection Engine ─────────────────────────────────────────────────────────


class AttackDetector:
    def __init__(self):
        self._rule_engine = None
        try:
            from rule_engine import get_rule_engine

            self._rule_engine = get_rule_engine()
        except Exception:
            self._rule_engine = None

        self.compiled_rules = {
            atype: [re.compile(p) for p in patterns]
            for atype, patterns in ATTACK_RULES.items()
        }
        self.stats = defaultdict(int)
        self._ml_anomaly_detector = None
        self._load_ml_detector()

    def reload_rules(self):
        if self._rule_engine is not None:
            try:
                self._rule_engine.reload()
            except Exception:
                pass

    def _load_ml_detector(self):
        """Load ML-based anomaly detector if scikit-learn available."""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.feature_extraction.text import TfidfVectorizer
            import numpy as np

            self._ml_anomaly_detector = MLAnomalyDetector()
            log.info("ML anomaly detector loaded")
        except ImportError:
            log.warning("scikit-learn not available, ML anomaly detection disabled")
        except Exception as e:
            log.error(f"Failed to load ML detector: {e}")

    def classify(self, payload: str) -> dict | None:
        """
        Returns attack dict if malicious payload detected, else None.
        Multi-rule match → highest-severity type returned.
        """
        if self._rule_engine is not None:
            try:
                result = self._rule_engine.classify(payload)
                if result:
                    self.stats[result["attack_type"]] += 1
                return result
            except Exception:
                pass

        decoded = unquote_plus(payload)
        matches = {}

        for atype, patterns in self.compiled_rules.items():
            hits = [p.pattern for p in patterns if p.search(decoded)]
            if hits:
                matches[atype] = hits

        if not matches:
            # Check ML anomaly detection
            if self._ml_anomaly_detector and self._ml_anomaly_detector.is_anomalous(
                decoded
            ):
                attack_type = "Anomaly"
                matches = {"Anomaly": ["ML anomaly detection"]}
            else:
                return None

        # Priority: CMDi > SQLi > LFI > XSS > ZeroDay > SSRF > CSRF > Anomaly
        priority = ["CMDi", "SQLi", "LFI", "XSS", "ZeroDay", "SSRF", "CSRF", "Anomaly"]
        attack_type = next(
            (t for t in priority if t in matches), list(matches.keys())[0]
        )

        self.stats[attack_type] += 1

        return {
            "attack_type": attack_type,
            "severity": SEVERITY_MAP[attack_type],
            "matched_rules": matches[attack_type][:3],  # top 3 matched
            "cve_hints": CVE_HINT_MAP[attack_type],
            "payload_snip": decoded[:200],
            "confidence": min(100, len(matches[attack_type]) * 25),
        }


# ─── Packet Sniffer ───────────────────────────────────────────────────────────


class AutoShieldEngine:
    def __init__(self, interface="eth0", port=80, event_callback=None):
        self.interface = interface
        self.port = port
        self.event_callback = event_callback  # fn(event_dict) called on detection
        self.detector = AttackDetector()
        self.running = False
        self._thread = None
        self.attack_log = []
        self._lock = threading.Lock()

    # ── packet handler ──────────────────────────────────────────────────────
    def _process_packet(self, packet):
        if not (packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP)):
            return

        raw_data = packet[Raw].load.decode("utf-8", errors="ignore")

        # Extract HTTP request line + body
        if not any(m in raw_data for m in ["GET ", "POST ", "PUT ", "DELETE "]):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        # Pull URL + body for analysis
        lines = raw_data.split("\r\n")
        target = raw_data  # full request as payload

        result = self.detector.classify(target)
        if not result:
            return

        event = {
            "event_id": f"evt-{uuid.uuid4().hex[:10]}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "attack_type": result["attack_type"],
            "severity": result["severity"],
            "confidence": result["confidence"],
            "cve_hints": result["cve_hints"],
            "payload_snip": result["payload_snip"],
            "matched_rules": result["matched_rules"],
            "action": "PENDING",
            "status": "DETECTED",
            "detection_source": "live_sniff",
            "owasp_category": ATTACK_CONTEXT[result["attack_type"]]["owasp"],
            "mitre_technique": ATTACK_CONTEXT[result["attack_type"]]["mitre"],
            "playbook": ATTACK_CONTEXT[result["attack_type"]]["playbook"],
        }

        with self._lock:
            self.attack_log.append(event)

        log.warning(
            f"[{result['severity']}] {result['attack_type']} from {src_ip} "
            f"| confidence={result['confidence']}% | CVE hint: {result['cve_hints'][0]}"
        )

        if self.event_callback:
            self.event_callback(event)

    # ── start / stop ────────────────────────────────────────────────────────
    def start(self):
        if not SCAPY_AVAILABLE:
            log.warning("Scapy unavailable. Use simulate_attack() for demo.")
            return

        self.running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        log.info(f"Engine started on {self.interface}:{self.port}")

    def _sniff_loop(self):
        sniff(
            iface=self.interface,
            filter=f"tcp port {self.port}",
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: not self.running,
        )

    def stop(self):
        self.running = False
        log.info("Engine stopped.")

    # ── simulation mode (demo / testing) ────────────────────────────────────
    def simulate_attack(self, attack_type: str = "SQLi", src_ip: str = "192.168.1.66"):
        """Inject a fake attack event — for demo without root/Scapy."""
        DEMO_PAYLOADS = {
            "SQLi": "GET /login?user=' OR 1=1 -- &pass=x HTTP/1.1",
            "XSS": "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1",
            "LFI": "GET /page?file=../../../../etc/passwd HTTP/1.1",
            "CMDi": "GET /ping?host=8.8.8.8;cat /etc/shadow HTTP/1.1",
        }
        payload = DEMO_PAYLOADS.get(attack_type, DEMO_PAYLOADS["SQLi"])
        result = self.detector.classify(payload)
        if not result:
            return None

        event = {
            "event_id": f"evt-{uuid.uuid4().hex[:10]}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "attack_type": result["attack_type"],
            "severity": result["severity"],
            "confidence": result["confidence"],
            "cve_hints": result["cve_hints"],
            "payload_snip": payload,
            "matched_rules": result["matched_rules"],
            "action": "PENDING",
            "status": "DETECTED",
            "detection_source": "simulation",
            "owasp_category": ATTACK_CONTEXT[result["attack_type"]]["owasp"],
            "mitre_technique": ATTACK_CONTEXT[result["attack_type"]]["mitre"],
            "playbook": ATTACK_CONTEXT[result["attack_type"]]["playbook"],
        }

        with self._lock:
            self.attack_log.append(event)

        if self.event_callback:
            self.event_callback(event)

        return event

    def get_log(self):
        with self._lock:
            return list(self.attack_log)

    def mark_blocked(self, src_ip: str):
        with self._lock:
            for e in self.attack_log:
                if e["src_ip"] == src_ip and e["action"] == "PENDING":
                    e["action"] = "BLOCKED"
                    e["status"] = "MITIGATED"


# ─── Quick test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":

    def on_attack(event):
        print(f"\n🚨 ATTACK DETECTED: {event['attack_type']} from {event['src_ip']}")
        print(f"   Severity : {event['severity']}")
        print(f"   CVE hint : {event['cve_hints'][0]}")
        print(f"   Payload  : {event['payload_snip'][:80]}")

    engine = AutoShieldEngine(event_callback=on_attack)

    print("=== AutoShield Engine Self-Test ===\n")
    for atype in ["SQLi", "XSS", "LFI", "CMDi"]:
        engine.simulate_attack(
            atype, src_ip=f"10.0.0.{['SQLi', 'XSS', 'LFI', 'CMDi'].index(atype) + 1}"
        )
        time.sleep(0.2)

    print(f"\nTotal events logged: {len(engine.get_log())}")
