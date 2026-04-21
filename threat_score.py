"""
AutoShield - Threat Score Engine
Computes 0-100 threat score per IP using feature engineering + ML heuristics.
No training data needed — rule-based scoring with ML-style feature weighting.
"""

import math
import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta

log = logging.getLogger("AutoShield.ThreatScore")

# ─── Feature weights (simulate trained model coefficients) ────────────────────

WEIGHTS = {
    "attack_count":         0.25,   # raw volume
    "attack_diversity":     0.20,   # how many different attack types
    "severity_score":       0.20,   # weighted severity
    "time_density":         0.15,   # attacks per minute
    "repeat_offender":      0.10,   # seen in previous sessions
    "payload_sophistication": 0.10, # match count per attack
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH":     7,
    "MEDIUM":   4,
    "LOW":      1,
}

ATTACK_TYPE_RISK = {
    "CMDi": 1.0,
    "SQLi": 0.95,
    "LFI":  0.90,
    "XSS":  0.70,
}

# ─── Per-IP state ─────────────────────────────────────────────────────────────

class IPProfile:
    def __init__(self, ip: str):
        self.ip              = ip
        self.events: list    = []
        self.first_seen      = datetime.now()
        self.last_seen       = datetime.now()
        self.threat_score    = 0
        self.threat_label    = "CLEAN"
        self.seen_previously = False

    def add_event(self, event: dict):
        self.events.append(event)
        self.last_seen = datetime.now()

    def to_dict(self) -> dict:
        return {
            "ip":           self.ip,
            "threat_score": self.threat_score,
            "threat_label": self.threat_label,
            "attack_count": len(self.events),
            "attack_types": list({e.get("attack_type","?") for e in self.events}),
            "first_seen":   self.first_seen.isoformat(),
            "last_seen":    self.last_seen.isoformat(),
            "worst_severity": self._worst_severity(),
        }

    def _worst_severity(self) -> str:
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            if any(e.get("severity") == sev for e in self.events):
                return sev
        return "UNKNOWN"


# ─── Threat Score Engine ──────────────────────────────────────────────────────

class ThreatScoreEngine:
    def __init__(self):
        self._profiles: dict[str, IPProfile] = {}
        self._global_ip_history: set          = set()   # IPs seen across sessions

    def ingest(self, event: dict) -> dict:
        """
        Process new attack event → update IP profile → recalculate score.
        Returns updated profile dict.
        """
        ip = event.get("src_ip", "0.0.0.0")
        if ip not in self._profiles:
            self._profiles[ip] = IPProfile(ip)
        profile = self._profiles[ip]

        # Mark repeat offender if seen before
        if ip in self._global_ip_history:
            profile.seen_previously = True
        self._global_ip_history.add(ip)

        profile.add_event(event)
        profile.threat_score = self._calculate_score(profile)
        profile.threat_label = self._label(profile.threat_score)

        return profile.to_dict()

    def _calculate_score(self, profile: IPProfile, apply_decay: bool = True) -> int:
        """
        Feature engineering → weighted score → sigmoid normalize to 0-100.
        """
        events = profile.events
        n      = len(events)
        if n == 0:
            return 0

        # F1: Attack count (log scale, saturates at ~20 attacks)
        f_count = min(math.log1p(n) / math.log1p(20), 1.0)

        # F2: Attack diversity (how many different types, max 4)
        types   = {e.get("attack_type","?") for e in events}
        f_div   = len(types) / 4.0

        # F3: Severity score (weighted average normalized to 0-1)
        sev_total = sum(
            SEVERITY_WEIGHTS.get(e.get("severity","LOW"), 1)
            for e in events
        )
        sev_max = SEVERITY_WEIGHTS["CRITICAL"] * n
        f_sev   = min(sev_total / max(sev_max, 1), 1.0)

        # F4: Time density — attacks per minute in the last 5 minutes
        now  = datetime.now()
        window_start = now - timedelta(minutes=5)
        recent = [
            e for e in events
            if datetime.fromisoformat(e.get("timestamp", now.isoformat())) > window_start
        ]
        density = len(recent) / 5.0   # attacks per minute
        f_density = min(density / 3.0, 1.0)   # saturates at 3 attacks/min

        # F5: Repeat offender
        f_repeat = 1.0 if profile.seen_previously else 0.0

        # F6: Payload sophistication (avg match count per event)
        match_counts = [len(e.get("matched_rules", [])) for e in events]
        avg_matches  = sum(match_counts) / max(len(match_counts), 1)
        f_sophist    = min(avg_matches / 5.0, 1.0)

        # F7: Attack type risk multiplier
        type_risks = [ATTACK_TYPE_RISK.get(e.get("attack_type","XSS"), 0.5) for e in events]
        f_type_risk = sum(type_risks) / max(len(type_risks), 1)

        # Weighted sum
        raw_score = (
            WEIGHTS["attack_count"]          * f_count    +
            WEIGHTS["attack_diversity"]      * f_div      +
            WEIGHTS["severity_score"]        * f_sev      +
            WEIGHTS["time_density"]          * f_density  +
            WEIGHTS["repeat_offender"]       * f_repeat   +
            WEIGHTS["payload_sophistication"]* f_sophist
        )

        # Apply type risk multiplier
        raw_score = raw_score * (0.5 + 0.5 * f_type_risk)

        # Sigmoid-ish normalization to 0-100
        score = int(raw_score * 100)

        # Apply time-based decay if requested
        if apply_decay:
            # Half-life of 5 minutes (300 seconds)
            seconds_since_last = (datetime.now() - profile.last_seen).total_seconds()
            decay_factor = math.pow(0.5, seconds_since_last / 300.0)
            score = int(score * decay_factor)

        return min(score, 100)

    @staticmethod
    def _label(score: int) -> str:
        if score >= 80: return "CRITICAL THREAT"
        if score >= 60: return "HIGH THREAT"
        if score >= 40: return "MEDIUM THREAT"
        if score >= 20: return "LOW THREAT"
        return "CLEAN"

    def get_decayed_score(self, ip: str) -> int:
        """Fetch the current threat score for an IP adjusted for time decay."""
        if ip not in self._profiles:
            return 0
        profile = self._profiles[ip]
        score = self._calculate_score(profile, apply_decay=True)
        # Update cached score in profile
        profile.threat_score = score
        profile.threat_label = self._label(score)
        return score

    def get_profile(self, ip: str) -> dict | None:
        if ip not in self._profiles:
            return None
        return self._profiles[ip].to_dict()

    def get_all_profiles(self, min_score: int = 0) -> list[dict]:
        profiles = [
            p.to_dict() for p in self._profiles.values()
            if p.threat_score >= min_score
        ]
        return sorted(profiles, key=lambda x: x["threat_score"], reverse=True)

    def get_top_threats(self, n: int = 5) -> list[dict]:
        return self.get_all_profiles()[:n]

    def score_bar(self, score: int, width: int = 20) -> str:
        """ASCII bar for terminal display."""
        filled = int(score / 100 * width)
        bar    = "█" * filled + "░" * (width - filled)
        color_prefix = ""
        if score >= 80:   color_prefix = "\033[91m"
        elif score >= 60: color_prefix = "\033[93m"
        elif score >= 40: color_prefix = "\033[94m"
        return f"{color_prefix}[{bar}]\033[0m {score:3d}/100"


# ─── Singleton ────────────────────────────────────────────────────────────────

_engine: ThreatScoreEngine | None = None

def get_threat_engine() -> ThreatScoreEngine:
    global _engine
    if _engine is None:
        _engine = ThreatScoreEngine()
    return _engine


# ─── Self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from datetime import datetime

    engine = ThreatScoreEngine()
    print("=== Threat Score Engine Self-Test ===\n")

    TEST_SEQUENCES = [
        # Persistent SQLi attacker
        [("10.0.0.1", "SQLi",  "CRITICAL", 3),
         ("10.0.0.1", "SQLi",  "CRITICAL", 3),
         ("10.0.0.1", "LFI",   "CRITICAL", 2),
         ("10.0.0.1", "CMDi",  "CRITICAL", 3)],
        # Single XSS probe
        [("10.0.0.2", "XSS",   "HIGH",     2)],
        # Mixed low-confidence
        [("10.0.0.3", "SQLi",  "HIGH",     1),
         ("10.0.0.3", "XSS",   "MEDIUM",   1)],
        # Aggressive multi-vector
        [("10.0.0.4", "CMDi",  "CRITICAL", 5),
         ("10.0.0.4", "SQLi",  "CRITICAL", 4),
         ("10.0.0.4", "LFI",   "CRITICAL", 3),
         ("10.0.0.4", "XSS",   "HIGH",     2),
         ("10.0.0.4", "CMDi",  "CRITICAL", 4)],
    ]

    for seq in TEST_SEQUENCES:
        for ip, atype, severity, matches in seq:
            event = {
                "src_ip":       ip,
                "attack_type":  atype,
                "severity":     severity,
                "matched_rules": ["rule"] * matches,
                "timestamp":    datetime.now().isoformat(),
            }
            profile = engine.ingest(event)

    print("Top threats:")
    for p in engine.get_top_threats(5):
        bar   = engine.score_bar(p["threat_score"])
        label = p["threat_label"]
        print(f"  {p['ip']:<14} {bar}  {label:<20} types={p['attack_types']}")

    print()
    print(f"Total IPs tracked: {len(engine.get_all_profiles())}")
