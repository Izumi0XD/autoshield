"""
AutoShield — Configurable Rule Engine
Loads detection rules from:
  1. Database (admin-managed, hot-reloadable)
  2. YAML rule files (version-controlled, portable)
  3. Threat intelligence feeds (auto-updated)

Rule format (YAML):
    rules:
      - id: r_sqli_001
        name: "SQLi - UNION SELECT"
        attack_type: SQLi
        pattern: "(?i)(union\\s+select)"
        severity: CRITICAL
        confidence: 100
        tags: [owasp-a03, cwe-89]
        description: "UNION-based SQL injection"
        cve_refs: ["CVE-2023-23752"]
        enabled: true
        priority: 100

Run:
    python rule_engine.py --validate rules/custom.yaml
    python rule_engine.py --test "GET /login?id=1 UNION SELECT * FROM users--"
"""

import re
import os
import json
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing  import Optional
from urllib.parse import unquote_plus

log = logging.getLogger("AutoShield.Rules")

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False
    log.warning("PyYAML not installed — YAML rule files disabled. pip install pyyaml")

import db as DB

RULES_DIR = Path(os.environ.get("AUTOSHIELD_RULES_DIR", "./rules"))

# ─── Rule object ──────────────────────────────────────────────────────────────

class Rule:
    __slots__ = ("id","name","attack_type","pattern","compiled","severity",
                 "confidence","tags","description","cve_refs","enabled","priority")

    def __init__(self, d: dict):
        self.id          = d["id"]
        self.name        = d.get("name",  d["id"])
        self.attack_type = d.get("attack_type","Custom")
        self.pattern     = d["pattern"]
        self.severity    = d.get("severity","HIGH")
        self.confidence  = int(d.get("confidence", d.get("priority",50)))
        self.tags        = d.get("tags",[])
        self.description = d.get("description","")
        self.cve_refs    = d.get("cve_refs", d.get("cve_hints",[]))
        self.enabled     = bool(d.get("enabled",True))
        self.priority    = int(d.get("priority",50))
        try:
            self.compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
        except re.error as e:
            log.error(f"Invalid regex in rule {self.id}: {e}")
            self.compiled = None

    def matches(self, text: str) -> bool:
        return bool(self.compiled and self.compiled.search(text))

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__ if k != "compiled"}


# ─── Rule engine ──────────────────────────────────────────────────────────────

class RuleEngine:
    """
    Thread-safe rule engine.
    Hot-reload rules without restart.
    """

    def __init__(self):
        self._rules:  dict[str, Rule] = {}    # id → Rule
        self._lock    = threading.RLock()
        self._version = 0
        self._load_from_db()
        self._load_from_yaml_dir()
        log.info(f"Rule engine loaded {len(self._rules)} rules (v{self._version})")

    # ── Loading ──────────────────────────────────────────────────────────────

    def _load_from_db(self):
        rows = DB.get_rules(enabled_only=False)
        with self._lock:
            for row in rows:
                try:
                    r = Rule({
                        "id":          row["id"],
                        "name":        row["name"],
                        "attack_type": row["attack_type"],
                        "pattern":     row["pattern"],
                        "severity":    row["severity"],
                        "confidence":  row["priority"],
                        "enabled":     bool(row["enabled"]),
                        "priority":    row["priority"],
                        "description": row.get("description",""),
                    })
                    self._rules[r.id] = r
                except Exception as e:
                    log.error(f"Bad rule from DB {row.get('id')}: {e}")
        self._version += 1

    def _load_from_yaml_dir(self):
        if not YAML_OK or not RULES_DIR.exists(): return
        for f in RULES_DIR.glob("*.yaml"):
            self._load_yaml_file(f)
        for f in RULES_DIR.glob("*.yml"):
            self._load_yaml_file(f)

    def _load_yaml_file(self, path: Path):
        if not YAML_OK: return
        try:
            data = yaml.safe_load(path.read_text())
            rules_data = data.get("rules", []) if isinstance(data,dict) else data
            added = 0
            with self._lock:
                for rd in rules_data:
                    try:
                        r = Rule(rd)
                        if r.enabled:
                            self._rules[r.id] = r
                            added += 1
                    except Exception as e:
                        log.error(f"Bad rule in {path}: {e}")
            if added:
                log.info(f"Loaded {added} rules from {path.name}")
        except Exception as e:
            log.error(f"Failed to load rules from {path}: {e}")

    def reload(self):
        """Hot-reload all rules from DB + YAML files."""
        with self._lock:
            self._rules.clear()
        self._load_from_db()
        self._load_from_yaml_dir()
        log.info(f"Rules reloaded: {len(self._rules)} rules (v{self._version})")

    def add_rule(self, rule_dict: dict):
        with self._lock:
            r = Rule(rule_dict)
            self._rules[r.id] = r
            self._version += 1

    def toggle(self, rule_id: str, enabled: bool):
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id].enabled = enabled
                self._version += 1

    # ── Classification ───────────────────────────────────────────────────────

    def classify(self, payload: str) -> Optional[dict]:
        """
        Main classification entry point.
        Returns attack dict or None.
        Checks decoded variants (URL-encoded, HTML entities, double-encoded).
        """
        targets = _decode_variants(payload)
        all_matches: dict[str, list] = {}

        with self._lock:
            rules = [r for r in self._rules.values() if r.enabled and r.compiled]

        for r in rules:
            for t in targets:
                if r.matches(t):
                    if r.attack_type not in all_matches:
                        all_matches[r.attack_type] = []
                    all_matches[r.attack_type].append(r)
                    break   # one match per rule

        if not all_matches: return None

        # Priority: CMDi > SQLi > LFI > XSS > Custom
        priority_order = ["CMDi","SQLi","LFI","XSS","Custom"]
        attack_type = next(
            (t for t in priority_order if t in all_matches),
            list(all_matches.keys())[0]
        )

        matched_rules = all_matches[attack_type]
        matched_rules.sort(key=lambda r: r.priority, reverse=True)

        # Aggregate confidence (more matches = higher confidence, cap 100)
        confidence = min(100, sum(r.confidence for r in matched_rules[:3]) // 3 * 2)
        confidence = max(confidence, matched_rules[0].confidence // 2)

        # Highest severity among matched rules
        sev_order = ["CRITICAL","HIGH","MEDIUM","LOW"]
        severity  = next(
            (s for s in sev_order if any(r.severity==s for r in matched_rules)),
            "HIGH"
        )

        # Collect CVE refs
        cve_hints = []
        for r in matched_rules:
            cve_hints.extend(r.cve_refs)
        cve_hints = list(dict.fromkeys(cve_hints))[:5]   # dedup, max 5

        # Fall back to built-in CVE hints if no refs in rules
        if not cve_hints:
            cve_hints = _BUILTIN_CVE.get(attack_type, [])

        return {
            "attack_type":   attack_type,
            "severity":      severity,
            "confidence":    confidence,
            "matched_rules": [r.name for r in matched_rules[:5]],
            "cve_hints":     cve_hints,
            "payload_snip":  payload[:300],
            "all_matches":   {t: [r.id for r in rs] for t,rs in all_matches.items()},
        }

    def get_all_rules(self) -> list[dict]:
        with self._lock:
            return [r.to_dict() for r in self._rules.values()]

    def rule_count(self) -> int:
        with self._lock:
            return len([r for r in self._rules.values() if r.enabled])

    def version(self) -> int:
        return self._version

    def test_against_all(self, payload: str) -> list[dict]:
        """Test payload against ALL rules, return all matches (for rule testing UI)."""
        targets = _decode_variants(payload)
        hits    = []
        with self._lock:
            for r in self._rules.values():
                if not r.enabled or not r.compiled: continue
                for t in targets:
                    if r.matches(t):
                        hits.append({**r.to_dict(), "matched_variant": t[:100]})
                        break
        hits.sort(key=lambda x: x["priority"], reverse=True)
        return hits


# ─── Decode variants (WAF evasion detection) ──────────────────────────────────

def _decode_variants(payload: str) -> list[str]:
    """Return multiple decode levels to catch obfuscated attacks."""
    variants = {payload}
    try: variants.add(unquote_plus(payload))
    except Exception: pass
    try: variants.add(unquote_plus(unquote_plus(payload)))   # double-encoded
    except Exception: pass
    # HTML entity decode
    try:
        import html
        variants.add(html.unescape(payload))
    except Exception: pass
    # Base64 fragments
    import base64
    for part in payload.split():
        try:
            dec = base64.b64decode(part + "==").decode("utf-8","ignore")
            if dec and len(dec) > 4: variants.add(dec)
        except Exception: pass
    return list(variants)


# ─── Built-in CVE hints ───────────────────────────────────────────────────────

_BUILTIN_CVE = {
    "SQLi": ["CVE-2023-23752","CVE-2023-28343","CVE-2022-24816"],
    "XSS":  ["CVE-2023-32315","CVE-2023-33225","CVE-2023-24044"],
    "LFI":  ["CVE-2023-29489","CVE-2023-27035","CVE-2023-25157"],
    "CMDi": ["CVE-2023-46604","CVE-2023-44487","CVE-2023-28434"],
}


# ─── YAML rule file writer ────────────────────────────────────────────────────

def export_rules_yaml(output_path: str = "rules/exported.yaml"):
    """Export DB rules to YAML file (for version control)."""
    if not YAML_OK:
        log.error("PyYAML required for export: pip install pyyaml")
        return
    rules = DB.get_rules(enabled_only=False)
    out   = {"rules": rules, "exported_at": datetime.now().isoformat()}
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path,"w") as f:
        yaml.dump(out, f, default_flow_style=False, sort_keys=False)
    log.info(f"Exported {len(rules)} rules to {output_path}")


def validate_yaml_rules(path: str) -> tuple[bool, list]:
    """Validate a YAML rule file. Returns (valid, errors)."""
    if not YAML_OK:
        return False, ["PyYAML not installed"]
    errors = []
    try:
        data = yaml.safe_load(Path(path).read_text())
        rules_data = data.get("rules",[]) if isinstance(data,dict) else data
        for rd in rules_data:
            try: Rule(rd)
            except Exception as e:
                errors.append(f"Rule {rd.get('id','?')}: {e}")
    except Exception as e:
        return False, [str(e)]
    return len(errors)==0, errors


# ─── Singleton ────────────────────────────────────────────────────────────────

_engine: Optional[RuleEngine] = None
_lock   = threading.Lock()

def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                _engine = RuleEngine()
    return _engine


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, sys
    DB.init_db()

    parser = argparse.ArgumentParser(description="AutoShield Rule Engine")
    parser.add_argument("--validate", metavar="YAML_FILE",
                        help="Validate a YAML rule file")
    parser.add_argument("--test",     metavar="PAYLOAD",
                        help="Test a payload against all rules")
    parser.add_argument("--export",   metavar="OUTPUT",
                        help="Export DB rules to YAML file")
    parser.add_argument("--list",     action="store_true",
                        help="List all rules")
    args = parser.parse_args()

    eng = get_rule_engine()

    if args.validate:
        ok, errs = validate_yaml_rules(args.validate)
        print(f"Valid: {ok}")
        for e in errs: print(f"  ERROR: {e}")
        sys.exit(0 if ok else 1)

    if args.test:
        result = eng.classify(args.test)
        if result:
            print(f"DETECTED: {result['attack_type']} [{result['severity']}]")
            print(f"Confidence: {result['confidence']}%")
            print(f"Matched rules: {result['matched_rules']}")
            print(f"CVE hints: {result['cve_hints']}")
        else:
            print("CLEAN — no threats detected")

        print("\nAll matches:")
        for m in eng.test_against_all(args.test):
            print(f"  [{m['severity']}] {m['name']} ({m['attack_type']})")
        sys.exit(0)

    if args.export:
        export_rules_yaml(args.export)
        sys.exit(0)

    if args.list:
        for r in eng.get_all_rules():
            status = "ON " if r["enabled"] else "OFF"
            print(f"  [{status}] [{r['severity']:8}] {r['id']:25} {r['name']}")
        print(f"\nTotal: {eng.rule_count()} enabled rules")
        sys.exit(0)

    parser.print_help()