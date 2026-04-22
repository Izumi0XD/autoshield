"""
AutoShield — Persistent Storage Layer
Supports SQLite (dev) and PostgreSQL (production).
"""

import os
import re
import json
import hashlib
import secrets
import time
import threading
import logging
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager
from typing import Optional

log = logging.getLogger("AutoShield.DB")

DB_PATH = Path(os.environ.get("AUTOSHIELD_DB", "autoshield.db"))
_DB_URL = os.environ.get("DATABASE_URL", "").strip()
_USE_PG = _DB_URL.startswith("postgresql") or _DB_URL.startswith("postgres")

if _USE_PG:
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool

    log.info("Using PostgreSQL backend: %s", _DB_URL.split("@")[-1])
    _pg_pool = None
    _pg_pool_lock = threading.Lock()

    def _get_pg_pool():
        global _pg_pool
        if _pg_pool is None:
            with _pg_pool_lock:
                if _pg_pool is None:
                    _pg_pool = psycopg2.pool.ThreadedConnectionPool(
                        minconn=2, maxconn=20, dsn=_DB_URL
                    )
        return _pg_pool
else:
    import sqlite3

    log.info("Using SQLite backend: %s", DB_PATH)


# ─── PG compatibility layer ───────────────────────────────────────────────────


def _pg_adapt(sql: str) -> str:
    """Convert SQLite SQL dialect to PostgreSQL."""
    # Placeholder
    sql = sql.replace("?", "%s")
    # Upsert
    is_ignore = bool(re.search(r"\bINSERT OR IGNORE\b", sql, re.I))
    is_replace = bool(re.search(r"\bINSERT OR REPLACE\b", sql, re.I))
    sql = re.sub(r"\bINSERT OR IGNORE\b", "INSERT", sql, flags=re.I)
    sql = re.sub(r"\bINSERT OR REPLACE\b", "INSERT", sql, flags=re.I)
    if (is_ignore or is_replace) and "ON CONFLICT" not in sql.upper():
        sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    # Auto-increment
    sql = re.sub(
        r"\bINTEGER PRIMARY KEY AUTOINCREMENT\b", "SERIAL PRIMARY KEY", sql, flags=re.I
    )
    # Boolean
    sql = re.sub(r"\bINTEGER DEFAULT 1\b", "BOOLEAN DEFAULT true", sql, flags=re.I)
    sql = re.sub(r"\bINTEGER DEFAULT 0\b", "BOOLEAN DEFAULT false", sql, flags=re.I)
    return sql


def _split_sql(script: str):
    """Split SQL script into individual statements."""
    stmts = []
    buf = []
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("--") or not stripped:
            continue
        buf.append(line)
        if stripped.endswith(";"):
            stmts.append("\n".join(buf))
            buf = []
    if buf:
        stmts.append("\n".join(buf))
    return stmts


class _PGResult:
    """Mimics sqlite3 Cursor enough for our codebase."""

    def __init__(self, cur):
        self._cur = cur
        self._lastrowid = None
        if cur.rowcount > 0:
            try:
                val = cur.fetchone()
                if val:
                    self._lastrowid = list(dict(val).values())[0]
                    return
            except Exception:
                pass
            try:
                cur.execute("SELECT lastval()")
                row = cur.fetchone()
                if row:
                    self._lastrowid = list(dict(row).values())[0]
            except Exception:
                pass

    @property
    def lastrowid(self):
        return self._lastrowid

    @property
    def rowcount(self):
        return self._cur.rowcount

    def fetchone(self):
        row = self._cur.fetchone()
        return dict(row) if row else None

    def fetchall(self):
        rows = self._cur.fetchall()
        return [dict(r) for r in rows]

    def __getitem__(self, key):
        return self.fetchone()[key]


class _PGConn:
    """Thin wrapper making psycopg2 look like sqlite3 for our code."""

    def __init__(self, raw_conn):
        self._conn = raw_conn
        self._cur = raw_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def execute(self, sql: str, params=()):
        sql = _pg_adapt(sql)
        # Append RETURNING id for INSERT statements so lastrowid works
        if re.match(r"\s*INSERT\s", sql, re.I) and "RETURNING" not in sql.upper():
            sql = sql.rstrip().rstrip(";") + " RETURNING id"
        try:
            self._cur.execute(sql, list(params) if params else None)
        except psycopg2.errors.UniqueViolation:
            self._conn.rollback()
            return _PGResult(self._cur)
        return _PGResult(self._cur)

    def executescript(self, script: str):
        """Run DDL init script."""
        old_ac = self._conn.autocommit
        self._conn.autocommit = True
        for stmt in _split_sql(script):
            stmt = _pg_adapt(stmt)
            if not stmt.strip():
                continue
            try:
                self._cur.execute(stmt)
            except Exception as e:
                if "already exists" not in str(e).lower():
                    log.debug("DDL skip: %s — %.80s", e, stmt)
        self._conn.autocommit = old_ac

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._cur.close()


# ─── Context manager ──────────────────────────────────────────────────────────


@contextmanager
def db():
    """Yield a DB connection. Commits on success, rolls back on error."""
    if _USE_PG:
        pool = _get_pg_pool()
        raw = pool.getconn()
        raw.autocommit = False
        conn = _PGConn(raw)
        try:
            yield conn
            raw.commit()
        except Exception:
            raw.rollback()
            raise
        finally:
            conn.close()
            pool.putconn(raw)
    else:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        raw = sqlite3.connect(str(DB_PATH))
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("PRAGMA foreign_keys=ON")
        try:
            yield raw
            raw.commit()
        except Exception:
            raw.rollback()
            raise
        finally:
            raw.close()


# ─── Schema ───────────────────────────────────────────────────────────────────

SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS sites (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    domain      TEXT NOT NULL,
    api_key     TEXT UNIQUE NOT NULL,
    plan        TEXT DEFAULT 'free',
    created_at  TEXT NOT NULL,
    config      TEXT DEFAULT '{}',
    upstream_url TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    site_id       TEXT REFERENCES sites(id),
    last_login    TEXT,
    created_at    TEXT NOT NULL,
    active        INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS user_sites (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_id    TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    role       TEXT DEFAULT 'owner',
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, site_id)
);
CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id          TEXT REFERENCES sites(id),
    timestamp        TEXT NOT NULL,
    src_ip           TEXT NOT NULL,
    dst_ip           TEXT,
    dst_port         INTEGER,
    attack_type      TEXT NOT NULL,
    severity         TEXT NOT NULL,
    confidence       INTEGER,
    payload_snip     TEXT,
    matched_rules    TEXT,
    cve_hints        TEXT,
    action           TEXT DEFAULT 'PENDING',
    status           TEXT DEFAULT 'DETECTED',
    sanitization     TEXT,
    raw_headers      TEXT,
    geo_country      TEXT,
    geo_city         TEXT,
    geo_isp          TEXT,
    ingestion_source TEXT DEFAULT 'manual'
);
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip          TEXT PRIMARY KEY,
    site_id     TEXT REFERENCES sites(id),
    attack_type TEXT,
    severity    TEXT,
    reason      TEXT,
    method      TEXT DEFAULT 'in-memory',
    blocked_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    unblocked   INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip           TEXT PRIMARY KEY,
    threat_score INTEGER DEFAULT 0,
    threat_label TEXT DEFAULT 'CLEAN',
    attack_count INTEGER DEFAULT 0,
    attack_types TEXT DEFAULT '[]',
    first_seen   TEXT,
    last_seen    TEXT,
    country      TEXT,
    isp          TEXT,
    notes        TEXT
);
CREATE TABLE IF NOT EXISTS rules (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    attack_type          TEXT NOT NULL,
    pattern              TEXT NOT NULL,
    severity             TEXT DEFAULT 'HIGH',
    enabled              INTEGER DEFAULT 1,
    priority             INTEGER DEFAULT 50,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    created_by           TEXT,
    description          TEXT,
    false_positive_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webhooks (
    id            TEXT PRIMARY KEY,
    site_id       TEXT REFERENCES sites(id),
    name          TEXT NOT NULL,
    url           TEXT NOT NULL,
    secret        TEXT,
    events        TEXT DEFAULT '["CRITICAL","HIGH"]',
    enabled       INTEGER DEFAULT 1,
    last_fired    TEXT,
    failure_count INTEGER DEFAULT 0,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user      TEXT,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT,
    ip        TEXT,
    result    TEXT DEFAULT 'OK'
);
CREATE TABLE IF NOT EXISTS rate_state (
    ip           TEXT NOT NULL,
    window_start TEXT NOT NULL,
    count        INTEGER DEFAULT 0,
    PRIMARY KEY (ip, window_start)
);
CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key   TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    cached_at   TEXT NOT NULL,
    ttl_seconds INTEGER DEFAULT 3600
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    site_id    TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip         TEXT
);
CREATE TABLE IF NOT EXISTS site_telemetry (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id      TEXT REFERENCES sites(id),
    timestamp    TEXT NOT NULL,
    cpu_percent  REAL,
    mem_percent  REAL,
    disk_percent REAL,
    details      TEXT
);
CREATE TABLE IF NOT EXISTS site_audits (
    site_id        TEXT PRIMARY KEY REFERENCES sites(id),
    timestamp      TEXT NOT NULL,
    security_score INTEGER,
    ssl_status     TEXT,
    ssl_expiry     TEXT,
    headers        TEXT,
    audit_log      TEXT
);
CREATE TABLE IF NOT EXISTS activity_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT NOT NULL REFERENCES users(id),
    action_type TEXT NOT NULL,
    description TEXT NOT NULL,
    metadata    TEXT DEFAULT '{}',
    timestamp   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_site      ON events(site_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(attack_type);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_blocked_ip       ON blocked_ips(ip);
CREATE INDEX IF NOT EXISTS idx_blocked_expires  ON blocked_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_site   ON site_telemetry(site_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_user_sites_user  ON user_sites(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sites_site  ON user_sites(site_id);
CREATE INDEX IF NOT EXISTS idx_activity_user_timestamp ON activity_logs(user_id, timestamp DESC);
"""

SCHEMA_POSTGRESQL = """
CREATE TABLE IF NOT EXISTS sites (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    domain      TEXT NOT NULL,
    api_key     TEXT UNIQUE NOT NULL,
    plan        TEXT DEFAULT 'free',
    created_at  TEXT NOT NULL,
    config      TEXT DEFAULT '{}',
    upstream_url TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    site_id       TEXT REFERENCES sites(id),
    last_login    TEXT,
    created_at    TEXT NOT NULL,
    active        BOOLEAN DEFAULT true
);
CREATE TABLE IF NOT EXISTS user_sites (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_id    TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    role       TEXT DEFAULT 'owner',
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, site_id)
);
CREATE TABLE IF NOT EXISTS events (
    id               SERIAL PRIMARY KEY,
    site_id          TEXT REFERENCES sites(id),
    timestamp        TEXT NOT NULL,
    src_ip           TEXT NOT NULL,
    dst_ip           TEXT,
    dst_port         INTEGER,
    attack_type      TEXT NOT NULL,
    severity         TEXT NOT NULL,
    confidence       INTEGER,
    payload_snip     TEXT,
    matched_rules    TEXT,
    cve_hints        TEXT,
    action           TEXT DEFAULT 'PENDING',
    status           TEXT DEFAULT 'DETECTED',
    sanitization     TEXT,
    raw_headers      TEXT,
    geo_country      TEXT,
    geo_city         TEXT,
    geo_isp          TEXT,
    ingestion_source TEXT DEFAULT 'manual'
);
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip          TEXT PRIMARY KEY,
    site_id     TEXT REFERENCES sites(id),
    attack_type TEXT,
    severity    TEXT,
    reason      TEXT,
    method      TEXT DEFAULT 'in-memory',
    blocked_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    unblocked   BOOLEAN DEFAULT false
);
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip           TEXT PRIMARY KEY,
    threat_score INTEGER DEFAULT 0,
    threat_label TEXT DEFAULT 'CLEAN',
    attack_count INTEGER DEFAULT 0,
    attack_types TEXT DEFAULT '[]',
    first_seen   TEXT,
    last_seen    TEXT,
    country      TEXT,
    isp          TEXT,
    notes        TEXT
);
CREATE TABLE IF NOT EXISTS rules (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    attack_type          TEXT NOT NULL,
    pattern              TEXT NOT NULL,
    severity             TEXT DEFAULT 'HIGH',
    enabled              BOOLEAN DEFAULT true,
    priority             INTEGER DEFAULT 50,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    created_by           TEXT,
    description          TEXT,
    false_positive_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webhooks (
    id            TEXT PRIMARY KEY,
    site_id       TEXT REFERENCES sites(id),
    name          TEXT NOT NULL,
    url           TEXT NOT NULL,
    secret        TEXT,
    events        TEXT DEFAULT '["CRITICAL","HIGH"]',
    enabled       BOOLEAN DEFAULT true,
    last_fired    TEXT,
    failure_count INTEGER DEFAULT 0,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id        SERIAL PRIMARY KEY,
    timestamp TEXT NOT NULL,
    user      TEXT,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT,
    ip        TEXT,
    result    TEXT DEFAULT 'OK'
);
CREATE TABLE IF NOT EXISTS rate_state (
    ip           TEXT NOT NULL,
    window_start TEXT NOT NULL,
    count        INTEGER DEFAULT 0,
    PRIMARY KEY (ip, window_start)
);
CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key   TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    cached_at   TEXT NOT NULL,
    ttl_seconds INTEGER DEFAULT 3600
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    site_id    TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip         TEXT
);
CREATE TABLE IF NOT EXISTS site_telemetry (
    id           SERIAL PRIMARY KEY,
    site_id      TEXT REFERENCES sites(id),
    timestamp    TEXT NOT NULL,
    cpu_percent  REAL,
    mem_percent  REAL,
    disk_percent REAL,
    details      TEXT
);
CREATE TABLE IF NOT EXISTS site_audits (
    site_id        TEXT PRIMARY KEY REFERENCES sites(id),
    timestamp      TEXT NOT NULL,
    security_score INTEGER,
    ssl_status     TEXT,
    ssl_expiry     TEXT,
    headers        TEXT,
    audit_log      TEXT
);
CREATE TABLE IF NOT EXISTS activity_logs (
    id          SERIAL PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    action_type TEXT NOT NULL,
    description TEXT NOT NULL,
    metadata    TEXT DEFAULT '{}',
    timestamp   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_site      ON events(site_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(attack_type);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_blocked_ip       ON blocked_ips(ip);
CREATE INDEX IF NOT EXISTS idx_blocked_expires  ON blocked_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_site   ON site_telemetry(site_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_user_sites_user  ON user_sites(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sites_site  ON user_sites(site_id);
CREATE INDEX IF NOT EXISTS idx_activity_user_timestamp ON activity_logs(user_id, timestamp DESC);
"""

SCHEMA = SCHEMA_POSTGRESQL if _USE_PG else SCHEMA_SQLITE


def init_db():
    if not _USE_PG:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
    _migrate_user_sites()
    log.info("DB initialized (backend=%s)", "postgresql" if _USE_PG else "sqlite")
    _seed_default_rules()


def _migrate_user_sites():
    now = datetime.now().isoformat()
    with db() as conn:
        rows = conn.execute(
            "SELECT id, site_id FROM users WHERE site_id IS NOT NULL AND active=1"
        ).fetchall()
        for row in rows:
            conn.execute(
                "INSERT OR IGNORE INTO user_sites (user_id, site_id, role, created_at) VALUES (?,?,?,?)",
                (row["id"], row["site_id"], "owner", now),
            )


def _seed_default_rules():
    DEFAULT_RULES = [
        (
            "r_sqli_union",
            "SQLi - UNION SELECT",
            "SQLi",
            r"(?i)(union\s+select)",
            "CRITICAL",
            100,
        ),
        (
            "r_sqli_sleep",
            "SQLi - Blind Time",
            "SQLi",
            r"(?i)(sleep\s*\(\s*\d+\s*\))",
            "CRITICAL",
            90,
        ),
        (
            "r_sqli_or",
            "SQLi - Auth Bypass",
            "SQLi",
            r"(?i)(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
            "CRITICAL",
            90,
        ),
        (
            "r_sqli_drop",
            "SQLi - DDL Attack",
            "SQLi",
            r"(?i)(drop\s+table)",
            "CRITICAL",
            95,
        ),
        (
            "r_sqli_info",
            "SQLi - Schema Enum",
            "SQLi",
            r"(?i)(information_schema)",
            "HIGH",
            80,
        ),
        (
            "r_sqli_load",
            "SQLi - File Read",
            "SQLi",
            r"(?i)(load_file\s*\()",
            "CRITICAL",
            95,
        ),
        (
            "r_sqli_outfile",
            "SQLi - File Write",
            "SQLi",
            r"(?i)(into\s+outfile)",
            "CRITICAL",
            95,
        ),
        (
            "r_sqli_xpcmd",
            "SQLi - MSSQL RCE",
            "SQLi",
            r"(?i)(xp_cmdshell)",
            "CRITICAL",
            100,
        ),
        ("r_xss_script", "XSS - Script Tag", "XSS", r"(?i)<script[^>]*>", "HIGH", 90),
        (
            "r_xss_on",
            "XSS - Event Handler",
            "XSS",
            r"(?i)(on\w+\s*=\s*['\"])",
            "HIGH",
            85,
        ),
        (
            "r_xss_alert",
            "XSS - Classic Probe",
            "XSS",
            r"(?i)(alert\s*\()",
            "MEDIUM",
            70,
        ),
        (
            "r_xss_cookie",
            "XSS - Cookie Theft",
            "XSS",
            r"(?i)(document\.cookie)",
            "HIGH",
            90,
        ),
        (
            "r_xss_iframe",
            "XSS - iFrame Inject",
            "XSS",
            r"(?i)(<iframe[^>]*>)",
            "HIGH",
            85,
        ),
        (
            "r_lfi_traverse",
            "LFI - Path Traversal",
            "LFI",
            r"(\.\.\/){2,}",
            "CRITICAL",
            95,
        ),
        (
            "r_lfi_passwd",
            "LFI - /etc/passwd",
            "LFI",
            r"(?i)(\/etc\/passwd)",
            "CRITICAL",
            100,
        ),
        (
            "r_lfi_shadow",
            "LFI - /etc/shadow",
            "LFI",
            r"(?i)(\/etc\/shadow)",
            "CRITICAL",
            100,
        ),
        (
            "r_lfi_php",
            "LFI - PHP Wrapper",
            "LFI",
            r"(?i)(php:\/\/filter)",
            "CRITICAL",
            95,
        ),
        ("r_lfi_proc", "LFI - /proc Self", "LFI", r"(?i)(\/proc\/self)", "HIGH", 85),
        (
            "r_cmdi_pipe",
            "CMDi - Pipe Exec",
            "CMDi",
            r"(?i)(\|[\s]*(ls|cat|id|whoami|pwd|uname))",
            "CRITICAL",
            95,
        ),
        (
            "r_cmdi_backtick",
            "CMDi - Backtick Exec",
            "CMDi",
            r"(?i)(`[\s]*(id|whoami|ls)[\s]*`)",
            "CRITICAL",
            100,
        ),
        (
            "r_cmdi_dollar",
            "CMDi - Subshell",
            "CMDi",
            r"(?i)(\$\([\s]*(id|whoami|ls)[\s]*\))",
            "CRITICAL",
            100,
        ),
        (
            "r_cmdi_nc",
            "CMDi - Netcat Bind",
            "CMDi",
            r"(?i)(nc\s+-[lne]+\s+\d+)",
            "CRITICAL",
            100,
        ),
        (
            "r_cmdi_wget",
            "CMDi - Remote Fetch",
            "CMDi",
            r"(?i)(wget\s+http)",
            "HIGH",
            85,
        ),
        (
            "r_cmdi_curl",
            "CMDi - Remote Fetch",
            "CMDi",
            r"(?i)(curl\s+http)",
            "HIGH",
            85,
        ),
    ]
    now = datetime.now().isoformat()
    with db() as conn:
        for rid, name, atype, pattern, sev, prio in DEFAULT_RULES:
            conn.execute(
                "INSERT OR IGNORE INTO rules (id, name, attack_type, pattern, severity, priority, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (rid, name, atype, pattern, sev, prio, now, now),
            )


# ─── User Sites ───────────────────────────────────────────────────────────────


def add_user_site(user_id: str, site_id: str, role: str = "owner") -> bool:
    now = datetime.now().isoformat()
    with db() as conn:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO user_sites (user_id, site_id, role, created_at) VALUES (?,?,?,?)",
                (user_id, site_id, role, now),
            )
            return True
        except Exception:
            return False


def get_user_sites(user_id: str) -> list:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT s.*, us.role as user_role, us.created_at as linked_at
            FROM sites s
            JOIN user_sites us ON s.id = us.site_id
            WHERE us.user_id = ?
            ORDER BY us.created_at ASC
            """,
            (user_id,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def remove_user_site(user_id: str, site_id: str) -> bool:
    with db() as conn:
        res = conn.execute(
            "DELETE FROM user_sites WHERE user_id=? AND site_id=?", (user_id, site_id)
        )
        return res.rowcount > 0


def user_owns_site(user_id: str, site_id: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM user_sites WHERE user_id=? AND site_id=?", (user_id, site_id)
        ).fetchone()
    return row is not None


# ─── Events ───────────────────────────────────────────────────────────────────


def insert_event(event: dict, site_id: str = "site_demo") -> int:
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO events
                (site_id, timestamp, src_ip, dst_ip, dst_port, attack_type, severity,
                 confidence, payload_snip, matched_rules, cve_hints, action, status,
                 sanitization, geo_country, geo_city, geo_isp, ingestion_source)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                site_id,
                event.get("timestamp", datetime.now().isoformat()),
                event.get("src_ip", "0.0.0.0"),
                event.get("dst_ip"),
                event.get("dst_port"),
                event.get("attack_type", "SQLi"),
                event.get("severity", "HIGH"),
                event.get("confidence", 0),
                event.get("payload_snip", "")[:500],
                json.dumps(event.get("matched_rules", [])),
                json.dumps(event.get("cve_hints", [])),
                event.get("action", "PENDING"),
                event.get("status", "DETECTED"),
                event.get("sanitization", ""),
                event.get("geo_country"),
                event.get("geo_city"),
                event.get("geo_isp"),
                event.get("ingestion_source", "manual"),
            ),
        )
        return cur.lastrowid or 0


def get_events(
    site_id: str = "site_demo",
    limit: int = 200,
    attack_type: str = None,
    severity: str = None,
    since: str = None,
    src_ip: str = None,
) -> list:
    filters = ["site_id = ?"]
    params = [site_id]
    if attack_type:
        filters.append("attack_type = ?")
        params.append(attack_type)
    if severity:
        filters.append("severity = ?")
        params.append(severity)
    if since:
        filters.append("timestamp >= ?")
        params.append(since)
    if src_ip:
        filters.append("src_ip = ?")
        params.append(src_ip)
    where = " AND ".join(filters)
    with db() as conn:
        rows = conn.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_event_action(event_id: int, action: str, status: str):
    with db() as conn:
        conn.execute(
            "UPDATE events SET action=?, status=? WHERE id=?",
            (action, status, event_id),
        )


def get_event_by_id(event_id: int) -> dict:
    with db() as conn:
        row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    return _row_to_dict(row) if row else None


def mark_false_positive(event_id: int, rule_id: str = None):
    with db() as conn:
        conn.execute("UPDATE events SET status='FP' WHERE id=?", (event_id,))
        if rule_id:
            conn.execute(
                "UPDATE rules SET false_positive_count = false_positive_count+1 WHERE id=?",
                (rule_id,),
            )


# ─── Blocked IPs ──────────────────────────────────────────────────────────────


def block_ip(
    ip: str,
    attack_type: str,
    severity: str,
    reason: str,
    duration_seconds: int = 3600,
    method: str = "in-memory",
    site_id: str = "site_demo",
):
    now = datetime.now()
    expires = now + timedelta(seconds=duration_seconds)
    with db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO blocked_ips
                (ip, site_id, attack_type, severity, reason, method, blocked_at, expires_at, unblocked)
            VALUES (?,?,?,?,?,?,?,?,0)
            """,
            (
                ip,
                site_id,
                attack_type,
                severity,
                reason,
                method,
                now.isoformat(),
                expires.isoformat(),
            ),
        )


def unblock_ip(ip: str, site_id: str = "site_demo"):
    with db() as conn:
        conn.execute(
            "UPDATE blocked_ips SET unblocked=1 WHERE ip=? AND site_id=?", (ip, site_id)
        )


def get_blocked_ips(site_id: str = "site_demo") -> list:
    now = datetime.now().isoformat()
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM blocked_ips WHERE site_id=? AND unblocked=0 AND expires_at > ? ORDER BY blocked_at DESC",
            (site_id, now),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def cleanup_expired_blocks():
    now = datetime.now().isoformat()
    with db() as conn:
        conn.execute(
            "UPDATE blocked_ips SET unblocked=1 WHERE expires_at <= ? AND unblocked=0",
            (now,),
        )


# ─── IP Reputation ────────────────────────────────────────────────────────────


def upsert_ip_reputation(ip, score, label, attack_types, country=None, isp=None):
    now = datetime.now().isoformat()
    with db() as conn:
        existing = conn.execute(
            "SELECT ip FROM ip_reputation WHERE ip=?", (ip,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE ip_reputation SET threat_score=?, threat_label=?, attack_count=attack_count+1, attack_types=?, last_seen=?, country=COALESCE(?,country), isp=COALESCE(?,isp) WHERE ip=?",
                (score, label, json.dumps(attack_types), now, country, isp, ip),
            )
        else:
            conn.execute(
                "INSERT OR IGNORE INTO ip_reputation (ip, threat_score, threat_label, attack_count, attack_types, first_seen, last_seen, country, isp) VALUES (?,?,?,1,?,?,?,?,?)",
                (ip, score, label, json.dumps(attack_types), now, now, country, isp),
            )


def get_ip_reputation(ip: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute("SELECT * FROM ip_reputation WHERE ip=?", (ip,)).fetchone()
    return _row_to_dict(row) if row else None


def get_top_threats(limit: int = 10) -> list:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM ip_reputation ORDER BY threat_score DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_threat_score(site_id: str) -> int:
    window_minutes = 45
    since = (datetime.now() - timedelta(minutes=window_minutes)).isoformat()
    with db() as conn:
        if site_id in ("all", "global"):
            events = conn.execute(
                "SELECT severity, timestamp, action, status FROM events WHERE timestamp >= ? AND attack_type != 'Benign'",
                (since,),
            ).fetchall()
        else:
            events = conn.execute(
                "SELECT severity, timestamp, action, status FROM events WHERE site_id=? AND timestamp >= ? AND attack_type != 'Benign'",
                (site_id, since),
            ).fetchall()

    if not events:
        return 0

    total_weight = 0.0
    sev_weights = {"CRITICAL": 26.0, "HIGH": 14.0, "MEDIUM": 6.0, "LOW": 2.0}
    now = datetime.now()

    for ev in events:
        ev = dict(ev)  # 🔥 THIS LINE FIXES EVERYTHING

        sev = str(ev.get("severity") or "LOW").upper()
        status = str(ev.get("status") or "").upper()
        action = str(ev.get("action") or "").upper()
        try:
            age_seconds = (
                now - datetime.fromisoformat(ev["timestamp"])
            ).total_seconds()
        except Exception:
            age_seconds = 0
        base = sev_weights.get(sev, 1.0)
        unresolved = status in {"DETECTED", "MITIGATING"} and action != "BLOCKED"
        fixed = action == "BLOCKED" or status in {"FIXED", "MITIGATED"}
        if unresolved:
            total_weight += base * 1.7 * max(0.0, 1.0 - (age_seconds / 300.0))
        elif fixed:
            total_weight += base * 0.85 * max(0.0, 1.0 - (age_seconds / 900.0))
        else:
            total_weight += base * 0.4 * max(0.0, 1.0 - (age_seconds / 300.0))

    last_event_time = max(datetime.fromisoformat(ev["timestamp"]) for ev in events)
    time_since_last = (now - last_event_time).total_seconds()
    if time_since_last > 300:
        decay_factor = max(0.0, 1.0 - (time_since_last - 300) / 1800.0)
        total_weight *= decay_factor

    return min(100, int(total_weight))


# ─── Rules ────────────────────────────────────────────────────────────────────


def get_rules(attack_type: str = None, enabled_only: bool = True) -> list:
    filters = []
    params = []
    if enabled_only:
        filters.append("enabled=1")
    if attack_type:
        filters.append("attack_type=?")
        params.append(attack_type)
    where = " AND ".join(filters) if filters else "1=1"
    with db() as conn:
        rows = conn.execute(
            f"SELECT * FROM rules WHERE {where} ORDER BY priority DESC", params
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def toggle_rule(rule_id: str, enabled: bool):
    with db() as conn:
        conn.execute(
            "UPDATE rules SET enabled=?, updated_at=? WHERE id=?",
            (1 if enabled else 0, datetime.now().isoformat(), rule_id),
        )


def add_custom_rule(
    name, attack_type, pattern, severity="HIGH", created_by="admin"
) -> str:
    rule_id = f"r_custom_{secrets.token_hex(4)}"
    now = datetime.now().isoformat()
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO rules (id, name, attack_type, pattern, severity, created_at, updated_at, created_by) VALUES (?,?,?,?,?,?,?,?)",
            (rule_id, name, attack_type, pattern, severity, now, now, created_by),
        )
    return rule_id


# ─── Webhooks ─────────────────────────────────────────────────────────────────


def get_webhooks(site_id: str = "site_demo") -> list:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM webhooks WHERE site_id=? AND enabled=1", (site_id,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def add_webhook(site_id, name, url, secret=None, events=None) -> str:
    wid = f"wh_{secrets.token_hex(6)}"
    now = datetime.now().isoformat()
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO webhooks (id, site_id, name, url, secret, events, created_at) VALUES (?,?,?,?,?,?,?)",
            (
                wid,
                site_id,
                name,
                url,
                secret,
                json.dumps(events or ["CRITICAL", "HIGH"]),
                now,
            ),
        )
    return wid


def record_webhook_fire(webhook_id: str, success: bool):
    now = datetime.now().isoformat()
    with db() as conn:
        if success:
            conn.execute(
                "UPDATE webhooks SET last_fired=?, failure_count=0 WHERE id=?",
                (now, webhook_id),
            )
        else:
            conn.execute(
                "UPDATE webhooks SET failure_count=failure_count+1 WHERE id=?",
                (webhook_id,),
            )


# ─── Sites ────────────────────────────────────────────────────────────────────


def validate_api_key(api_key: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute("SELECT * FROM sites WHERE api_key=?", (api_key,)).fetchone()
    return _row_to_dict(row) if row else None


def get_site(site_id: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
    return _row_to_dict(row) if row else None


def list_sites() -> list:
    with db() as conn:
        rows = conn.execute("SELECT * FROM sites ORDER BY created_at DESC").fetchall()
    return [_row_to_dict(r) for r in rows]


def update_site_config(site_id: str, config: dict) -> bool:
    with db() as conn:
        current = conn.execute(
            "SELECT config FROM sites WHERE id=?", (site_id,)
        ).fetchone()
        if not current:
            return False
        try:
            existing = json.loads(current["config"]) if current["config"] else {}
        except Exception:
            existing = {}
        existing.update(config)
        conn.execute(
            "UPDATE sites SET config=? WHERE id=?", (json.dumps(existing), site_id)
        )
    return True


def update_site_name(site_id: str, name: str) -> bool:
    with db() as conn:
        res = conn.execute("UPDATE sites SET name=? WHERE id=?", (name, site_id))
        return res.rowcount > 0


def update_site_upstream(site_id: str, upstream_url: str) -> bool:
    with db() as conn:
        res = conn.execute(
            "UPDATE sites SET upstream_url=? WHERE id=?", (upstream_url, site_id)
        )
        return res.rowcount > 0


def create_site(name, domain, plan="free", user_id=None, upstream_url=None) -> dict:
    site_id = f"site_{secrets.token_hex(6)}"
    api_key = f"as_{secrets.token_urlsafe(32)}"
    now = datetime.now().isoformat()
    upstream = upstream_url or f"http://{domain}"
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO sites (id, name, domain, api_key, plan, created_at, upstream_url) VALUES (?,?,?,?,?,?,?)",
            (site_id, name, domain, api_key, plan, now, upstream),
        )
    if user_id:
        log_activity(
            user_id,
            "ADD_WEBSITE",
            f"Added website '{name}' ({domain})",
            {"site_id": site_id, "domain": domain},
        )
    return {
        "site_id": site_id,
        "api_key": api_key,
        "id": site_id,
        "upstream_url": upstream,
    }


def delete_site(site_id: str, user_id: str) -> bool:
    if remove_user_site(user_id, site_id):
        site = get_site(site_id)
        if site:
            log_activity(
                user_id,
                "DELETE_WEBSITE",
                f"Removed website '{site['name']}' ({site['domain']})",
                {"site_id": site_id},
            )
        return True
    return False


def update_site_plan(site_id: str, plan: str) -> bool:
    with db() as conn:
        res = conn.execute("UPDATE sites SET plan=? WHERE id=?", (plan, site_id))
        return res.rowcount > 0


# ─── Auth / Sessions ──────────────────────────────────────────────────────────


def get_user(username: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=? AND active=1", (username,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_user_by_id(user_id: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id=? AND active=1", (user_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def update_user_password(username: str, password_hash: str):
    with db() as conn:
        conn.execute(
            "UPDATE users SET password_hash=? WHERE username=?",
            (password_hash, username),
        )


def create_session(user_id: str, site_id: str, ip: str, ttl_hours: int = 8) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now()
    expires = now + timedelta(hours=ttl_hours)
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO sessions (token, user_id, site_id, created_at, expires_at, ip) VALUES (?,?,?,?,?,?)",
            (token, user_id, site_id, now.isoformat(), expires.isoformat(), ip),
        )
    return token


def validate_session(token: str) -> Optional[dict]:
    now = datetime.now().isoformat()
    with db() as conn:
        row = conn.execute(
            """
            SELECT s.*, u.id AS id, u.username, u.role, u.site_id AS profile_site_id
            FROM sessions s JOIN users u ON s.user_id = u.id
            WHERE s.token=? AND s.expires_at > ?
            """,
            (token, now),
        ).fetchone()
    return _row_to_dict(row) if row else None


def record_login(user_id: str, username: str):
    now = datetime.now().isoformat()
    with db() as conn:
        conn.execute("UPDATE users SET last_login=? WHERE username=?", (now, username))
    log_activity(user_id, "LOGIN", f"User '{username}' logged in")


# ─── Audit Log ────────────────────────────────────────────────────────────────


def audit(user, action, target=None, detail=None, ip=None, result="OK"):
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO audit_log (timestamp, user, action, target, detail, ip, result) VALUES (?,?,?,?,?,?,?)",
            (datetime.now().isoformat(), user, action, target, detail, ip, result),
        )


def get_site_audit(site_id: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM site_audits WHERE site_id=?", (site_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


# ─── CVE Cache ────────────────────────────────────────────────────────────────


def get_cached_cve(key: str) -> Optional[list]:
    with db() as conn:
        row = conn.execute(
            "SELECT data, cached_at, ttl_seconds FROM cve_cache WHERE cache_key=?",
            (key,),
        ).fetchone()
    if not row:
        return None
    if (
        datetime.now() - datetime.fromisoformat(row["cached_at"])
    ).total_seconds() > row["ttl_seconds"]:
        return None
    return json.loads(row["data"])


def set_cached_cve(key: str, data: list, ttl_seconds: int = 3600):
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (cache_key, data, cached_at, ttl_seconds) VALUES (?,?,?,?)",
            (key, json.dumps(data), datetime.now().isoformat(), ttl_seconds),
        )


# ─── Analytics ────────────────────────────────────────────────────────────────


def get_stats(site_id: str = "site_demo", hours: int = 24) -> dict:
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    since_visitor = (datetime.now() - timedelta(hours=1)).isoformat()
    with db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE site_id=? AND timestamp>=?",
            (site_id, since),
        ).fetchone()
        total = list(dict(total).values())[0] if total else 0

        blocked = conn.execute(
            "SELECT COUNT(*) FROM events WHERE site_id=? AND timestamp>=? AND action='BLOCKED'",
            (site_id, since),
        ).fetchone()
        blocked = list(dict(blocked).values())[0] if blocked else 0

        unique_visitors = conn.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM events WHERE site_id=? AND timestamp>=?",
            (site_id, since_visitor),
        ).fetchone()
        unique_visitors = list(dict(unique_visitors).values())[0] if unique_visitors else 0

        by_type = conn.execute(
            "SELECT attack_type, COUNT(*) as cnt FROM events WHERE site_id=? AND timestamp>=? GROUP BY attack_type ORDER BY cnt DESC",
            (site_id, since),
        ).fetchall()
    return {
        "total": total,
        "blocked": blocked,
        "visitors": unique_visitors,
        "by_type": {r["attack_type"]: r["cnt"] for r in by_type},
        "block_rate": round(blocked / max(total, 1) * 100, 1),
        "since_hours": hours,
    }


def get_global_stats() -> dict:
    since = (datetime.now() - timedelta(hours=24)).isoformat()
    with db() as conn:
        total_row = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp>=?", (since,)
        ).fetchone()
        total = list(dict(total_row).values())[0] if total_row else 0

        blocked_row = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp>=? AND action='BLOCKED'",
            (since,),
        ).fetchone()
        blocked = list(dict(blocked_row).values())[0] if blocked_row else 0

        sites_row = conn.execute("SELECT COUNT(*) FROM sites").fetchone()
        sites = list(dict(sites_row).values())[0] if sites_row else 0

        by_type = conn.execute(
            "SELECT attack_type, COUNT(*) as cnt FROM events WHERE timestamp>=? GROUP BY attack_type ORDER BY cnt DESC",
            (since,),
        ).fetchall()
    return {
        "total": total,
        "blocked": blocked,
        "activeSites": sites,
        "threatScore": get_threat_score("all"),
        "block_rate": round(blocked / max(total, 1) * 100, 1),
        "by_type": {r["attack_type"] or "Unknown": r["cnt"] for r in by_type},
    }


def get_timeline(site_id: str = "site_demo", limit: int = 200) -> list:
    return get_events(site_id=site_id, limit=limit)


# ─── Rate Limiting ────────────────────────────────────────────────────────────


def record_and_check_rate(
    ip: str, window_seconds: int = 60, threshold: int = 5
) -> tuple:
    now = datetime.now()
    window_start = now.replace(
        second=(now.second // max(1, window_seconds)) * window_seconds, microsecond=0
    ).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO rate_state (ip, window_start, count) VALUES (?,?,1)",
            (ip, window_start),
        )
        conn.execute(
            "UPDATE rate_state SET count=count+1 WHERE ip=? AND window_start=?",
            (ip, window_start),
        )
        count_row = conn.execute(
            "SELECT count FROM rate_state WHERE ip=? AND window_start=?",
            (ip, window_start),
        ).fetchone()
    count = count_row["count"] if count_row else 1
    return count, count >= threshold


# ─── Telemetry ────────────────────────────────────────────────────────────────


def insert_telemetry(site_id, cpu, mem, disk, details=None):
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO site_telemetry (site_id, timestamp, cpu_percent, mem_percent, disk_percent, details) VALUES (?,?,?,?,?,?)",
            (
                site_id,
                datetime.now().isoformat(),
                cpu,
                mem,
                disk,
                json.dumps(details or {}),
            ),
        )


def get_latest_telemetry(site_id: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM site_telemetry WHERE site_id=? ORDER BY timestamp DESC LIMIT 1",
            (site_id,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def upsert_site_audit(site_id, score, ssl_status, ssl_expiry, headers, audit_log_data):
    with db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO site_audits
                (site_id, timestamp, security_score, ssl_status, ssl_expiry, headers, audit_log)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                site_id,
                datetime.now().isoformat(),
                score,
                ssl_status,
                ssl_expiry,
                json.dumps(headers),
                json.dumps(audit_log_data),
            ),
        )


def get_geo_for_ip(ip: str) -> dict:
    if ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return {"country": "LOCAL", "city": "Localhost", "isp": "Local"}
    try:
        import urllib.request

        url = f"http://ipapi.co/{ip}/json/"
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            return {
                "country": data.get("country_code", "UNK"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("org", "Unknown ISP"),
            }
    except Exception:
        arr = ["US", "CN", "RU", "GB", "DE", "BR", "NL", "IN", "US", "RO"]
        res = arr[int(hashlib.md5(ip.encode()).hexdigest(), 16) % len(arr)]
        return {"country": res, "city": "Unknown", "isp": "Unknown ISP"}


# ─── Activity Logging ─────────────────────────────────────────────────────────


def log_activity(user_id, action_type, description, metadata=None):
    now = datetime.now().isoformat()
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO activity_logs (user_id, action_type, description, metadata, timestamp) VALUES (?,?,?,?,?)",
            (user_id, action_type, description, json.dumps(metadata or {}), now),
        )


def get_user_activity(
    user_id, limit=50, offset=0, action_type=None, start_date=None
) -> list:
    query = "SELECT * FROM activity_logs WHERE user_id = ?"
    params = [user_id]
    if action_type:
        query += " AND action_type = ?"
        params.append(action_type)
    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _row_to_dict(row) -> dict:
    if row is None:
        return {}
    if isinstance(row, dict):
        d = dict(row)
    else:
        try:
            d = dict(row)
        except Exception:
            return {}
    for field in ("matched_rules", "cve_hints", "attack_types", "events", "config"):
        if field in d and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    return d


def purge_old_events(days: int = 90):
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    with db() as conn:
        count_row = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp < ?", (cutoff,)
        ).fetchone()
        n = list(dict(count_row).values())[0] if count_row else 0
        conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM rate_state WHERE window_start < ?", (cutoff,))
    log.info("Purged %d events older than %d days", n, days)
    return n


if __name__ == "__main__":
    init_db()
    print(f"DB initialized (backend={'postgresql' if _USE_PG else 'sqlite'})")
    print(f"Rules loaded: {len(get_rules())}")
    print(f"Sites: {len(list_sites())}")
