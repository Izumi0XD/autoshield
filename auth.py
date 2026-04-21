"""
AutoShield — Production Auth
bcrypt password hashing + RBAC + session tokens.
Backward-compatible migration from plaintext .autoshield_users.json.
"""

import os
import json
import secrets
import logging
import hashlib
from pathlib import Path
from typing import Optional

log = logging.getLogger("AutoShield.Auth")

try:
    import bcrypt

    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False
    log.warning("bcrypt not installed — using SHA-256 fallback. pip install bcrypt")

import db as DB

# ─── Password hashing ─────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    if BCRYPT_OK:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    # Fallback: PBKDF2 with random salt
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2${salt}${h.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash == "__NEEDS_HASH__":
        return False

    if BCRYPT_OK and stored_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception:
            return False

    # PBKDF2 fallback
    if stored_hash.startswith("pbkdf2$"):
        _, salt, hex_hash = stored_hash.split("$", 2)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
        return h.hex() == hex_hash

    # Legacy SHA-256 (migrate on next login)
    import hashlib as _hl

    return _hl.sha256(password.encode()).hexdigest() == stored_hash


# ─── Bootstrap default users ──────────────────────────────────────────────────

DEFAULT_USERS = {
    "admin": {
        "password": os.environ.get("AUTOSHIELD_ADMIN_PASS", "admin123"),
        "role": "admin",
    },
    "analyst": {
        "password": os.environ.get("AUTOSHIELD_ANALYST_PASS", "analyst123"),
        "role": "analyst",
    },
    "soc": {
        "password": os.environ.get("AUTOSHIELD_SOC_PASS", "soc123"),
        "role": "soc_lead",
    },
    "exec": {
        "password": os.environ.get("AUTOSHIELD_EXEC_PASS", "exec123"),
        "role": "executive",
    },
}

TEST_SITES = {
    "site_demo": {
        "name": "Demo Organization",
        "domain": "demo.autoshield.ai",
        "api_key": "as_demo_key_change_in_production",
        "plan": "enterprise",
    },
    "site_free_demo": {
        "name": "Free Demo Workspace",
        "domain": "free-demo.autoshield.ai",
        "api_key": "as_free_demo_key_change_in_production",
        "plan": "free",
    },
}

TEST_USERS = {
    "premium.demo": {
        "password": os.environ.get("AUTOSHIELD_PREMIUM_DEMO_PASS", "premium123"),
        "role": "admin",
        "site_id": "site_demo",
    },
    "free.demo": {
        "password": os.environ.get("AUTOSHIELD_FREE_DEMO_PASS", "free123"),
        "role": "analyst",
        "site_id": "site_free_demo",
    },
}


def _ensure_seed_sites_and_users():
    now = "datetime('now')"
    with DB.db() as conn:
        for sid, site in TEST_SITES.items():
            conn.execute(
                f"""
                INSERT OR IGNORE INTO sites (id, name, domain, api_key, plan, created_at, config)
                VALUES (?,?,?,?,?,{now},'{{}}')
                """,
                (
                    sid,
                    site["name"],
                    site["domain"],
                    site["api_key"],
                    site["plan"],
                ),
            )

        for uname, cfg in TEST_USERS.items():
            conn.execute(
                f"""
                INSERT OR IGNORE INTO users (id, username, password_hash, role, site_id, created_at)
                VALUES (?,?,?,?,?,{now})
                """,
                (
                    f"u_{uname.replace('.', '_')}",
                    uname,
                    "__NEEDS_HASH__",
                    cfg["role"],
                    cfg["site_id"],
                ),
            )


def bootstrap_users():
    """Hash + store default users on first boot. Safe to call multiple times."""
    _ensure_seed_sites_and_users()

    for username, cfg in DEFAULT_USERS.items():
        user = DB.get_user(username)
        if user and user.get("password_hash") == "__NEEDS_HASH__":
            h = hash_password(cfg["password"])
            DB.update_user_password(username, h)
            log.info(f"Password hashed for user: {username}")

    for username, cfg in TEST_USERS.items():
        user = DB.get_user(username)
        if user and user.get("password_hash") == "__NEEDS_HASH__":
            h = hash_password(cfg["password"])
            DB.update_user_password(username, h)
            log.info(f"Password hashed for test user: {username}")

    # Migrate from legacy .autoshield_users.json if it exists
    _migrate_legacy_users()


def _migrate_legacy_users():
    legacy = Path(".autoshield_users.json")
    if not legacy.exists():
        return
    try:
        data = json.loads(legacy.read_text())
        users = data if isinstance(data, list) else data.get("users", [])
        for u in users:
            uname = u.get("username")
            if not uname:
                continue
            existing = DB.get_user(uname)
            if existing:
                continue  # already in DB
            plain = u.get("password", "")
            h = hash_password(plain)
            with DB.db() as conn:
                import secrets as _s

                conn.execute(
                    """
                    INSERT OR IGNORE INTO users
                        (id, username, password_hash, role, site_id, created_at)
                    VALUES (?,?,?,?,?,datetime('now'))
                """,
                    (
                        f"u_{_s.token_hex(4)}",
                        uname,
                        h,
                        u.get("role", "analyst"),
                        "site_demo",
                    ),
                )
        log.info(f"Migrated {len(users)} users from legacy auth file")
        # Rename legacy file so we don't migrate again
        legacy.rename(legacy.with_suffix(".json.migrated"))
    except Exception as e:
        log.error(f"Legacy migration failed: {e}")


# ─── Login ────────────────────────────────────────────────────────────────────


def login(
    username: str, password: str, ip: str = "0.0.0.0"
) -> tuple[bool, Optional[str], Optional[dict]]:
    """
    Attempt login. Returns (success, session_token, user_dict).
    """
    user = DB.get_user(username)
    if not user:
        DB.audit(
            "system",
            "LOGIN_FAIL",
            target=username,
            detail="user not found",
            ip=ip,
            result="FAIL",
        )
        return False, None, None

    stored_hash = user.get("password_hash", "")
    if not verify_password(password, stored_hash):
        DB.audit(username, "LOGIN_FAIL", detail="bad password", ip=ip, result="FAIL")
        return False, None, None

    # Auto-upgrade hash if using legacy format
    if not stored_hash.startswith("$2") and not stored_hash.startswith("pbkdf2$"):
        DB.update_user_password(username, hash_password(password))

    token = DB.create_session(user["id"], user.get("site_id", "site_demo"), ip)
    DB.record_login(user["id"], username)
    DB.audit(username, "LOGIN_OK", ip=ip)
    return True, token, user


def logout(token: str):
    DB.audit("system", "LOGOUT", detail=token[:8] + "...")
    # Remove session from DB
    with DB.db() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))


def validate_token(token: str) -> Optional[dict]:
    return DB.validate_session(token)


# ─── RBAC ─────────────────────────────────────────────────────────────────────

ROLE_PERMISSIONS = {
    "admin": {
        "can_block",
        "can_unblock",
        "can_add_rules",
        "can_delete_rules",
        "can_view_events",
        "can_view_reports",
        "can_manage_users",
        "can_manage_sites",
        "can_view_audit",
        "can_run_simulations",
        "can_manage_webhooks",
        "can_view_payloads",
    },
    "soc_lead": {
        "can_block",
        "can_unblock",
        "can_add_rules",
        "can_view_events",
        "can_view_reports",
        "can_run_simulations",
        "can_manage_webhooks",
        "can_view_payloads",
    },
    "analyst": {
        "can_view_events",
        "can_view_reports",
        "can_run_simulations",
        "can_view_payloads",
    },
    "executive": {
        "can_view_events",
        "can_view_reports",
    },
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def require_permission(role: str, permission: str):
    if not has_permission(role, permission):
        raise PermissionError(f"Role '{role}' lacks permission '{permission}'")


# ─── Streamlit helpers ────────────────────────────────────────────────────────


def streamlit_login_widget():
    """Render login form + handle auth in Streamlit. Returns (logged_in, user)."""
    try:
        import streamlit as st
    except ImportError:
        return False, None

    if "auth_token" in st.session_state and st.session_state.auth_token:
        user = validate_token(st.session_state.auth_token)
        if user:
            return True, user
        else:
            st.session_state.auth_token = None

    st.markdown(
        """
    <div style="max-width:400px;margin:80px auto;background:#0e1420;border:1px solid #1e2d45;
                border-radius:8px;padding:32px">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:28px">🛡️</div>
        <div style="font-size:18px;font-weight:700;color:#cdd8eb;margin-top:8px">AutoShield AI</div>
        <div style="font-size:11px;color:#4a6080;font-family:monospace;margin-top:4px">FUSION CONSOLE</div>
      </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button(
            "Sign In", use_container_width=True, type="primary"
        )

    if submitted:
        ok, token, user = login(username, password, ip="streamlit")
        if ok:
            st.session_state.auth_token = token
            st.session_state.current_user = user
            st.rerun()
        else:
            st.error("Invalid credentials")

    return False, None


if __name__ == "__main__":
    DB.init_db()
    bootstrap_users()
    print("Auth system initialized")
    print(f"bcrypt: {BCRYPT_OK}")
    print("Testing login...")
    ok, token, user = login("admin", "admin123")
    print(f"admin login: {ok}, role={user.get('role') if user else None}")
    ok2, token2, user2 = login("analyst", "analyst123")
    print(f"analyst login: {ok2}, role={user2.get('role') if user2 else None}")
