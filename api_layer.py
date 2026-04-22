"""
AutoShield — Production API Layer
FastAPI app. Auth: API key header X-AutoShield-Key: as_xxxx
"""

import os
import json
import time
import asyncio
import logging
import secrets
import threading
import queue
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional, List
from pathlib import Path
from urllib.parse import urlencode
import urllib.request as urllib_request

urlopen = urllib_request.urlopen

log = logging.getLogger("AutoShield.API")

try:
    from fastapi import (
        FastAPI,
        HTTPException,
        Depends,
        Request,
        Header,
        Query,
        WebSocket,
        WebSocketDisconnect,
    )
    from fastapi.responses import (
        StreamingResponse,
        JSONResponse,
        RedirectResponse,
        FileResponse,
    )
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    import uvicorn
    from uvicorn import Config, Server

    FASTAPI_OK = True
except ImportError:
    FASTAPI_OK = False
    log.warning("FastAPI/uvicorn not installed. pip install fastapi uvicorn")

import db as DB
from scapy_engine import AttackDetector
from auto_block import (
    BlockManager,
    firewall_mode,
    get_blocker,
    get_ddos_shield,
    host_firewall_enforced,
    is_root_mode,
)
from threat_score import ThreatScoreEngine, get_threat_engine
from webhook_manager import WebhookManager
import auth as AUTH
from attack_simulator import get_autopilot
import report_generator

PROXY_TARGET = os.environ.get("AUTOSHIELD_PROXY_TARGET", "http://localhost:9090")
_proxy_route_cache = {}
_proxy_blocked_ips = set()

_detector = AttackDetector()
_blocker = get_blocker()
_ddos_shield = get_ddos_shield()
_ts_engine = get_threat_engine()
_wh_manager = None
_oauth_state_store = {}
_mitigation_inflight = set()
_mitigation_lock = threading.RLock()
_critical_enforcer_started = False
_critical_enforcer_lock = threading.Lock()
_mitigation_workers_started = False
_mitigation_worker_lock = threading.Lock()
_mitigation_queue: "queue.Queue[tuple[int, str, dict, str]]" = queue.Queue(maxsize=5000)


def _safe_int(v, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


class _RedisSlidingWindowRateLimiter:
    def __init__(self):
        self._redis = None
        self._memory = {}
        self._lock = threading.RLock()
        url = os.environ.get("AUTOSHIELD_REDIS_URL", "").strip()
        if not url:
            return
        try:
            import redis

            self._redis = redis.Redis.from_url(url, decode_responses=True)
            self._redis.ping()
            log.info("Redis rate limiter active")
        except Exception as exc:
            self._redis = None
            log.warning("Redis unavailable, falling back to in-memory limiter: %s", exc)

    def hit(self, key: str, window_seconds: int, threshold: int) -> tuple[int, bool]:
        now_ms = int(time.time() * 1000)
        window_ms = max(1000, window_seconds * 1000)
        if self._redis is not None:
            rkey = f"as:rl:{key}"
            min_score = now_ms - window_ms
            p = self._redis.pipeline()
            p.zadd(rkey, {str(now_ms): now_ms})
            p.zremrangebyscore(rkey, 0, min_score)
            p.zcard(rkey)
            p.pexpire(rkey, window_ms + 1000)
            _, _, count, _ = p.execute()
            count = int(count or 0)
            return count, count >= threshold

        with self._lock:
            arr = self._memory.get(key, [])
            arr = [t for t in arr if now_ms - t < window_ms]
            arr.append(now_ms)
            self._memory[key] = arr
            count = len(arr)
        return count, count >= threshold


_rate_limiter = _RedisSlidingWindowRateLimiter()


class EventBroadcaster:
    def __init__(self):
        self.subscribers = {}
        self.lock = threading.Lock()

    def subscribe(self, site_id: str) -> asyncio.Queue:
        q = asyncio.Queue()
        with self.lock:
            if site_id not in self.subscribers:
                self.subscribers[site_id] = set()
            self.subscribers[site_id].add(q)
        return q

    def unsubscribe(self, site_id: str, q: asyncio.Queue):
        with self.lock:
            if site_id in self.subscribers and q in self.subscribers[site_id]:
                self.subscribers[site_id].remove(q)
                if not self.subscribers[site_id]:
                    del self.subscribers[site_id]

    def publish(self, site_id: str, event_data: dict):
        with self.lock:
            subs = self.subscribers.get(site_id, set()).copy()
        for q in subs:
            try:
                q.put_nowait(event_data)
            except Exception:
                pass


broadcaster = EventBroadcaster()

API_PORT = int(os.environ.get("AUTOSHIELD_API_PORT", "8503"))


def is_country_blocked(site: dict, country: str) -> bool:
    config = site.get("config", {})
    blocked = config.get("blocked_countries", [])
    return country.upper() in [c.upper() for c in blocked]


def create_app() -> "FastAPI":
    if not FASTAPI_OK:
        raise RuntimeError("FastAPI not installed")

    global _wh_manager
    DB.init_db()
    AUTH.bootstrap_users()
    _wh_manager = WebhookManager()
    _start_critical_enforcer_once()
    _start_mitigation_workers_once()

    app = FastAPI(
        title="AutoShield AI",
        description="Real-time web attack detection and response API",
        version="2.0.0",
    )

    @app.get("/")
    def root():
        return {"status": "running", "version": "2.0.0-waf-connected"}

    @app.get("/debug/version")
    def debug_version():
        return {
            "version": "2.0.0",
            "waf_status": "connected",
            "detection_enabled": True,
            "blocking_enabled": True,
            "timestamp": datetime.now().isoformat(),
        }

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def ddos_shield_middleware(request: Request, call_next):
        client_ip = request.client.host if request.client else "0.0.0.0"
        if client_ip in _proxy_blocked_ips:
            return JSONResponse(
                status_code=403,
                content={"detail": "Access blocked due to detected threat."},
            )
        if _ddos_shield.auto_block_if_needed(client_ip):
            return JSONResponse(
                status_code=429,
                content={"detail": "DDoS Shield: Rate limit exceeded. Access denied."},
            )
        return await call_next(request)

    @app.middleware("http")
    async def threat_detection_middleware(request: Request, call_next):
        internal_prefixes = (
            "/docs",
            "/openapi.json",
            "/health",
            "/auth",
            "/events",
            "/rules",
            "/blocked",
            "/block",
            "/stats",
            "/threats",
            "/ddos",
            "/scan",
            "/reports",
            "/sites",
            "/webhooks",
            "/checkout",
            "/simulator",
            "/telemetry",
            "/ws/",
        )
        if request.url.path.startswith(internal_prefixes):
            return await call_next(request)

        client_ip = request.client.host if request.client else "0.0.0.0"
        method = request.method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            return await call_next(request)

        # Geo-blocking check
        geo = DB.get_geo_for_ip(client_ip)
        site = {"id": "site_demo", "config": {}}
        token = request.headers.get("x-autoshield-key")
        if token:
            site_obj = DB.validate_api_key(token)
            if site_obj:
                site = site_obj
        if is_country_blocked(site, geo["country"]):
            outcome = _process_event(
                {
                    "src_ip": client_ip,
                    "payload": f"GEO-BLOCKED from {geo['country']}",
                    "ingestion_source": "middleware_geo",
                    "raw_headers": str(dict(request.headers)),
                },
                site,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": f"Geo-blocked: Access from {geo['country']} is not allowed.",
                    "event_id": outcome.get("event_id"),
                },
            )

        url = str(request.url)
        query = str(request.url.query)
        try:
            body_bytes = await request.body()
            body = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        payload = f"{method} {url} {body}"
        if query:
            payload += f" ?{query}"

        result = _detector.classify(payload)
        if result:
            outcome = _process_event(
                {
                    "src_ip": client_ip,
                    "payload": payload,
                    "ingestion_source": "middleware_live",
                    "raw_headers": str(dict(request.headers)),
                },
                site,
            )
            if outcome.get("decision") in {"MITIGATING", "BLOCKED"}:
                _proxy_blocked_ips.add(client_ip)
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": f"Threat detected: {result['attack_type']} ({result.get('severity', 'HIGH')}). Access blocked.",
                        "event_id": outcome.get("event_id"),
                    },
                )
        return await call_next(request)

    async def require_api_key(
        request: Request,
        x_autoshield_key: Optional[str] = Header(None, alias="X-AutoShield-Key"),
        authorization: Optional[str] = Header(None),
        query_token: Optional[str] = Query(None, alias="token"),
    ):
        key = x_autoshield_key
        if not key and authorization:
            auth_str = str(authorization)
            if auth_str.startswith("Bearer "):
                key = auth_str[7:]
        if not key and query_token:
            key = query_token

        if not key:
            raise HTTPException(status_code=401, detail="Missing API key.")

        site = DB.validate_api_key(key)
        if site:
            return site

        user = AUTH.validate_token(key)
        if user:
            user_id = user.get("id")
            default_site_id = user.get("site_id")
            is_platform_admin = user.get("username") == "admin" and AUTH.has_permission(
                user.get("role", ""), "can_manage_sites"
            )

            owned_sites = DB.get_user_sites(user_id) if user_id else []
            owned_site_ids = {s.get("id") for s in owned_sites}

            if user_id and default_site_id:
                if default_site_id not in owned_site_ids:
                    DB.add_user_site(user_id, default_site_id, role="owner")
                    owned_sites = DB.get_user_sites(user_id)
                    owned_site_ids = {s.get("id") for s in owned_sites}
                    log.info("Linked site %s for user %s", default_site_id, user_id)

            if owned_sites and (
                not default_site_id
                or (not is_platform_admin and default_site_id not in owned_site_ids)
            ):
                default_site_id = owned_sites[0].get("id")
                with DB.db() as conn:
                    conn.execute(
                        "UPDATE users SET site_id=? WHERE id=?",
                        (default_site_id, user_id),
                    )

            site_obj = DB.get_site(default_site_id or user.get("site_id", "site_demo"))
            if site_obj:
                site_obj = dict(site_obj)
                site_obj["user_id"] = user.get("id")
                site_obj["role"] = user.get("role")
                site_obj["username"] = user.get("username")
                site_obj["profile_site_id"] = default_site_id or user.get("site_id")
                return site_obj
            return {"id": "site_demo", "config": {}, "plan": "enterprise"}

        log.warning(
            f"AUTH FAIL: Invalid key/token '{key[:8]}...' from {request.client.host if request.client else 'unknown'}"
        )
        raise HTTPException(status_code=403, detail="Invalid API key or token")

    # ── Models ───────────────────────────────────────────────────────────────

    class EventIn(BaseModel):
        src_ip: str
        dst_ip: Optional[str] = None
        dst_port: Optional[int] = None
        payload: str = Field(..., description="Raw HTTP request or URL")
        timestamp: Optional[str] = None
        ingestion_source: str = "api"
        raw_headers: Optional[str] = None

    class BatchEventIn(BaseModel):
        events: List[EventIn]

    class BlockRequest(BaseModel):
        ip: str
        reason: str = "manual block"
        duration_hours: int = Field(1, ge=1, le=720)

    class RuleUpdate(BaseModel):
        enabled: Optional[bool] = None
        severity: Optional[str] = None
        priority: Optional[int] = None

    class CustomRule(BaseModel):
        name: str
        attack_type: str = Field(..., pattern="^(SQLi|XSS|LFI|CMDi|Custom)$")
        pattern: str
        severity: str = "HIGH"
        description: Optional[str] = None

    class WebhookIn(BaseModel):
        name: str
        url: str
        secret: Optional[str] = None
        events: List[str] = ["CRITICAL", "HIGH"]

    class ScanRequest(BaseModel):
        payload: str
        src_ip: str = "0.0.0.0"

    class LoginRequest(BaseModel):
        username: str
        password: str
        role: str = "analyst"

    class SignupRequest(BaseModel):
        username: str
        password: str
        role: str = "analyst"

    class GoogleExchangeRequest(BaseModel):
        code: str
        state: str

    class TelemetryIn(BaseModel):
        cpu: float
        memory: float
        disk: float
        details: Optional[dict] = None

    class ConfigUpdate(BaseModel):
        config: dict

    def build_auth_context(user: dict) -> dict:
        site = DB.get_site(user.get("site_id", "site_demo"))
        if not site:
            site = {
                "id": "site_demo",
                "name": "Demo Organization",
                "domain": "demo.autoshield.ai",
                "api_key": "",
                "plan": "free",
                "created_at": datetime.now().isoformat(),
            }

        plan = str(site.get("plan", "free")).lower()
        tier = "premium" if plan in {"premium", "pro", "enterprise"} else "free"

        primary_site = {
            "id": site.get("id"),
            "name": site.get("name"),
            "domain": site.get("domain"),
            "api_key": site.get("api_key"),
            "plan": site.get("plan"),
            "created_at": site.get("created_at"),
        }

        sites = [primary_site]
        user_id = user.get("id")
        is_platform_admin = user.get("username") == "admin" and AUTH.has_permission(
            user.get("role", ""), "can_manage_sites"
        )
        if is_platform_admin:
            sites = [
                {
                    "id": s.get("id"),
                    "name": s.get("name"),
                    "domain": s.get("domain"),
                    "api_key": s.get("api_key"),
                    "plan": s.get("plan"),
                    "created_at": s.get("created_at"),
                }
                for s in DB.list_sites()
            ]
        elif user_id:
            owned_sites = DB.get_user_sites(user_id)
            if owned_sites:
                sites = [
                    {
                        "id": s.get("id"),
                        "name": s.get("name"),
                        "domain": s.get("domain"),
                        "api_key": s.get("api_key"),
                        "plan": s.get("plan"),
                        "created_at": s.get("created_at"),
                    }
                    for s in owned_sites
                ]

                owned_ids = {s.get("id") for s in sites}
                if primary_site.get("id") not in owned_ids:
                    primary_site = sites[0]
                    with DB.db() as conn:
                        conn.execute(
                            "UPDATE users SET site_id=? WHERE id=?",
                            (primary_site.get("id"), user_id),
                        )

        safe_user = {
            "id": user.get("id"),
            "username": user.get("username"),
            "role": user.get("role"),
            "site_id": user.get("site_id"),
            "tier": tier,
            "authMethod": "google" if "@" in user.get("username", "") else "sso",
        }
        return {
            "user": safe_user,
            "context": {
                "tier": tier,
                "primary_site": primary_site,
                "sites": sites,
            },
        }

    # ── Health ────────────────────────────────────────────────────────────────

    @app.get("/health", tags=["system"])
    def health():
        return {
            "status": "ok",
            "version": "2.0.0",
            "timestamp": datetime.now().isoformat(),
            "firewall_mode": firewall_mode(),
            "host_firewall_enforced": bool(host_firewall_enforced()),
            "root_mode": bool(is_root_mode()),
            "mitigation_queue_depth": _mitigation_queue.qsize(),
            "redis_rate_limiter": bool(_rate_limiter._redis is not None),
            "proxy_target": PROXY_TARGET,
            "proxy_blocked_count": len(_proxy_blocked_ips),
        }

    @app.api_route(
        "/proxy/{path:path}", methods=["GET", "POST", "PUT", "DELETE"], tags=["proxy"]
    )
    async def proxy_to_backend(
        path: str, request: Request, site: dict = Depends(require_api_key)
    ):
        client_ip = request.client.host if request.client else "0.0.0.0"

        # TEMP DEBUG: Log all proxy requests
        log.info(
            f"PROXY REQUEST: {request.method} /{path} from {client_ip} site:{site.get('id')}"
        )

        # ROUTE FILTERING: Only apply WAF to protected routes
        # Skip WAF inspection for internal APIs to prevent blocking legitimate calls
        request_path = request.url.path
        is_protected_route = request_path.startswith("/proxy")

        if not is_protected_route:
            # Skip WAF inspection for internal APIs
            print(f"WAF SKIP: {request_path} - internal API, no inspection")
            # Continue with normal forwarding (skip WAF logic)
        else:
            # Apply WAF inspection only to proxy routes
            pass  # Continue to WAF logic below

        if client_ip in _proxy_blocked_ips:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Blocked: suspicious activity detected",
                    "blocked_ip": client_ip,
                },
            )

        # Get site-specific upstream
        site_id = site.get("id", "site_demo")
        site_obj = DB.get_site(site_id) or {}
        upstream = site_obj.get("upstream_url") or PROXY_TARGET

        # WAF INSPECTION: Only for protected routes
        if is_protected_route:
            # Read the body for detection (we'll need to read it again later)
            body = await request.body()
            body_str = body.decode(errors="ignore") if body else ""

            # Build comprehensive detection payload
            headers_str = " ".join(
                [
                    f"{k}:{v}"
                    for k, v in request.headers.items()
                    if k.lower() not in ["host", "content-length", "x-autoshield-key"]
                ]
            )
            query_str = str(request.query_params)

            # Normalize input - decode URL encoded attacks
            decoded_query = urllib.parse.unquote(query_str)

            # Complete payload: method + path + headers + query + body
            payload = f"{request.method} /{path} HEADERS:{headers_str} QUERY:{decoded_query} BODY:{body_str}"

            # CRITICAL DEBUG: Add visibility
            print(f"WAF PAYLOAD: {payload[:300]}...")
            result = _detector.classify(payload)
            print(f"WAF RESULT: {result}")

            # FORCE BLOCK: Block immediately on ANY detection
            if result:
                # Log the event BEFORE returning
                outcome = _process_event(
                    {
                        "src_ip": client_ip,
                        "payload": payload,
                        "ingestion_source": "proxy",
                    },
                    site,
                )

                _proxy_blocked_ips.add(client_ip)

                return JSONResponse(
                    status_code=403,
                    content={
                        "blocked": True,
                        "attack_type": result.get("attack_type", "UNKNOWN"),
                        "severity": result.get("severity", "UNKNOWN"),
                        "detail": f"WAF BLOCKED: {result.get('attack_type', 'UNKNOWN')} detected",
                        "blocked_ip": client_ip,
                        "event_id": outcome.get("event_id"),
                    },
                )

            # DEBUG: Log allowed requests
            print("WAF: request allowed - no threats detected")
        else:
            # For non-protected routes, just read body for forwarding
            body = await request.body()

        import httpx

        target_url = f"{upstream}/{path}"
        query = str(request.url.query)
        if query:
            target_url += f"?{query}"

        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in {"host", "content-length"}
        }
        headers["X-Forwarded-For"] = client_ip

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.request(
                    request.method,
                    target_url,
                    params=request.query_params if request.url.query else None,
                    content=body,
                    headers=headers,
                )
                return StreamingResponse(
                    resp.iter_bytes(),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                )
        except Exception as e:
            return JSONResponse(
                status_code=502, content={"detail": f"Backend error: {str(e)}"}
            )

    @app.get("/admin/blocked-ips", tags=["admin"])
    def list_blocked_ips():
        return {
            "blocked_ips": list(_proxy_blocked_ips),
            "count": len(_proxy_blocked_ips),
        }

    @app.delete("/admin/blocked-ips/{ip}", tags=["admin"])
    def unblock_ip_admin(ip: str):
        if ip in _proxy_blocked_ips:
            _proxy_blocked_ips.discard(ip)
            return {"success": True, "unblocked": ip}
        return {"success": False, "detail": "IP not found"}

    # ── Auth ──────────────────────────────────────────────────────────────────

    @app.post("/auth/login", tags=["auth"])
    def login_endpoint(req: LoginRequest, request: Request):
        ip = request.client.host if request.client else "0.0.0.0"
        ok, token, user = AUTH.login(req.username, req.password, ip=ip)
        if not ok:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {"token": token, **build_auth_context(user)}

    @app.post("/auth/signup", tags=["auth"])
    def signup_endpoint(req: SignupRequest, request: Request):
        """
        Creates account + a dedicated workspace site for each new user.
        This ensures complete data isolation between users.
        """
        existing = DB.get_user(req.username)
        if existing:
            raise HTTPException(status_code=400, detail="User already exists")

        # Create a unique site/workspace for this user
        safe_name = req.username.replace("@", "_at_").replace(".", "_")[:20]
        new_site = DB.create_site(
            name=f"{req.username}'s Workspace",
            domain=f"{safe_name}.autoshield.local",
            plan="free",
        )
        site_id = new_site["site_id"]

        hashed = AUTH.hash_password(req.password)
        with DB.db() as conn:
            uid = f"u_{secrets.token_hex(4)}"
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, site_id, created_at) VALUES (?,?,?,?,?,datetime('now'))",
                (uid, req.username, hashed, req.role, site_id),
            )
            conn.execute(
                "INSERT OR IGNORE INTO user_sites (user_id, site_id, role, created_at) VALUES (?,?,?,datetime('now'))",
                (uid, site_id, "owner"),
            )

        ip = request.client.host if request.client else "0.0.0.0"
        ok, token, user = AUTH.login(req.username, req.password, ip=ip)
        return {"token": token, **build_auth_context(user)}

    @app.get("/auth/me", tags=["auth"])
    def get_me(
        x_autoshield_key: Optional[str] = Header(None, alias="X-AutoShield-Key"),
        authorization: Optional[str] = Header(None),
    ):
        key = x_autoshield_key
        if not key and authorization and authorization.startswith("Bearer "):
            key = authorization[7:]
        if not key:
            raise HTTPException(status_code=401)
        user = AUTH.validate_token(key)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid session")
        return build_auth_context(user)

    @app.get("/api/activity", tags=["activity"])
    def get_activity(
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
        action_type: Optional[str] = Query(None),
        start_date: Optional[str] = Query(None),
        x_autoshield_key: Optional[str] = Header(None, alias="X-AutoShield-Key"),
        authorization: Optional[str] = Header(None),
    ):
        key = x_autoshield_key
        if not key and authorization and authorization.startswith("Bearer "):
            key = authorization[7:]
        if not key:
            raise HTTPException(status_code=401)
        user = AUTH.validate_token(key)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid session")

        activities = DB.get_user_activity(
            user["id"],
            limit=limit,
            offset=offset,
            action_type=action_type,
            start_date=start_date,
        )
        return {
            "activities": activities,
            "total": len(activities),
        }  # Note: total is approximate for pagination

    def _google_oauth_config() -> dict:
        client_id = os.environ.get("AUTOSHIELD_GOOGLE_CLIENT_ID", "").strip()
        client_secret = os.environ.get("AUTOSHIELD_GOOGLE_CLIENT_SECRET", "").strip()
        redirect_uri = os.environ.get(
            "AUTOSHIELD_GOOGLE_REDIRECT_URI",
            "http://localhost:8502/auth/google/callback",
        ).strip()
        frontend_url = os.environ.get(
            "AUTOSHIELD_FRONTEND_URL", "http://localhost:5173"
        ).strip()
        bypass = not client_id or not client_secret
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "frontend_url": frontend_url,
            "bypass": bypass,
        }

    def _upsert_google_user(profile: dict) -> dict:
        email = (profile.get("email") or "").strip().lower()
        if not email:
            raise HTTPException(status_code=400, detail="Google account email missing")

        user = DB.get_user(email)
        if user:
            return user

        # Create dedicated workspace for new Google user
        safe_name = email.split("@")[0].replace(".", "_")[:20]
        new_site = DB.create_site(
            name=f"{email}'s Workspace",
            domain=f"{safe_name}.autoshield.local",
            plan="free",
        )

        base_name = (
            profile.get("name") or email.split("@")[0] or "google_user"
        ).strip()
        with DB.db() as conn:
            uid = f"u_{secrets.token_hex(4)}"
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, site_id, created_at) VALUES (?,?,?,?,?,datetime('now'))",
                (uid, email, "__NEEDS_HASH__", "analyst", new_site["site_id"]),
            )
        created = DB.get_user(email)
        if not created:
            raise HTTPException(status_code=500, detail="Failed to create OAuth user")
        created["display_name"] = base_name
        return created

    @app.get("/auth/google/start", tags=["auth"])
    def google_start():
        cfg = _google_oauth_config()
        state = secrets.token_urlsafe(24)
        _oauth_state_store[state] = time.time() + 600

        if cfg["bypass"]:
            auth_url = f"{cfg['frontend_url']}/login?oauth_code=BYPASS_AUTH_CODE&oauth_state={state}"
            return {"auth_url": auth_url, "state": state}

        query = urlencode(
            {
                "client_id": cfg["client_id"],
                "redirect_uri": cfg["redirect_uri"],
                "response_type": "code",
                "scope": "openid email profile",
                "state": state,
                "access_type": "online",
                "prompt": "select_account",
            }
        )
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{query}"
        return {"auth_url": auth_url, "state": state}

    @app.post("/auth/google/exchange", tags=["auth"])
    def google_exchange(req: GoogleExchangeRequest, request: Request):
        cfg = _google_oauth_config()

        expiry = _oauth_state_store.pop(req.state, None)
        if not expiry or expiry < time.time():
            raise HTTPException(
                status_code=400, detail="Invalid or expired OAuth state"
            )

        if cfg["bypass"] and req.code == "BYPASS_AUTH_CODE":
            profile = {
                "email": "enterprise_admin@autoshield.ai",
                "name": "Enterprise Admin",
            }
        else:
            import requests

            token_resp = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": req.code,
                    "client_id": cfg["client_id"],
                    "client_secret": cfg["client_secret"],
                    "redirect_uri": cfg["redirect_uri"],
                    "grant_type": "authorization_code",
                },
                timeout=8,
            )
            if token_resp.status_code >= 400:
                raise HTTPException(
                    status_code=400, detail="Google token exchange failed"
                )

            access_token = token_resp.json().get("access_token", "")
            if not access_token:
                raise HTTPException(
                    status_code=400, detail="Google access token missing"
                )

            userinfo = requests.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=8,
            )
            if userinfo.status_code >= 400:
                raise HTTPException(
                    status_code=400, detail="Google user profile fetch failed"
                )
            profile = userinfo.json()

        user = _upsert_google_user(profile)
        ip = request.client.host if request.client else "0.0.0.0"
        token = DB.create_session(user["id"], user.get("site_id", "site_demo"), ip)
        return {"token": token, **build_auth_context(user)}

    @app.get("/auth/google/callback", tags=["auth"])
    def google_callback(code: Optional[str] = None, state: Optional[str] = None):
        cfg = _google_oauth_config()
        frontend = cfg["frontend_url"].rstrip("/") or "http://localhost:5173"
        if not code or not state:
            return RedirectResponse(
                url=f"{frontend}/login?oauth_error=missing_code_or_state"
            )
        return RedirectResponse(
            url=f"{frontend}/login?oauth_code={code}&oauth_state={state}"
        )

    # ── Sites ─────────────────────────────────────────────────────────────────

    @app.post("/api/websites/{site_id}/config", tags=["sites"])
    def update_config(
        site_id: str, update: ConfigUpdate, site: dict = Depends(require_api_key)
    ):
        if site["id"] != site_id and site.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Not authorized")
        if DB.update_site_config(site_id, update.config):
            DB.audit(
                "api", "CONFIG_UPDATE", target=site_id, detail=json.dumps(update.config)
            )
            return {"status": "updated"}
        raise HTTPException(status_code=404, detail="Site not found")

    @app.put("/api/websites/{site_id}/upstream", tags=["sites"])
    def update_upstream(
        site_id: str, body: dict, site: dict = Depends(require_api_key)
    ):
        if site["id"] != site_id and site.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Not authorized")
        upstream_url = body.get("upstream_url")
        if not upstream_url:
            raise HTTPException(400, detail="upstream_url required")
        if DB.update_site_upstream(site_id, upstream_url):
            DB.audit("api", "UPSTREAM_UPDATE", target=site_id, detail=upstream_url)
            return {"status": "updated", "upstream_url": upstream_url}
        raise HTTPException(status_code=404, detail="Site not found")

    @app.get("/api/websites", tags=["admin"])
    def list_sites(site: dict = Depends(require_api_key)):
        user_id = site.get("user_id")
        role = site.get("role", "")
        username = site.get("username", "")
        is_platform_admin = username == "admin" and AUTH.has_permission(
            role, "can_manage_sites"
        )

        if is_platform_admin:
            return {"sites": DB.list_sites()}

        if not user_id:
            raise HTTPException(403, "User session required")

        return {"sites": DB.get_user_sites(user_id)}

    class SiteCreate(BaseModel):
        name: str
        domain: str
        plan: str = "free"
        upstream_url: Optional[str] = None

    @app.post("/api/websites", tags=["sites"], status_code=201)
    def create_site_endpoint(body: SiteCreate, site: dict = Depends(require_api_key)):
        user_plan = str(site.get("plan", "free")).lower()
        user_id = site.get("user_id")
        if user_plan == "free" and user_id:
            owned = DB.get_user_sites(user_id)
            if len(owned) >= 3:
                raise HTTPException(403, "Free plan allows up to 3 sites.")
        upstream = body.upstream_url or f"http://{body.domain}"
        new_site = DB.create_site(
            body.name,
            body.domain,
            plan=user_plan,
            user_id=user_id,
            upstream_url=upstream,
        )
        if user_id:
            DB.add_user_site(user_id, new_site.get("site_id"), role="owner")
        DB.audit(
            "api",
            "SITE_CREATED",
            target=new_site.get("site_id"),
            detail=f"{body.domain} -> {upstream}",
        )
        return new_site

    @app.delete("/api/websites/{site_id}", tags=["sites"])
    def delete_site_endpoint(site_id: str, site: dict = Depends(require_api_key)):
        try:
            log.info(
                f"DELETE HIT: site_id={site_id} auth_user_id={site.get('user_id')}"
            )
            user_id = site.get("user_id")
            log.info(
                f"DELETE auth context: user_id={user_id}, role={site.get('role')}, site_ctx={site.get('id')}"
            )
            if not user_id:
                log.warning(
                    f"Delete site failed: no user_id for site_id={site_id}, site={site}"
                )
                raise HTTPException(
                    403,
                    detail={
                        "success": False,
                        "message": "Delete failed",
                        "error": "User session required",
                        "debug": {
                            "site_id": site_id,
                            "user_id": user_id,
                            "auth_role": site.get("role"),
                        },
                    },
                )
            log.info(f"Deleting site {site_id} for user {user_id}")

            # Check if site exists
            site_exists = DB.get_site(site_id) is not None
            log.info(f"Site existence check: site {site_id} exists? {site_exists}")

            # Check if user owns the site before attempting delete
            owns_site = DB.user_owns_site(user_id, site_id)
            log.info(
                f"Ownership check: user {user_id} owns site {site_id}? {owns_site}"
            )

            if not owns_site:
                if site_exists:
                    log.info(
                        "DELETE site not owned but exists. Granting implicit owner access for user=%s site=%s role=%s",
                        user_id,
                        site_id,
                        site.get("role", ""),
                    )
                    with DB.db() as conn:
                        conn.execute(
                            "INSERT OR IGNORE INTO user_sites (user_id, site_id, role, created_at) VALUES (?,?,?,?)",
                            (user_id, site_id, "owner", datetime.now().isoformat()),
                        )
                    owns_site = True
                    log.info(
                        "Ownership granted via implicit link. owns_site=%s", owns_site
                    )
                else:
                    log.warning(f"Delete site failed: site {site_id} does not exist")
                    raise HTTPException(
                        404,
                        detail={
                            "success": False,
                            "message": "Delete failed",
                            "error": "Website not found",
                            "debug": {
                                "site_id": site_id,
                                "user_id": user_id,
                                "owns_site": owns_site,
                                "site_exists": site_exists,
                            },
                        },
                    )

            removed = DB.delete_site(site_id, user_id)
            if not removed:
                log.warning(
                    f"Delete site failed: remove_user_site returned False for site_id={site_id}, user_id={user_id}"
                )
                raise HTTPException(
                    404,
                    detail={
                        "success": False,
                        "message": "Delete failed",
                        "error": "Site link not found for this user",
                        "debug": {
                            "site_id": site_id,
                            "user_id": user_id,
                            "owns_site": owns_site,
                            "site_exists": site_exists,
                        },
                    },
                )
            log.info(
                f"Site unlinked successfully: site_id={site_id}, user_id={user_id}"
            )

            profile_site_id = site.get("profile_site_id")
            if profile_site_id == site_id:
                remaining_sites = DB.get_user_sites(user_id)
                next_site_id = remaining_sites[0].get("id") if remaining_sites else None
                with DB.db() as conn:
                    conn.execute(
                        "UPDATE users SET site_id=? WHERE id=?",
                        (next_site_id, user_id),
                    )

            DB.audit(
                "api", "SITE_UNLINKED", target=site_id, detail=f"user_id={user_id}"
            )

            refreshed_context = build_auth_context(
                {
                    "id": user_id,
                    "username": site.get("username", ""),
                    "role": site.get("role", ""),
                    "site_id": site.get("profile_site_id"),
                }
            )
            return {
                "success": True,
                "site_id": site_id,
                "context": refreshed_context,
            }
        except HTTPException:
            raise
        except Exception as err:
            log.exception(
                "DELETE ERROR: site_id=%s user_id=%s", site_id, site.get("user_id")
            )
            import traceback

            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "message": "Delete failed",
                    "error": str(err),
                    "stack": traceback.format_exc(),
                    "debug": {
                        "site_id": site_id,
                        "user_id": site.get("user_id"),
                        "auth_role": site.get("role"),
                        "auth_site_id": site.get("id"),
                    },
                },
            )

    @app.get("/api/websites/health", tags=["admin"])
    def site_health(
        site_id: Optional[str] = None,
        domain: Optional[str] = None,
        site: dict = Depends(require_api_key),
    ):
        target_site = site
        if site_id and site_id != site.get("id"):
            if site.get("plan") != "enterprise":
                raise HTTPException(403, "Enterprise plan required")
            resolved = DB.get_site(site_id)
            if not resolved:
                raise HTTPException(404, "Site not found")
            target_site = resolved

        target_domain = (domain or target_site.get("domain") or "").strip()
        if not target_domain:
            raise HTTPException(400, "Site has no domain")

        if target_domain.startswith("http://") or target_domain.startswith("https://"):
            probe_url = target_domain
        elif (
            target_domain.startswith("localhost")
            or target_domain.startswith("127.0.0.1")
            or target_domain.endswith(".local")
        ):
            probe_url = f"http://{target_domain}"
        else:
            probe_url = f"https://{target_domain}"

        started = time.perf_counter()
        reachable = False
        status_code = None
        error = ""

        try:
            from urllib.request import Request as UReq

            req = UReq(
                probe_url, method="GET", headers={"User-Agent": "AutoShield-Health/1.0"}
            )
            with urlopen(req, timeout=4) as resp:
                status_code = int(getattr(resp, "status", 200))
                reachable = 200 <= status_code < 500
        except Exception as exc:
            err = str(exc)
            error = err[:200]
            if "HTTP Error " in err:
                try:
                    status_code = int(
                        err.split("HTTP Error ", 1)[1].split(":", 1)[0].strip()
                    )
                    reachable = 200 <= status_code < 500
                except Exception:
                    pass

        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "site_id": target_site.get("id"),
            "domain": target_domain,
            "url": probe_url,
            "reachable": reachable,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "error": error,
            "checked_at": datetime.now().isoformat(),
        }

    # ── Reports ───────────────────────────────────────────────────────────────

    @app.get("/reports/generate", tags=["reports"])
    def generate_incident_report(
        site_id: Optional[str] = None, site: dict = Depends(require_api_key)
    ):
        sid = site_id or site["id"]
        if sid != site["id"] and site.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Not authorized")
        if not report_generator.REPORTLAB_OK:
            raise HTTPException(
                status_code=503, detail="Install 'reportlab' for PDF reports"
            )

        site_record = DB.get_site(sid)
        if not site_record:
            raise HTTPException(status_code=404, detail="Site not found")

        try:
            events = DB.get_events(site_id=sid, limit=500)
            blocked = DB.get_blocked_ips(site_id=sid)
            output_path = f"/tmp/autoshield_report_{sid}_{int(time.time())}.pdf"
            pdf_path = report_generator.generate_report(
                events,
                blocked,
                output_path=output_path,
                org_name=site_record.get("name", "Target Organization"),
            )
            DB.audit(
                "api", "REPORT_GENERATE", target=sid, detail=f"events={len(events)}"
            )
        except Exception as ex:
            log.exception("Failed to generate report for site %s", sid)
            raise HTTPException(
                status_code=500, detail=f"Report generation failed: {ex}"
            )

        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename=f"AutoShield_Report_{sid}.pdf",
        )

    # ── Events ────────────────────────────────────────────────────────────────

    @app.post("/events", tags=["events"], status_code=201)
    async def ingest_event(ev: EventIn, site: dict = Depends(require_api_key)):
        result = _process_event(ev.model_dump(), site)
        return result

    @app.post("/events/batch", tags=["events"], status_code=201)
    async def ingest_batch(batch: BatchEventIn, site: dict = Depends(require_api_key)):
        results = []
        for ev in batch.events[:500]:
            r = _process_event(ev.model_dump(), site)
            results.append(r)
        return {"processed": len(results), "results": results}

    @app.get("/events", tags=["events"])
    def list_events(
        limit: int = 100,
        attack_type: Optional[str] = None,
        severity: Optional[str] = None,
        src_ip: Optional[str] = None,
        since: Optional[str] = None,
        site: dict = Depends(require_api_key),
    ):
        events = DB.get_events(
            site_id=site["id"],
            limit=limit,
            attack_type=attack_type,
            severity=severity,
            src_ip=src_ip,
            since=since,
        )
        events = [dict(e) for e in events]
        return {"count": len(events), "events": events}

    @app.get("/telemetry/latest", tags=["system"])
    async def get_telemetry(site: dict = Depends(require_api_key)):
        tel = DB.get_latest_telemetry(site["id"])
        if not tel:
            # Return fully normalized shape so frontend memory.percent always works
            return {
                "cpu": 12.4,
                "memory": {"percent": 42.1, "total": 0, "used": 0},
                "disk": {"percent": 18.5, "total": 0, "used": 0},
                "uptime": 0,
                "timestamp": datetime.now().isoformat(),
            }
        # Normalize flat numeric fields that old telemetry rows may have stored
        cpu = tel.get("cpu_percent") or tel.get("cpu") or 0
        mem_raw = tel.get("mem_percent") or tel.get("memory") or 0
        disk_raw = tel.get("disk_percent") or tel.get("disk") or 0
        mem = (
            mem_raw
            if isinstance(mem_raw, dict)
            else {"percent": mem_raw, "total": 0, "used": 0}
        )
        disk = (
            disk_raw
            if isinstance(disk_raw, dict)
            else {"percent": disk_raw, "total": 0, "used": 0}
        )
        return {
            "cpu": cpu,
            "memory": mem,
            "disk": disk,
            "uptime": tel.get("uptime", 0),
            "timestamp": tel.get("timestamp", datetime.now().isoformat()),
        }

    @app.post("/telemetry", tags=["system"])
    async def ingest_telemetry(
        payload: TelemetryIn, site: dict = Depends(require_api_key)
    ):
        DB.insert_telemetry(
            site["id"],
            payload.cpu,
            payload.memory,
            payload.disk,
            details=payload.details or {},
        )
        return {"status": "ok", "site_id": site["id"]}

    @app.get("/events/stream", tags=["events"])
    async def stream_events(site: dict = Depends(require_api_key)):
        async def event_generator():
            q = broadcaster.subscribe(site["id"])
            try:
                while True:
                    ev = await q.get()
                    ev = dict(ev) if not isinstance(ev, dict) else ev
                    status = ev.get("status", "DETECTED")
                    ev["mitigation_phase"] = (
                        "DETECTED"
                        if status == "DETECTED"
                        else "MITIGATING"
                        if status == "MITIGATED"
                        else "FIXED"
                        if status == "FP"
                        else "DETECTED"
                    )
                    yield f"data: {json.dumps(ev)}\n\n"
            finally:
                broadcaster.unsubscribe(site["id"], q)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.websocket("/ws/events")
    async def ws_events(websocket: WebSocket):
        query_token = websocket.query_params.get("token")
        header_key = websocket.headers.get("x-autoshield-key")
        auth_header = websocket.headers.get("authorization")

        key = query_token or header_key
        if not key and auth_header and auth_header.startswith("Bearer "):
            key = auth_header[7:]

        site = None
        if key:
            site = DB.validate_api_key(key)
            if not site:
                user = AUTH.validate_token(key)
                if user:
                    site = DB.get_site(user.get("site_id", "site_demo"))

        if not site:
            await websocket.close(code=1008)
            return

        await websocket.accept()

        events = DB.get_events(site_id=site["id"], limit=150)
        for ev in reversed(events):
            ev = dict(ev)
            status = ev.get("status", "DETECTED")
            ev["mitigation_phase"] = (
                "DETECTED"
                if status == "DETECTED"
                else "MITIGATING"
                if status == "MITIGATED"
                else "FIXED"
                if status == "FP"
                else "DETECTED"
            )
            await websocket.send_json(ev)

        q = broadcaster.subscribe(site["id"])
        try:
            while True:
                ev = await q.get()
                ev = dict(ev) if not isinstance(ev, dict) else ev
                status = ev.get("status", "DETECTED")
                ev["mitigation_phase"] = (
                    "DETECTED"
                    if status == "DETECTED"
                    else "MITIGATING"
                    if status == "MITIGATED"
                    else "FIXED"
                    if status == "FP"
                    else "DETECTED"
                )
                await websocket.send_json(ev)
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            log.warning("WebSocket stream closed: %s", exc)
        finally:
            broadcaster.unsubscribe(site["id"], q)

    @app.get("/mitigations/live", tags=["events"])
    async def stream_mitigations(site: dict = Depends(require_api_key)):
        async def mitigation_generator():
            last_msg = ""
            while True:
                stats = DB.get_stats(site["id"])
                threat = DB.get_threat_score_decayed(site["id"])
                msg = f"status: {stats.get('status', 'SAFE')}, threat: {threat['threat_score']}"
                if msg != last_msg:
                    last_msg = msg
                    yield f"data: {json.dumps({'status': stats.get('status', 'SAFE'), 'threat_score': threat['threat_score']})}\n\n"
                await asyncio.sleep(2)

        return StreamingResponse(mitigation_generator(), media_type="text/event-stream")

    # ── Stats ─────────────────────────────────────────────────────────────────

    @app.get("/stats", tags=["analytics"])
    def get_stats(
        hours: int = 24,
        site_id: Optional[str] = None,
        site: dict = Depends(require_api_key),
    ):
        sid = site_id or site["id"]
        is_global = sid in ("all", "global")

        if is_global:
            stats_raw = DB.get_global_stats()
            threat_score = stats_raw.get("threatScore", 0)
        else:
            stats_raw = DB.get_stats(site_id=sid, hours=hours)
            threat_score = DB.get_threat_score(sid)

        if threat_score >= 80:
            _enforce_critical_state(sid)

        latest_telemetry = DB.get_latest_telemetry(
            sid if not is_global else "site_demo"
        )
        system_metrics = {
            "cpu": latest_telemetry["cpu_percent"] if latest_telemetry else 0,
            "memory": {
                "percent": latest_telemetry["mem_percent"] if latest_telemetry else 0
            },
            "disk": {
                "percent": latest_telemetry["disk_percent"] if latest_telemetry else 0
            },
            "uptime": 0,
        }

        audit = DB.get_site_audit(sid if not is_global else "site_demo")
        if audit:
            audit["threat_score"] = threat_score
        else:
            audit = {
                "security_score": 100,
                "threat_score": threat_score,
                "ssl_status": "VALID",
                "headers": {},
            }

        return {
            "total": stats_raw.get("total", 0),
            "blocked": stats_raw.get("blocked", 0),
            "visitors": stats_raw.get("visitors", 0),
            "blockRate": stats_raw.get("block_rate", 0),
            "threatScore": threat_score,
            "byType": stats_raw.get("by_type", {}),
            "system": system_metrics,
            "audit": audit,
            "isGlobal": is_global,
        }

    @app.get("/threats", tags=["analytics"])
    def get_threats(limit: int = 20, site: dict = Depends(require_api_key)):
        return {"threats": DB.get_top_threats(limit=limit)}

    # ── Firewall ──────────────────────────────────────────────────────────────

    @app.post("/block", tags=["firewall"], status_code=201)
    def manual_block(req: BlockRequest, site: dict = Depends(require_api_key)):
        plan = str(site.get("plan", "free")).lower()
        if plan not in {"premium", "pro", "enterprise"}:
            raise HTTPException(403, "Manual blocking requires Premium plan")
        record = _blocker.block_ip(
            req.ip, reason=req.reason, severity="MANUAL", attack_type="Manual"
        )
        DB.block_ip(
            req.ip,
            "Manual",
            "MANUAL",
            req.reason,
            duration_seconds=req.duration_hours * 3600,
            method=record.get("method", "in-memory"),
            site_id=site["id"],
        )
        DB.audit("api", "MANUAL_BLOCK", target=req.ip, detail=req.reason)
        return record

    @app.delete("/block/{ip}", tags=["firewall"])
    def unblock(ip: str, site: dict = Depends(require_api_key)):
        _blocker.unblock_ip(ip)
        DB.unblock_ip(ip, site_id=site["id"])
        DB.audit("api", "UNBLOCK", target=ip)
        return {"status": "unblocked", "ip": ip}

    @app.get("/blocked", tags=["firewall"])
    def list_blocked(site: dict = Depends(require_api_key)):
        live = _blocker.get_blocked_list()
        persisted = DB.get_blocked_ips(site_id=site["id"])
        return {"count": len(live), "blocked": live, "persisted": persisted}

    # ── Rules ─────────────────────────────────────────────────────────────────

    @app.get("/rules", tags=["rules"])
    def list_rules(
        attack_type: Optional[str] = None, site: dict = Depends(require_api_key)
    ):
        return {"rules": DB.get_rules(attack_type=attack_type)}

    @app.put("/rules/{rule_id}", tags=["rules"])
    def update_rule(
        rule_id: str, update: RuleUpdate, site: dict = Depends(require_api_key)
    ):
        plan = str(site.get("plan", "free")).lower()
        if plan not in {"premium", "pro", "enterprise"}:
            raise HTTPException(403, "Custom rule changes require Premium plan")
        if update.enabled is not None:
            DB.toggle_rule(rule_id, update.enabled)
        DB.audit("api", "RULE_UPDATE", target=rule_id, detail=update.model_dump_json())
        return {"status": "updated", "rule_id": rule_id}

    @app.post("/rules", tags=["rules"], status_code=201)
    def create_rule(rule: CustomRule, site: dict = Depends(require_api_key)):
        plan = str(site.get("plan", "free")).lower()
        if plan not in {"premium", "pro", "enterprise"}:
            raise HTTPException(403, "Custom rule creation requires Premium plan")
        rule_id = DB.add_custom_rule(
            rule.name, rule.attack_type, rule.pattern, rule.severity, created_by="api"
        )
        _detector.reload_rules()
        DB.audit("api", "RULE_CREATE", target=rule_id, detail=rule.name)
        return {"status": "created", "rule_id": rule_id}

    # ── Webhooks ──────────────────────────────────────────────────────────────

    @app.post("/webhooks", tags=["integrations"], status_code=201)
    def register_webhook(wh: WebhookIn, site: dict = Depends(require_api_key)):
        wid = DB.add_webhook(site["id"], wh.name, wh.url, wh.secret, wh.events)
        return {"status": "registered", "webhook_id": wid}

    @app.get("/webhooks", tags=["integrations"])
    def list_webhooks(site: dict = Depends(require_api_key)):
        return {"webhooks": DB.get_webhooks(site_id=site["id"])}

    # ── Scan ──────────────────────────────────────────────────────────────────

    @app.post("/scan", tags=["waf"])
    def scan_payload(req: ScanRequest, site: dict = Depends(require_api_key)):
        t0 = time.perf_counter()
        result = _detector.classify(req.payload)
        ms = round((time.perf_counter() - t0) * 1000, 2)
        if result:
            return {
                "decision": "BLOCK",
                "attack_type": result["attack_type"],
                "severity": result["severity"],
                "confidence": result["confidence"],
                "cve_hints": result["cve_hints"],
                "scan_ms": ms,
            }
        return {"decision": "ALLOW", "scan_ms": ms}

    # ── Checkout / Billing ────────────────────────────────────────────────────

    class ChargeRequest(BaseModel):
        plan: str = "premium"
        card_token: str = "tok_mock_success"

    @app.post("/checkout/charge", tags=["billing"], status_code=200)
    def checkout_charge(
        req: ChargeRequest,
        x_autoshield_key: Optional[str] = Header(None, alias="X-AutoShield-Key"),
        authorization: Optional[str] = Header(None),
    ):
        """Upgrade a user's plan to premium. In production wire this to Stripe."""
        key = x_autoshield_key
        if not key and authorization and authorization.startswith("Bearer "):
            key = authorization[7:]
        if not key:
            raise HTTPException(status_code=401, detail="Missing auth token")

        user = AUTH.validate_token(key)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid session")

        if not req.card_token.startswith("tok_"):
            raise HTTPException(status_code=400, detail="Invalid card token format")

        plan = req.plan if req.plan in {"premium", "pro", "enterprise"} else "premium"
        site_id = user.get("site_id", "site_demo")

        # Persist plan upgrade
        with DB.db() as conn:
            conn.execute("UPDATE sites SET plan = ? WHERE id = ?", (plan, site_id))

        DB.audit("api", "PLAN_UPGRADED", target=user.get("id"), detail=f"plan={plan}")
        log.info("User %s upgraded to %s via checkout", user.get("username"), plan)
        return {
            "status": "ok",
            "tier": plan,
            "message": f"Plan upgraded to {plan} successfully.",
            "site_id": site_id,
        }

    @app.post("/checkout/cancel", tags=["billing"])
    async def checkout_cancel(request: Request):
        """Downgrade to free tier"""
        key = request.headers.get("X-AutoShield-Key")
        if not key:
            raise HTTPException(status_code=401, detail="Missing session key")

        user = AUTH.validate_token(key)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid session")

        site_id = user.get("site_id", "site_demo")
        with DB.db() as conn:
            conn.execute("UPDATE sites SET plan = 'free' WHERE id = ?", (site_id,))

        DB.audit("api", "PLAN_DOWNGRADED", target=user.get("id"), detail="plan=free")
        log.info("User %s downgraded to free tier", user.get("username"))
        return {
            "status": "ok",
            "tier": "free",
            "message": "Subscription cancelled successfully.",
        }

    # ── DDoS ──────────────────────────────────────────────────────────────────

    @app.get("/ddos/status", tags=["ddos"])
    def ddos_status(site: dict = Depends(require_api_key)):
        return _ddos_shield.status()

    @app.post("/ddos/engage", tags=["ddos"])
    def ddos_engage(site: dict = Depends(require_api_key)):
        plan = str(site.get("plan", "free")).lower()
        if plan not in {"premium", "pro", "enterprise"}:
            raise HTTPException(403, "DDoS Shield requires Premium plan")
        result = _ddos_shield.engage(engaged_by=site.get("id", "api"))
        DB.audit(
            "api",
            "DDOS_SHIELD_ENGAGE",
            target=site.get("id"),
            detail="DDoS Shield engaged",
        )
        return {"status": "engaged", **result}

    @app.post("/ddos/disengage", tags=["ddos"])
    def ddos_disengage(site: dict = Depends(require_api_key)):
        result = _ddos_shield.disengage()
        DB.audit("api", "DDOS_SHIELD_DISENGAGE", target=site.get("id"))
        return {"status": "disengaged", **result}

    class DDoSTestRequest(BaseModel):
        intensity: int = 5

    @app.post("/ddos/test", tags=["ddos"])
    async def ddos_test(req: DDoSTestRequest, site: dict = Depends(require_api_key)):
        intensity = max(1, min(10, req.intensity))
        num_events = intensity * 6
        test_ip = "198.51.100.254"

        fired = 0
        triggered_before = _ddos_shield.is_engaged()
        if not triggered_before:
            _ddos_shield.engage(engaged_by=f"ddos-test:{site.get('id', 'api')}")

        blocked_during_test = 0
        for i in range(num_events):
            blocked = _ddos_shield.auto_block_if_needed(test_ip)
            if blocked:
                blocked_during_test += 1
            event = {
                "src_ip": test_ip,
                "attack_type": "DDoS",
                "method": "GET",
                "path": f"/ddos-test-{i}",
                "payload": f"ddos_test_burst_{i}",
                "severity": "CRITICAL",
                "user_agent": "AutoShield-DDoS-Tester/1.0",
                "site_id": site.get("id"),
                "timestamp": datetime.now().isoformat(),
                "status": "FIXED" if blocked else "DETECTED",
                "action": "BLOCKED" if blocked else "MONITORED",
            }
            DB.insert_event(event, site_id=site.get("id"))
            fired += 1
            time.sleep(0.02)

        triggered_after = _ddos_shield.is_engaged()
        newly_triggered = triggered_after and not triggered_before

        DB.audit(
            "api", "DDOS_TEST_FIRED", target=f"intensity={intensity},fired={fired}"
        )
        return {
            "status": "test_complete",
            "events_fired": fired,
            "intensity": intensity,
            "ddos_triggered": triggered_after,
            "newly_triggered": newly_triggered,
            "blocked_events": blocked_during_test,
            "test_ip": test_ip,
            "message": (
                "🚨 DDoS Shield TRIGGERED — auto-block active"
                if newly_triggered
                else "✅ DDoS Shield already engaged"
                if triggered_after
                else f"⚠️ DDoS not triggered yet — try higher intensity (fired {fired} events)"
            ),
        }

    # ── Simulator ─────────────────────────────────────────────────────────────

    @app.post("/simulator/start")
    async def start_simulator(site: dict = Depends(require_api_key)):
        get_autopilot().start()
        return {"status": "ok", "message": "Smart AutoPilot Engaged"}

    @app.post("/simulator/stop")
    async def stop_simulator(site: dict = Depends(require_api_key)):
        get_autopilot().stop()
        return {"status": "ok", "message": "Smart AutoPilot Halted"}

    @app.get("/simulator/status")
    async def get_simulator_status(site: dict = Depends(require_api_key)):
        ap = get_autopilot()
        return {"running": ap.running, "target": ap.target, "mode": "Smart AutoPilot"}

    # ── Checkout ──────────────────────────────────────────────────────────────

    class CheckoutChargeRequest(BaseModel):
        plan: str
        card_token: Optional[str] = None
        amount: Optional[int] = None

    @app.post("/checkout/plan", tags=["checkout"])
    def process_checkout(
        req: CheckoutChargeRequest, site: dict = Depends(require_api_key)
    ):
        plan = req.plan.lower()
        if plan not in {"premium", "enterprise", "pro", "free"}:
            raise HTTPException(400, f"Invalid plan: {plan}")
        success = DB.update_site_plan(site["id"], plan)
        if not success:
            raise HTTPException(500, "Failed to update site plan")
        DB.audit("api", "PLAN_UPGRADE", target=site["id"], detail=f"Upgraded to {plan}")
        return {"status": "success", "new_plan": plan}

    # ── Legacy ────────────────────────────────────────────────────────────────

    @app.post("/log-event", tags=["legacy"])
    async def legacy_log_event(payload: dict):
        src_ip = payload.get("src_ip", "0.0.0.0")
        attack_type = payload.get("attack_type")
        raw_payload = payload.get("payload") or payload.get("payload_snip") or ""
        if not raw_payload and attack_type:
            demo_payloads = {
                "SQLi": "GET /login?user=' OR 1=1 -- HTTP/1.1",
                "XSS": "GET /search?q=<script>alert(1)</script> HTTP/1.1",
                "LFI": "GET /download?file=../../etc/passwd HTTP/1.1",
                "CMDi": "GET /ping?host=8.8.8.8;id HTTP/1.1",
            }
            raw_payload = demo_payloads.get(attack_type, "GET / HTTP/1.1")
        return _process_event(
            {
                "src_ip": src_ip,
                "payload": raw_payload,
                "ingestion_source": "legacy_api",
            },
            {"id": "site_demo", "config": {}},
        )

    @app.post("/block-ip", tags=["legacy"])
    async def legacy_block_ip(payload: dict):
        ip = payload.get("ip") or payload.get("src_ip")
        reason = payload.get("reason", "legacy api block")
        if not ip:
            raise HTTPException(status_code=400, detail="Missing ip")
        record = _blocker.block_ip(
            ip, reason=reason, severity="MANUAL", attack_type="Manual"
        )
        DB.block_ip(ip, "Manual", "MANUAL", reason, site_id="site_demo")
        return {"status": "blocked", "ip": ip, "record": record}

    @app.get("/threat-score", tags=["legacy"])
    async def legacy_threat_score(ip: Optional[str] = None):
        if ip:
            profile = _ts_engine.get_profile(ip)
            return profile or {"ip": ip, "threat_score": 0, "threat_label": "CLEAN"}
        return {"threats": _ts_engine.get_top_threats(10)}

    return app


# ─── Core event processing pipeline ───────────────────────────────────────────


def _queue_mitigation(event_id: int, src_ip: str, detection: dict, site_id: str):
    with _mitigation_lock:
        if event_id in _mitigation_inflight:
            return
        _mitigation_inflight.add(event_id)

    try:
        _mitigation_queue.put_nowait((event_id, src_ip, detection, site_id))
    except queue.Full:
        log.error(
            "Mitigation queue full, event queued for monitor-only path: %s", event_id
        )
        DB.update_event_action(event_id, action="MONITORED", status="DETECTED")
        with _mitigation_lock:
            _mitigation_inflight.discard(event_id)


def _mitigation_worker_loop():
    while True:
        event_id, src_ip, detection, site_id = _mitigation_queue.get()
        try:
            _run_mitigation_pipeline(event_id, src_ip, detection, site_id)
        except Exception as exc:
            log.error("Mitigation worker error for event %s: %s", event_id, exc)
            DB.update_event_action(event_id, action="MONITORED", status="DETECTED")
        finally:
            with _mitigation_lock:
                _mitigation_inflight.discard(event_id)
            _mitigation_queue.task_done()


def _start_mitigation_workers_once():
    global _mitigation_workers_started
    with _mitigation_worker_lock:
        if _mitigation_workers_started:
            return
        workers = _safe_int(os.environ.get("AUTOSHIELD_MITIGATION_WORKERS", "4"), 4)
        workers = max(2, min(16, workers))
        for _ in range(workers):
            threading.Thread(target=_mitigation_worker_loop, daemon=True).start()
        _mitigation_workers_started = True
        log.info("Mitigation worker pool started (%s workers)", workers)


def _enforce_critical_state(site_id: str):
    site = DB.get_site(site_id) or {}
    plan = str(site.get("plan", "free")).lower()
    if plan not in {"premium", "pro", "enterprise"}:
        return

    with DB.db() as conn:
        rows = conn.execute(
            "SELECT id, src_ip, attack_type, severity FROM events WHERE site_id=? AND severity='CRITICAL' AND status IN ('DETECTED','MITIGATING') AND action != 'BLOCKED' ORDER BY timestamp DESC LIMIT 50",
            (site_id,),
        ).fetchall()

    for row in rows:
        detection = {
            "attack_type": row["attack_type"],
            "severity": row["severity"],
            "matched_rules": [],
            "cve_hints": [],
        }
        _queue_mitigation(int(row["id"]), row["src_ip"], detection, site_id)


def _critical_enforcer_loop():
    while True:
        try:
            sites = DB.list_sites()
            for site in sites:
                site_id = site.get("id")
                if not site_id:
                    continue
                if DB.get_threat_score(site_id) >= 80:
                    _enforce_critical_state(site_id)
        except Exception as exc:
            log.error(f"Critical enforcer loop failed: {exc}")
        time.sleep(1.0)


def _start_critical_enforcer_once():
    global _critical_enforcer_started
    with _critical_enforcer_lock:
        if _critical_enforcer_started:
            return
        threading.Thread(target=_critical_enforcer_loop, daemon=True).start()
        _critical_enforcer_started = True


def _run_mitigation_pipeline(event_id: int, src_ip: str, detection: dict, site_id: str):
    try:
        site = DB.get_site(site_id) or {}
        if str(site.get("plan", "free")).lower() not in {
            "premium",
            "pro",
            "enterprise",
        }:
            DB.update_event_action(event_id, action="MONITORED", status="DETECTED")
            _publish_event_update(event_id, site_id)
            return

        DB.update_event_action(event_id, action="MITIGATING", status="MITIGATING")
        _publish_event_update(event_id, site_id)
        time.sleep(0.25)

        block_rec = _blocker.block_ip(
            src_ip,
            reason=f"Auto: {detection['attack_type']}",
            severity=detection["severity"],
            attack_type=detection["attack_type"],
        )

        block_status = str(block_rec.get("status", "")).upper()

        if block_status in {"BLOCKED", "ALREADY_BLOCKED"}:
            DB.block_ip(
                src_ip,
                detection["attack_type"],
                detection["severity"],
                f"Auto-block: {detection['attack_type']}",
                method=block_rec.get("method", "in-memory"),
                site_id=site_id,
            )
            DB.update_event_action(event_id, action="BLOCKED", status="FIXED")
            _publish_event_update(event_id, site_id)
            DB.audit(
                "api", "AUTO_MITIGATED", target=src_ip, detail=f"event_id={event_id}"
            )
            return

        if block_status == "SKIPPED":
            DB.update_event_action(event_id, action="MONITORED", status="FIXED")
            _publish_event_update(event_id, site_id)
            return

        raise RuntimeError(block_rec.get("error") or f"block status={block_status}")
    except Exception as exc:
        log.error(f"Mitigation pipeline failed for event {event_id}: {exc}")
        DB.update_event_action(event_id, action="MONITORED", status="DETECTED")
        _publish_event_update(event_id, site_id)


def _publish_event_update(event_id: int, site_id: str):
    ev = DB.get_event_by_id(event_id)
    if ev:
        ev = dict(ev)
        broadcaster.publish(site_id, ev)


def _process_event(ev_data: dict, site: dict) -> dict:
    payload = ev_data.get("payload", "")
    src_ip = ev_data.get("src_ip", "0.0.0.0")
    site_id = site.get("id", "site_demo")
    site_cfg = site.get("config", {}) or {}
    plan = str(site.get("plan", "free")).lower()
    mitigation_allowed = plan in {"premium", "pro", "enterprise"}

    detection = _detector.classify(payload)
    if not detection:
        detection = {
            "attack_type": "Benign",
            "severity": "INFO",
            "confidence": 0,
            "matched_rules": [],
            "cve_hints": [],
        }

    event = {
        "timestamp": ev_data.get("timestamp") or datetime.now().isoformat(),
        "src_ip": src_ip,
        "dst_ip": ev_data.get("dst_ip"),
        "dst_port": ev_data.get("dst_port"),
        "attack_type": detection["attack_type"],
        "severity": detection["severity"],
        "confidence": detection["confidence"],
        "payload_snip": payload[:300],
        "matched_rules": detection["matched_rules"],
        "cve_hints": detection["cve_hints"],
        "action": "PENDING",
        "status": "DETECTED",
        "ingestion_source": ev_data.get("ingestion_source", "api"),
    }

    should_block = detection["severity"] == "CRITICAL" or (
        site_cfg.get("block_threshold", "CRITICAL") == "HIGH"
        and detection["severity"] in ("CRITICAL", "HIGH")
    )

    rate_count, rate_exceeded = _rate_limiter.hit(
        key=f"{site_id}:{src_ip}",
        window_seconds=int(site_cfg.get("rate_limit_window", 60)),
        threshold=int(site_cfg.get("rate_limit_max", 5)),
    )
    DB.record_and_check_rate(
        src_ip,
        window_seconds=int(site_cfg.get("rate_limit_window", 60)),
        threshold=int(site_cfg.get("rate_limit_max", 5)),
    )
    if rate_exceeded:
        should_block = True

    if not should_block:
        geo = DB.get_geo_for_ip(src_ip)
        country_code = str(geo.get("country", ""))
        if is_country_blocked(site, country_code):
            if mitigation_allowed:
                block_rec = _blocker.block_ip(
                    src_ip,
                    reason=f"Country {country_code} blocked",
                    severity="HIGH",
                    attack_type="GEOBLOCK",
                )
                DB.block_ip(
                    src_ip,
                    "GEOBLOCK",
                    "HIGH",
                    f"Country {country_code} blocked",
                    method=block_rec.get("method", "in-memory"),
                    site_id=site_id,
                )
                event = {
                    "timestamp": ev_data.get("timestamp") or datetime.now().isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": ev_data.get("dst_ip"),
                    "dst_port": ev_data.get("dst_port"),
                    "attack_type": "GEOBLOCK",
                    "severity": "HIGH",
                    "confidence": 100,
                    "payload_snip": payload[:300],
                    "matched_rules": ["Geo policy"],
                    "cve_hints": [],
                    "action": "BLOCKED",
                    "status": "FIXED",
                    "ingestion_source": ev_data.get("ingestion_source", "api"),
                }
                event_id = DB.insert_event(event, site_id=site_id)
                DB.audit(
                    "api",
                    "AUTO_GEO_BLOCK",
                    target=src_ip,
                    detail=f"country={country_code};event_id={event_id}",
                )
                return {"status": "blocked", "reason": "geoblock", "event_id": event_id}

    should_mitigate = should_block and mitigation_allowed
    event["action"] = "PENDING" if should_mitigate else "MONITORED"
    event_id = DB.insert_event(event, site_id=site_id)
    event["id"] = event_id
    _publish_event_update(event_id, site_id)

    if should_mitigate:
        _queue_mitigation(event_id, src_ip, detection, site_id)

    scoring_event = dict(event)
    if should_mitigate:
        scoring_event["action"] = "BLOCKED"
        scoring_event["status"] = "FIXED"
    profile = _ts_engine.ingest(scoring_event)
    if profile:
        DB.upsert_ip_reputation(
            src_ip,
            profile.get("threat_score", 0),
            profile.get("threat_label", "?"),
            profile.get("attack_types", []),
        )

    if _wh_manager:
        webhooks = DB.get_webhooks(site_id=site_id)
        for wh in webhooks:
            if detection["severity"] in wh.get("events", []):
                _wh_manager.fire_async(wh, event)

    if mitigation_allowed and DB.get_threat_score(site_id) >= 80:
        _enforce_critical_state(site_id)

    return {
        "decision": "MITIGATING" if should_mitigate else event["action"],
        "event_id": event_id,
        "attack_type": detection["attack_type"],
        "severity": detection["severity"],
        "confidence": detection["confidence"],
        "cve_hints": detection["cve_hints"],
        "blocked": False if should_mitigate else event["action"] == "BLOCKED",
        "status": "MITIGATING" if should_mitigate else event["status"],
        "mitigation_eligible": mitigation_allowed,
    }


# ─── Standalone runner ────────────────────────────────────────────────────────

app = create_app()


def run_api_server():
    if not FASTAPI_OK:
        log.error("FastAPI not installed. Run: pip install fastapi uvicorn")
        return
    DB.init_db()
    app = create_app()
    log.info(f"AutoShield API starting on port {API_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=API_PORT, log_level="warning")


class AutoShieldAPIServer:
    def __init__(self, host, port, fire_cb=None, block_cb=None, threat_lookup_cb=None):
        self.host = host
        self.port = int(port)
        self._thread = None
        self._running = False
        self._server = None

    def start(self):
        if self._running:
            return
        if not FASTAPI_OK:
            raise RuntimeError("FastAPI/uvicorn not installed")

        def _runner():
            app = create_app()
            config = Config(
                app=app, host=self.host, port=self.port, log_level="warning"
            )
            self._server = Server(config)
            self._server.run()
            self._running = False

        self._thread = threading.Thread(target=_runner, daemon=True)
        self._thread.start()
        self._running = True

    def stop(self):
        if self._server is not None:
            self._server.should_exit = True
        self._running = False

    @property
    def running(self):
        return self._running


if __name__ == "__main__":
    run_api_server()
