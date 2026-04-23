"""
AutoShield — JavaScript Challenge System
==========================================
Proof-of-work bot detection system. When the EscalationEngine returns CHALLENGE
(score 40-79), this module serves an HTML page containing a SHA-256 nonce-finding
puzzle. Legitimate browsers solve it in ~1-3 seconds; most bots/scrapers fail.

Flow:
  1. proxy_to_backend() detects CHALLENGE decision
  2. check_challenge_cookie() returns False (no valid bypass cookie)
  3. Serve challenge HTML page (auto-solving JS puzzle)
  4. Browser POSTs solution to /challenge/verify
  5. Server validates nonce → issues HMAC-signed bypass cookie (30 min TTL)
  6. Browser retries original request → cookie valid → request passes through

Why this surpasses Hostinger:
  - Hostinger has no challenge system (binary block/allow only)
  - Cloudflare uses similar JS challenges but with proprietary Turnstile
  - AutoShield's PoW challenge is transparent, open, and configurable
"""

import os
import time
import hmac
import json
import hashlib
import secrets
import logging
from datetime import datetime
from typing import Optional, Tuple

log = logging.getLogger("AutoShield.Challenge")

# ── Configuration ───────────────────────────────────────────────────────────
CHALLENGE_SECRET = os.environ.get(
    "AUTOSHIELD_CHALLENGE_SECRET",
    "autoshield-challenge-default-key-change-in-production",
)
CHALLENGE_TTL = int(os.environ.get("AUTOSHIELD_CHALLENGE_TTL", "1800"))  # 30 min
CHALLENGE_DIFFICULTY = int(os.environ.get("AUTOSHIELD_CHALLENGE_DIFFICULTY", "4"))  # leading hex zeros

# Cookie name for the bypass token
COOKIE_NAME = "as_challenge_token"


# ── Token Generation & Validation ───────────────────────────────────────────

def _sign(data: str) -> str:
    """HMAC-SHA256 sign a string."""
    return hmac.new(
        CHALLENGE_SECRET.encode(), data.encode(), hashlib.sha256
    ).hexdigest()


def generate_challenge(client_ip: str, path: str = "/") -> dict:
    """Generate a unique challenge for a client IP + path combination."""
    timestamp = int(time.time())
    nonce_prefix = secrets.token_hex(16)
    challenge_id = hashlib.sha256(
        f"{client_ip}:{path}:{nonce_prefix}:{timestamp}".encode()
    ).hexdigest()[:32]

    return {
        "challenge_id": challenge_id,
        "prefix": nonce_prefix,
        "difficulty": CHALLENGE_DIFFICULTY,
        "timestamp": timestamp,
        "signature": _sign(f"{challenge_id}:{nonce_prefix}:{timestamp}"),
    }


def verify_solution(
    challenge_id: str,
    prefix: str,
    nonce: str,
    timestamp: int,
    signature: str,
    client_ip: str,
) -> Tuple[bool, str]:
    """Verify a client's proof-of-work solution.

    Returns (success, reason).
    """
    # 1. Check timestamp freshness (challenge must be < 5 min old)
    if abs(time.time() - timestamp) > 300:
        return False, "Challenge expired"

    # 2. Verify HMAC signature (prevents forged challenges)
    expected_sig = _sign(f"{challenge_id}:{prefix}:{timestamp}")
    if not hmac.compare_digest(signature, expected_sig):
        return False, "Invalid challenge signature"

    # 3. Verify the proof-of-work: SHA256(prefix + nonce) must start with N zeros
    solution = hashlib.sha256(f"{prefix}{nonce}".encode()).hexdigest()
    required_prefix = "0" * CHALLENGE_DIFFICULTY
    if not solution.startswith(required_prefix):
        return False, f"Invalid proof-of-work (need {CHALLENGE_DIFFICULTY} leading zeros)"

    return True, "OK"


def create_bypass_cookie(client_ip: str) -> str:
    """Create an HMAC-signed bypass cookie value.

    Format: {ip}:{expiry}:{signature}
    """
    expiry = int(time.time()) + CHALLENGE_TTL
    payload = f"{client_ip}:{expiry}"
    sig = _sign(payload)
    return f"{payload}:{sig}"


def validate_bypass_cookie(cookie_value: str, client_ip: str) -> bool:
    """Validate an HMAC-signed bypass cookie.

    Returns True if the cookie is valid, not expired, and matches the client IP.
    """
    if not cookie_value:
        return False
    try:
        parts = cookie_value.split(":")
        if len(parts) != 3:
            return False
        stored_ip, expiry_str, sig = parts
        expiry = int(expiry_str)

        # Check expiry
        if time.time() > expiry:
            return False

        # Check IP match (optional: can be disabled for mobile clients)
        if stored_ip != client_ip:
            return False

        # Verify HMAC
        expected_sig = _sign(f"{stored_ip}:{expiry_str}")
        return hmac.compare_digest(sig, expected_sig)

    except (ValueError, TypeError):
        return False


# ── Challenge HTML Page ──────────────────────────────────────────────────────

def render_challenge_html(challenge: dict, original_url: str = "/") -> str:
    """Render the JavaScript challenge page.

    The page auto-solves the SHA-256 puzzle using Web Workers for performance,
    then POSTs the solution to /challenge/verify and retries the original URL.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check - AutoShield</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: system-ui, -apple-system, sans-serif;
    background: #0a0e1a;
    color: #c9d1d9;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    overflow: hidden;
  }}
  .card {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 16px;
    padding: 2.5rem 3rem;
    text-align: center;
    max-width: 480px;
    width: 90%;
    position: relative;
    z-index: 1;
  }}
  .shield {{
    width: 64px; height: 64px;
    margin: 0 auto 1.5rem;
    border-radius: 50%;
    background: linear-gradient(135deg, #00d4ff22, #7c3aed22);
    border: 2px solid #00d4ff44;
    display: flex; align-items: center; justify-content: center;
    font-size: 28px;
    animation: pulse-ring 2s ease-in-out infinite;
  }}
  @keyframes pulse-ring {{
    0%, 100% {{ box-shadow: 0 0 0 0 #00d4ff33; }}
    50% {{ box-shadow: 0 0 0 12px #00d4ff00; }}
  }}
  h1 {{
    color: #00d4ff;
    font-size: 1.3rem;
    margin-bottom: 0.5rem;
    font-weight: 700;
  }}
  .sub {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 1.5rem; line-height: 1.5; }}
  .progress-wrap {{
    background: #0d1117;
    border-radius: 8px;
    height: 6px;
    overflow: hidden;
    margin-bottom: 1rem;
  }}
  .progress-bar {{
    height: 100%;
    background: linear-gradient(90deg, #00d4ff, #7c3aed);
    border-radius: 8px;
    width: 0%;
    transition: width 0.3s ease;
  }}
  .status {{
    font-size: 0.75rem;
    color: #8b949e;
    font-family: 'SF Mono', 'Fira Code', monospace;
    min-height: 20px;
  }}
  .success {{
    color: #3fb950;
    font-weight: 600;
  }}
  .error {{
    color: #f85149;
    font-weight: 600;
  }}
  .tag {{
    display: inline-block;
    background: #0d1117;
    border: 1px solid #00d4ff33;
    color: #00d4ff;
    padding: 0.2rem 0.6rem;
    border-radius: 20px;
    font-size: 0.65rem;
    margin-top: 1.5rem;
    font-weight: 600;
    letter-spacing: 0.5px;
  }}
  .bg-grid {{
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    z-index: 0;
  }}
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="card">
  <div class="shield">&#x1F6E1;&#xFE0F;</div>
  <h1>Verifying your browser</h1>
  <p class="sub">AutoShield is checking that your connection is secure.<br>This usually takes 1-3 seconds.</p>
  <div class="progress-wrap"><div class="progress-bar" id="pbar"></div></div>
  <div class="status" id="status">Initializing security check...</div>
  <span class="tag">AUTOSHIELD PROTECTED</span>
</div>
<script>
(function() {{
  const CHALLENGE_ID = "{challenge['challenge_id']}";
  const PREFIX = "{challenge['prefix']}";
  const DIFFICULTY = {challenge['difficulty']};
  const TIMESTAMP = {challenge['timestamp']};
  const SIGNATURE = "{challenge['signature']}";
  const ORIGINAL_URL = "{original_url}";
  const ZERO_PREFIX = "0".repeat(DIFFICULTY);

  const pbar = document.getElementById("pbar");
  const statusEl = document.getElementById("status");

  async function sha256(msg) {{
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  }}

  async function solve() {{
    statusEl.textContent = "Running security verification...";
    pbar.style.width = "20%";

    let nonce = 0;
    const batchSize = 5000;
    const maxAttempts = 10000000;

    while (nonce < maxAttempts) {{
      for (let i = 0; i < batchSize; i++) {{
        const candidate = PREFIX + nonce.toString();
        const hash = await sha256(candidate);
        if (hash.startsWith(ZERO_PREFIX)) {{
          pbar.style.width = "80%";
          statusEl.textContent = "Verification passed. Redirecting...";
          return nonce.toString();
        }}
        nonce++;
      }}
      // Update progress periodically
      const progress = Math.min(70, 20 + (nonce / 500000) * 50);
      pbar.style.width = progress + "%";
      statusEl.textContent = "Verifying... (" + nonce.toLocaleString() + " checks)";
      // Yield to UI thread
      await new Promise(r => setTimeout(r, 0));
    }}
    throw new Error("Challenge too difficult");
  }}

  async function submitSolution(nonce) {{
    const res = await fetch("/challenge/verify", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{
        challenge_id: CHALLENGE_ID,
        prefix: PREFIX,
        nonce: nonce,
        timestamp: TIMESTAMP,
        signature: SIGNATURE,
      }}),
    }});

    if (!res.ok) {{
      const err = await res.json().catch(() => ({{ detail: "Unknown error" }}));
      throw new Error(err.detail || "Verification failed");
    }}

    return res.json();
  }}

  async function run() {{
    try {{
      const nonce = await solve();
      pbar.style.width = "90%";
      statusEl.textContent = "Submitting verification...";

      await submitSolution(nonce);
      pbar.style.width = "100%";
      statusEl.innerHTML = '<span class="success">&#10003; Verified. Redirecting...</span>';

      setTimeout(() => {{
        window.location.href = ORIGINAL_URL || "/";
      }}, 500);
    }} catch (err) {{
      pbar.style.width = "100%";
      statusEl.innerHTML = '<span class="error">Verification failed: ' + err.message + '</span>';
    }}
  }}

  // Start after short delay (feels more natural)
  setTimeout(run, 300);
}})();
</script>
</body>
</html>"""


# ── Stats tracking ───────────────────────────────────────────────────────────

_challenge_stats = {
    "issued": 0,
    "solved": 0,
    "failed": 0,
    "bypassed": 0,  # valid cookie presented
}


def get_challenge_stats() -> dict:
    """Return challenge system statistics."""
    return dict(_challenge_stats)


def record_issued():
    _challenge_stats["issued"] += 1


def record_solved():
    _challenge_stats["solved"] += 1


def record_failed():
    _challenge_stats["failed"] += 1


def record_bypassed():
    _challenge_stats["bypassed"] += 1
