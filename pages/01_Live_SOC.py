import streamlit as st

from auth import current_user, logout, require_auth
from ui_shell import inject_shell_styles, render_sidebar, render_top_nav

require_auth()

st.set_page_config(page_title="Live SOC — AutoShield AI", page_icon="⚡", layout="wide")

inject_shell_styles()
render_sidebar("live_soc")
search = render_top_nav("live_soc")

# ─── Page header ───────────────────────────────────────────────────────────────
st.markdown(
    """<div style="margin-bottom:16px">
      <div style="font-size:24px;font-weight:800;color:#E7EEF9;letter-spacing:-.02em">⚡ Live SOC</div>
      <div style="font-size:13px;color:#8B949E;margin-top:4px">Real-time security operations center — monitor threats as they happen</div>
    </div>""",
    unsafe_allow_html=True,
)

if search:
    st.info(f"Search query active: {search}")

# ─── Metrics ───────────────────────────────────────────────────────────────────
log = st.session_state.get("log", [])
bips_count = len(st.session_state.get("blocker", type("", (), {"get_blocked_list": lambda s: []})()).get_blocked_list()) if hasattr(st.session_state.get("blocker", None), "get_blocked_list") else 0
total = len(log)
blocked = len([e for e in log if e.get("action") == "BLOCKED"])
active_threats = len([e for e in log[-60:] if e.get("status") != "MITIGATED"]) if log else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Active Threats", str(active_threats), delta=f"+{min(active_threats, 3)}" if active_threats else "0")
c2.metric("Events Processed", str(total), delta=f"{len(log[-20:]) if log else 0} recent")
c3.metric("Blocked", str(blocked), delta=f"{int(blocked/total*100) if total else 0}% rate")
c4.metric("System Health", "Stable" if active_threats < 5 else "Elevated", "nominal" if active_threats < 5 else "attention")

# ─── Live Attack Feed ──────────────────────────────────────────────────────────
st.markdown(
    """<div class="glass" style="margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div style="font-size:12px;font-weight:700;color:#E7EEF9">Live Activity Feed</div>
        <div style="display:flex;align-items:center;gap:6px">
          <span style="width:6px;height:6px;border-radius:50%;background:#00FF9C;animation:pulse-dot 1.5s ease infinite"></span>
          <span style="font-size:10px;color:#8B949E;font-family:Space Mono,monospace">STREAMING</span>
        </div>
      </div>""",
    unsafe_allow_html=True,
)

if log:
    for ev in reversed(log[-12:]):
        sev = ev.get("severity", "LOW")
        sev_color = {"CRITICAL": "#FF4D4D", "HIGH": "#FFC857", "MEDIUM": "#00C8FF", "LOW": "#00FF9C"}.get(sev, "#8B949E")
        at_color = {"SQLi": "#FF4D4D", "XSS": "#FFC857", "LFI": "#6A5CFF", "CMDi": "#FF8B5B"}.get(ev.get("attack_type", ""), "#8B949E")
        act = ev.get("action", "PENDING")
        act_color = "#00FF9C" if act == "BLOCKED" else "#FFC857" if act == "RATE_MONITORED" else "#4A6080"
        st.markdown(
            f"<div style='font-family:Space Mono,monospace;font-size:11px;padding:7px 0;border-bottom:1px solid rgba(28,37,53,.5);display:flex;align-items:center;gap:12px'>"
            f"<span style='color:#4A6080;min-width:44px'>{ev.get('timestamp', '')[-8:-3]}</span>"
            f"<span style='color:{sev_color};font-weight:600;min-width:70px'>[{sev}]</span>"
            f"<span style='color:{at_color};min-width:40px'>{ev.get('attack_type', '?')}</span>"
            f"<span style='color:#CDD8EB'>from</span>"
            f"<span style='color:#E7EEF9;font-weight:600'>{ev.get('src_ip', '?')}</span>"
            f"<span style='color:#4A6080'>→</span>"
            f"<span style='color:{act_color}'>{act}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
else:
    st.markdown(
        """<div style="text-align:center;padding:32px;color:#4A6080;font-family:Space Mono,monospace;font-size:12px">
          🟢 NO ACTIVE THREATS — System monitoring. Use the Fusion Dashboard sidebar to simulate attacks.
        </div>""",
        unsafe_allow_html=True,
    )

st.markdown("</div>", unsafe_allow_html=True)

# ─── Recent stats ──────────────────────────────────────────────────────────────
if log:
    from collections import Counter
    type_counts = Counter(e.get("attack_type", "?") for e in log)
    st.markdown(
        '<div class="glass" style="margin-top:12px"><div style="font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px">Attack Type Distribution</div>',
        unsafe_allow_html=True,
    )
    type_colors = {"SQLi": "#FF4D4D", "XSS": "#FFC857", "LFI": "#6A5CFF", "CMDi": "#FF8B5B"}
    for at, cnt in type_counts.most_common(4):
        pct = int(cnt / max(total, 1) * 100)
        col = type_colors.get(at, "#8B949E")
        st.markdown(
            f"""<div style="margin-bottom:10px">
              <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                <span style="font-size:12px;font-weight:600;color:{col}">{at}</span>
                <span style="font-size:11px;color:#CDD8EB;font-family:Space Mono,monospace">{cnt} ({pct}%)</span>
              </div>
              <div style="background:#0B0F14;border-radius:3px;height:6px;overflow:hidden">
                <div style="background:{col};height:100%;width:{pct}%;border-radius:3px;transition:width .5s"></div>
              </div>
            </div>""",
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

# ─── Footer ────────────────────────────────────────────────────────────────────
u = current_user()
st.markdown(
    f"<div style='margin-top:16px;padding:12px 0;border-top:1px solid #1C2535;font-size:11px;color:#4A6080;font-family:Space Mono,monospace'>"
    f"Signed in as: {u.get('name', 'Unknown')} ({u.get('provider', 'local')}) &nbsp;·&nbsp; "
    f"<a href='#' style='color:#00C8FF;text-decoration:none'>Open Fusion Dashboard →</a></div>",
    unsafe_allow_html=True,
)

col_l, col_r = st.columns(2)
with col_l:
    if st.button("Logout", use_container_width=True, key="soc_logout"):
        logout()
        st.switch_page("pages/00_Login.py")
with col_r:
    if st.button("Open Fusion Dashboard", use_container_width=True, key="soc_dash"):
        st.switch_page("dashboard.py")
