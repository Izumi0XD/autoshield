import streamlit as st

from auth import current_user, logout


DESIGN_SYSTEM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700;800&family=Space+Mono:wght@400;700&display=swap');

/* ═══════════════════ GLOBAL DESIGN TOKENS ═══════════════════ */
:root {
  --bg:       #0B0F14;
  --bg-deep:  #080B10;
  --bg-soft:  #0A0E13;
  --surface:  #11161C;
  --surface2: #151C25;
  --line:     #1C2535;
  --line2:    #24344B;
  --text:     #E7EEF9;
  --text2:    #CDD8EB;
  --muted:    #8B949E;
  --muted2:   #4A6080;
  --cyan:     #00C8FF;
  --purple:   #6A5CFF;
  --red:      #FF4D4D;
  --green:    #00FF9C;
  --yellow:   #FFC857;
  --orange:   #FF8B5B;
  --font:     'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
  --mono:     'Space Mono', 'SF Mono', Consolas, monospace;
  --radius:   12px;
  --radius-sm: 8px;
  --radius-lg: 16px;
}

/* ═══════════════════ APP SHELL ═══════════════════ */
.stApp {
  background: var(--bg) !important;
  color: var(--text) !important;
  font-family: var(--font) !important;
}

.stApp::before {
  content: '';
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse 600px 400px at 8% 6%, rgba(0,200,255,.03), transparent),
    radial-gradient(ellipse 500px 350px at 85% 8%, rgba(106,92,255,.025), transparent);
  pointer-events: none;
  z-index: 0;
}

.stApp > header { display: none !important; }

.block-container {
  max-width: 1300px !important;
  margin: 0 auto !important;
  padding: 0.5rem 1.1rem 1.8rem !important;
  animation: shell-enter .35s cubic-bezier(.22,1,.36,1);
}

/* ═══════════════════ SIDEBAR ═══════════════════ */
[data-testid="stSidebar"] {
  background: var(--bg-soft) !important;
  border-right: 1px solid var(--line) !important;
}

[data-testid="stSidebar"] * {
  color: var(--text) !important;
}

section[data-testid="stSidebarContent"] {
  padding: 0 !important;
}

[data-testid="stSidebarNav"] a {
  border-left: 2px solid transparent;
  border-radius: var(--radius-sm);
  padding: 9px 12px !important;
  margin: 2px 8px;
  transition: all .2s cubic-bezier(.22,1,.36,1);
  font-size: 13px !important;
}

[data-testid="stSidebarNav"] a:hover {
  background: rgba(0,200,255,.04) !important;
  border-left-color: rgba(0,200,255,.3);
}

[data-testid="stSidebarNav"] a[aria-current="page"] {
  background: rgba(0,200,255,.08) !important;
  border-left-color: var(--cyan) !important;
}

/* ═══════════════════ BUTTONS ═══════════════════ */
div[data-testid="stButton"] > button,
.stLinkButton > a {
  border-radius: var(--radius) !important;
  font-family: var(--font) !important;
  font-weight: 500 !important;
  font-size: 13px !important;
  transition: all .2s cubic-bezier(.22,1,.36,1) !important;
  border: 1px solid var(--line2) !important;
  background: var(--surface) !important;
  color: var(--text) !important;
}

div[data-testid="stButton"] > button:hover,
.stLinkButton > a:hover {
  transform: translateY(-1px);
  border-color: rgba(0,200,255,.4) !important;
  box-shadow: 0 8px 24px rgba(0,0,0,.3), 0 0 0 1px rgba(0,200,255,.1) !important;
  background: var(--surface2) !important;
}

div[data-testid="stButton"] > button:active {
  transform: scale(.98) translateY(0);
}

div[data-testid="stButton"] > button[kind="primary"] {
  background: linear-gradient(135deg, var(--cyan), var(--purple)) !important;
  border: none !important;
  color: #fff !important;
  font-weight: 600 !important;
}

div[data-testid="stButton"] > button[kind="primary"]:hover {
  box-shadow: 0 8px 32px rgba(0,200,255,.25), 0 0 0 1px rgba(0,200,255,.2) !important;
}

/* ═══════════════════ INPUTS ═══════════════════ */
div[data-testid="stTextInput"] input,
div[data-testid="stTextArea"] textarea,
div[data-testid="stNumberInput"] input {
  background: var(--bg-deep) !important;
  border: 1px solid var(--line) !important;
  border-radius: var(--radius) !important;
  color: var(--text) !important;
  font-family: var(--font) !important;
  font-size: 13px !important;
  transition: all .2s ease !important;
}

div[data-testid="stTextInput"] input:focus,
div[data-testid="stTextArea"] textarea:focus,
div[data-testid="stNumberInput"] input:focus {
  border-color: var(--cyan) !important;
  box-shadow: 0 0 0 1px rgba(0,200,255,.3), 0 0 20px rgba(0,200,255,.08) !important;
  outline: none !important;
}

/* ═══════════════════ METRICS ═══════════════════ */
div[data-testid="stMetric"] {
  background: var(--surface) !important;
  border: 1px solid var(--line) !important;
  border-radius: var(--radius) !important;
  padding: 14px 16px !important;
  box-shadow: 0 4px 16px rgba(0,0,0,.2);
  transition: all .25s cubic-bezier(.22,1,.36,1);
}

div[data-testid="stMetric"]:hover {
  border-color: var(--line2) !important;
  transform: translateY(-2px);
  box-shadow: 0 8px 28px rgba(0,0,0,.3);
}

div[data-testid="stMetric"] label {
  color: var(--muted) !important;
  font-size: 11px !important;
  font-family: var(--mono) !important;
  letter-spacing: .06em !important;
  text-transform: uppercase !important;
}

div[data-testid="stMetric"] [data-testid="stMetricValue"] {
  color: var(--text) !important;
  font-family: var(--mono) !important;
  font-weight: 700 !important;
}

/* ═══════════════════ TABS ═══════════════════ */
[data-testid="stTabs"] button {
  background: transparent !important;
  color: var(--muted) !important;
  font-family: var(--font) !important;
  font-size: 12px !important;
  font-weight: 500 !important;
  border-bottom: 2px solid transparent !important;
  border-radius: 0 !important;
  padding: 10px 18px !important;
  letter-spacing: .03em;
  transition: all .2s ease !important;
}

[data-testid="stTabs"] button:hover {
  color: var(--text2) !important;
}

[data-testid="stTabs"] button[aria-selected="true"] {
  color: var(--cyan) !important;
  border-bottom-color: var(--cyan) !important;
}

[data-testid="stTabs"] {
  border-bottom: 1px solid var(--line) !important;
}

/* ═══════════════════ CODE & EXPANDERS ═══════════════════ */
.stCode, code {
  background: var(--bg-deep) !important;
  color: var(--green) !important;
  font-family: var(--mono) !important;
  font-size: 11px !important;
  border: 1px solid var(--line) !important;
  border-radius: var(--radius-sm) !important;
}

[data-testid="stExpander"] {
  background: var(--surface) !important;
  border: 1px solid var(--line) !important;
  border-radius: var(--radius-sm) !important;
}

[data-testid="stExpander"] summary {
  color: var(--text2) !important;
  font-size: 12px !important;
}

/* ═══════════════════ SELECTBOX / RADIO ═══════════════════ */
div[data-testid="stSelectbox"] > div > div {
  background: var(--surface) !important;
  border: 1px solid var(--line) !important;
  border-radius: var(--radius) !important;
  color: var(--text) !important;
}

div[data-testid="stRadio"] label {
  font-size: 12px !important;
  color: var(--text) !important;
}

/* ═══════════════════ DIVIDERS ═══════════════════ */
hr {
  border-color: var(--line) !important;
  margin: 12px 0 !important;
}

div[data-testid="stHorizontalBlock"] {
  gap: 12px !important;
}

.element-container { margin: 0 !important; }

/* ═══════════════════ SCROLLBARS ═══════════════════ */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--bg-soft); }
::-webkit-scrollbar-thumb { background: var(--line2); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: var(--muted2); }

/* ═══════════════════ COMPONENT CLASSES ═══════════════════ */
.shell-top {
  position: sticky;
  top: 0;
  z-index: 40;
  background: rgba(11,15,20,.92);
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  padding: 10px 16px;
  margin-bottom: 16px;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}

.glass {
  background: rgba(17,22,28,.92);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 16px;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  box-shadow: 0 8px 24px rgba(0,0,0,.2);
}

.glass-card {
  background: rgba(17,22,28,.92);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 14px;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  box-shadow: 0 8px 24px rgba(2,8,20,.28);
  animation: shell-enter .3s cubic-bezier(.22,1,.36,1);
}

.sb-sec {
  padding: 14px 14px 6px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .12em;
  color: var(--muted2);
  text-transform: uppercase;
  font-family: var(--mono);
}

.neon-pill {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  border: 1px solid rgba(0,200,255,.3);
  background: rgba(0,200,255,.08);
  color: #8DD9FF;
  font-size: 10px;
  font-family: var(--mono);
}

.table-card {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 14px 16px;
}

.log-row {
  display: grid;
  grid-template-columns: 80px 140px 95px 95px 120px 1fr;
  gap: 10px;
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  transition: all .18s ease;
}

.log-row:hover {
  background: rgba(0,200,255,.03);
  border-color: var(--line);
}

.skeleton {
  position: relative;
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  height: 16px;
  margin: 8px 0;
}

.skeleton::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,.04), transparent);
  transform: translateX(-100%);
  animation: shimmer 1.8s ease infinite;
}

.muted { color: var(--muted); font-size: 12px; }

.sk {
  position: relative;
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  height: 14px;
  margin: 7px 0;
}

.sk::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,.04), transparent);
  transform: translateX(-100%);
  animation: shimmer 1.8s ease infinite;
}

/* ═══════════════════ ANIMATIONS ═══════════════════ */
@keyframes shell-enter {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: none; }
}

@keyframes shimmer {
  100% { transform: translateX(100%); }
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; }
  50%      { opacity: .3; }
}

@keyframes pulse-glow {
  0%, 100% { box-shadow: 0 0 0 0 rgba(0,200,255,.15); }
  50%      { box-shadow: 0 0 12px 4px rgba(0,200,255,.08); }
}

@keyframes pulse-r { 0%,100%{opacity:1} 50%{opacity:.3} }
@keyframes pulse-g { 0%,100%{opacity:1} 50%{opacity:.5} }
@keyframes fadein  { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:none} }
@keyframes sh      { 100%{transform:translateX(100%)} }
</style>
"""


def inject_shell_styles() -> None:
    st.markdown(DESIGN_SYSTEM_CSS, unsafe_allow_html=True)


def render_sidebar(active_page: str) -> None:
    with st.sidebar:
        st.markdown(
            """<div style="padding:18px 16px 14px;border-bottom:1px solid #1C2535">
          <div style="display:flex;align-items:center;gap:10px">
            <div style="width:32px;height:32px;border-radius:10px;background:linear-gradient(135deg,#00C8FF,#6A5CFF);
                        display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0">🛡️</div>
            <div>
              <div style="font-size:15px;font-weight:700;color:#E7EEF9;letter-spacing:-.02em">AutoShield AI</div>
              <div style="font-size:10px;color:#4A6080;letter-spacing:.08em;font-family:'Space Mono',monospace;margin-top:1px">CONTROL PANEL</div>
            </div>
          </div>
        </div>""",
            unsafe_allow_html=True,
        )

        st.markdown('<div class="sb-sec">Navigation</div>', unsafe_allow_html=True)
        st.page_link("dashboard.py", label="Fusion Dashboard", icon="🛡️")
        st.page_link("pages/01_Live_SOC.py", label="Live SOC", icon="⚡")
        st.page_link(
            "pages/02_Attack_Geography.py", label="Attack Geography", icon="🌐"
        )
        st.page_link(
            "pages/03_Threat_Intelligence.py", label="Threat Intelligence", icon="🧠"
        )
        st.page_link(
            "pages/04_Operations_Reports.py", label="Operations & Reports", icon="📦"
        )
        st.page_link("pages/05_My_Websites.py", label="My Websites", icon="🗂️")
        st.markdown('<div class="sb-sec">Website Setup</div>', unsafe_allow_html=True)
        st.page_link("pages/05_My_Websites.py", label="Add Website (Setup)", icon="🧩")
        st.markdown("---")
        if st.button("Logout", use_container_width=True, key=f"logout_{active_page}"):
            logout()
            st.switch_page("pages/00_Login.py")


def render_top_nav(key_suffix: str = "") -> str:
    user = current_user()
    notifs = st.session_state.get("notifications", [])
    st.markdown('<div class="shell-top">', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([2.6, 1, 1], gap="small")
    with c1:
        query = st.text_input(
            "Search",
            placeholder="Search IP / domain / CVE",
            key=f"shell_search_{key_suffix}",
            label_visibility="collapsed",
        )
    with c2:
        with st.popover(f"🔔 Alerts ({len(notifs)})", use_container_width=True):
            if notifs:
                for n in reversed(notifs[-6:]):
                    lvl = n.get("level", "INFO")
                    col = {
                        "CRITICAL": "#FF4D4D",
                        "WARNING": "#FFC857",
                        "INFO": "#00C8FF",
                    }.get(lvl, "#8B949E")
                    st.markdown(
                        f"<div style='font-size:12px;padding:5px 0;border-bottom:1px solid #1C2535'>"
                        f"<span style='color:{col};font-weight:600'>[{lvl}]</span> "
                        f"<span style='color:#CDD8EB'>{n.get('message', '-')}</span></div>",
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    "<div style='color:#4A6080;font-size:12px;padding:8px 0'>No alerts yet</div>",
                    unsafe_allow_html=True,
                )
    with c3:
        with st.popover("👤 Profile", use_container_width=True):
            st.markdown(
                f"<div style='padding:4px 0'>"
                f"<div style='font-size:14px;font-weight:600;color:#E7EEF9'>{user.get('name', 'Unknown')}</div>"
                f"<div style='font-size:11px;color:#8B949E;margin-top:2px'>{user.get('email', '')}</div>"
                f"<div style='font-size:10px;color:#4A6080;margin-top:4px;font-family:Space Mono,monospace'>"
                f"Provider: {user.get('provider', 'local').upper()}</div></div>",
                unsafe_allow_html=True,
            )
    st.markdown("</div>", unsafe_allow_html=True)
    return query
