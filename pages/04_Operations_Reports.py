import streamlit as st
import base64

from auth import current_user, logout, require_auth
from ui_shell import inject_shell_styles, render_sidebar, render_top_nav

require_auth()

st.set_page_config(page_title="Operations & Reports — AutoShield AI", page_icon="📦", layout="wide")
inject_shell_styles()
render_sidebar("ops_reports")
search = render_top_nav("ops_reports")

st.markdown(
    """<div style="margin-bottom:16px">
      <div style="font-size:24px;font-weight:800;color:#E7EEF9;letter-spacing:-.02em">📦 Operations & Reports</div>
      <div style="font-size:13px;color:#8B949E;margin-top:4px">Incident reporting, alert configuration, and compliance workflows</div>
    </div>""",
    unsafe_allow_html=True,
)

if search:
    st.info(f"Search query active: {search}")

log = st.session_state.get("log", [])

r1, r2 = st.columns([1.2, 1], gap="medium")

with r1:
    st.markdown(
        '<div class="glass"><div style="font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:14px">📄 Incident Report Generator</div>',
        unsafe_allow_html=True,
    )
    org = st.text_input("Organization Name", value="Target Organization", key="ops_org")

    try:
        from report_generator import generate_report, REPORTLAB_OK
        if REPORTLAB_OK:
            if st.button("🖨 Generate PDF Report", type="primary", use_container_width=True, key="ops_gen"):
                if not log:
                    st.warning("No attack data. Simulate attacks from the Fusion Dashboard first.")
                else:
                    blocker = st.session_state.get("blocker", None)
                    bips = blocker.get_blocked_list() if blocker and hasattr(blocker, "get_blocked_list") else []
                    with st.spinner("Generating report..."):
                        try:
                            rpath = generate_report(log, bips, "/tmp/ops_report.pdf", org)
                            with open(rpath, "rb") as f:
                                b64r = base64.b64encode(f.read()).decode()
                            st.markdown(
                                f"""<div style="background:rgba(0,42,20,.8);border:1px solid rgba(0,255,156,.3);
                                            border-radius:10px;padding:16px 18px;margin-top:12px">
                                  <div style="font-size:13px;font-weight:600;color:#00FF9C;margin-bottom:10px">✅ Report Generated Successfully</div>
                                  <a href="data:application/pdf;base64,{b64r}" download="autoshield_report.pdf"
                                     style="background:rgba(0,255,156,.08);color:#00FF9C;border:1px solid rgba(0,255,156,.3);
                                            padding:10px 20px;border-radius:8px;text-decoration:none;font-size:12px;
                                            font-family:Space Mono,monospace;display:inline-block;
                                            transition:all .2s ease">⬇ Download Report PDF</a>
                                </div>""",
                                unsafe_allow_html=True,
                            )
                        except Exception as ex:
                            st.error(f"Report generation failed: {ex}")
        else:
            st.markdown(
                """<div style="background:rgba(26,13,0,.8);border:1px solid rgba(255,139,91,.3);
                            border-radius:10px;padding:14px 16px">
                  <div style="font-size:12px;color:#FF8B5B">pip install reportlab</div>
                  <div style="font-size:10px;color:#4A6080;margin-top:4px">ReportLab is required for PDF generation</div>
                </div>""",
                unsafe_allow_html=True,
            )
    except Exception as ex:
        st.error(f"Report module error: {ex}")

    st.markdown(
        """<div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:10px;
                    padding:14px 16px;margin-top:14px">
          <div style="font-size:12px;font-weight:600;color:#E7EEF9;margin-bottom:8px">Report Includes</div>
          <div style="font-size:11px;color:#8B949E;font-family:Space Mono,monospace;line-height:2">
            ✓ Executive summary + statistics<br/>
            ✓ Full attack log (last 50 events)<br/>
            ✓ Blocked IP table with reasons<br/>
            ✓ SQLi/XSS/LFI/CMDi recommendations<br/>
            ✓ CONFIDENTIAL classification
          </div>
        </div>""",
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

with r2:
    # Alert configuration
    st.markdown(
        '<div class="glass"><div style="font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:14px">🚨 Alert Configuration</div>',
        unsafe_allow_html=True,
    )
    try:
        from alert_system import alert_config_status, fire_alert
        acfg = alert_config_status()
        for channel, icon, cname in [
            ("whatsapp", "📱", "WhatsApp / Twilio"),
            ("email", "📧", "Email / SMTP"),
        ]:
            cfg = acfg[channel]
            ok = cfg["configured"]
            sc = "#00FF9C" if ok else "#4A6080"
            st.markdown(
                f"""<div style="background:rgba(8,11,16,.5);border:1px solid {'rgba(0,255,156,.2)' if ok else '#1C2535'};
                            border-radius:10px;padding:14px 16px;margin-bottom:10px">
                  <div style="display:flex;justify-content:space-between;align-items:center">
                    <div style="font-size:13px;font-weight:600;color:#E7EEF9">{icon} {cname}</div>
                    <span style="background:{'rgba(0,42,20,.8)' if ok else 'rgba(8,11,16,.5)'};color:{sc};
                                 border:1px solid {sc}44;padding:3px 10px;border-radius:6px;
                                 font-size:9px;font-family:Space Mono,monospace">{'ACTIVE' if ok else 'NOT SET'}</span>
                  </div>
                  <div style="font-size:10px;color:#4A6080;font-family:Space Mono,monospace;margin-top:8px">
                    {'To: ' + cfg['to'][:40] if ok else 'Set env: ' + ('TWILIO_SID + ALERT_WA_TO' if channel == 'whatsapp' else 'SMTP_USER + ALERT_EMAIL_TO')}
                  </div>
                </div>""",
                unsafe_allow_html=True,
            )

        st.markdown(
            """<div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:10px;
                        padding:12px 14px;margin-bottom:12px">
              <div style="font-size:10px;color:#8B949E;font-family:Space Mono,monospace;line-height:2">
                🔴 CRITICAL → immediate alert<br/>
                🟡 HIGH → alert after 5 events/min<br/>
                ⏱ Cooldown: 120s per IP<br/>
                📤 WhatsApp + Email (parallel)
              </div>
            </div>""",
            unsafe_allow_html=True,
        )

        if st.button("📨 Send Test Alert", use_container_width=True, key="ops_test_alert"):
            from datetime import datetime
            ev_t = st.session_state.get("last") or {
                "src_ip": "0.0.0.0", "attack_type": "SQLi", "severity": "CRITICAL",
                "action": "BLOCKED", "confidence": 75, "cve_hints": ["CVE-2023-23752"],
                "payload_snip": "test", "timestamp": datetime.now().isoformat(),
            }
            res = fire_alert(ev_t, force=True)
            wa_r = res.get("channels", {}).get("whatsapp", {}).get("status", "SKIPPED")
            em_r = res.get("channels", {}).get("email", {}).get("status", "SKIPPED")
            st.markdown(
                f"""<div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:10px;
                            padding:12px 14px;margin-top:8px">
                  <div style="font-size:10px;font-family:Space Mono,monospace;color:#4A6080">
                    WhatsApp: <span style="color:{'#00FF9C' if wa_r == 'SENT' else '#FFC857'}">{wa_r}</span><br/>
                    Email: <span style="color:{'#00FF9C' if em_r == 'SENT' else '#FFC857'}">{em_r}</span>
                  </div>
                </div>""",
                unsafe_allow_html=True,
            )
    except Exception as ex:
        st.error(f"Alert system error: {ex}")
    st.markdown("</div>", unsafe_allow_html=True)

    # Quick stats
    if log:
        total = len(log)
        blocked = len([e for e in log if e.get("action") == "BLOCKED"])
        st.markdown(
            f"""<div class='glass' style='margin-top:12px'>
              <div style='font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:10px'>Session Summary</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
                <div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:8px;padding:12px;text-align:center">
                  <div style="font-size:20px;font-weight:700;color:#00C8FF;font-family:Space Mono,monospace">{total}</div>
                  <div style="font-size:9px;color:#4A6080;font-family:Space Mono,monospace;text-transform:uppercase">Total Events</div>
                </div>
                <div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:8px;padding:12px;text-align:center">
                  <div style="font-size:20px;font-weight:700;color:#00FF9C;font-family:Space Mono,monospace">{int(blocked/total*100) if total else 0}%</div>
                  <div style="font-size:9px;color:#4A6080;font-family:Space Mono,monospace;text-transform:uppercase">Block Rate</div>
                </div>
              </div>
            </div>""",
            unsafe_allow_html=True,
        )

# ─── Footer ────────────────────────────────────────────────────────────────────
u = current_user()
st.caption(f"Signed in as: {u.get('name', 'Unknown')} ({u.get('provider', 'local')})")
c1, c2 = st.columns(2)
with c1:
    if st.button("Logout", use_container_width=True, key="ops_logout"):
        logout()
        st.switch_page("pages/00_Login.py")
with c2:
    if st.button("Open Fusion Dashboard", use_container_width=True, key="ops_dash"):
        st.switch_page("dashboard.py")
