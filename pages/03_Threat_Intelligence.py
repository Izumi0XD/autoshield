import streamlit as st

from auth import current_user, logout, require_auth
from ui_shell import inject_shell_styles, render_sidebar, render_top_nav

require_auth()

st.set_page_config(page_title="Threat Intelligence — AutoShield AI", page_icon="🧠", layout="wide")
inject_shell_styles()
render_sidebar("threat_intel")
search = render_top_nav("threat_intel")

st.markdown(
    """<div style="margin-bottom:16px">
      <div style="font-size:24px;font-weight:800;color:#E7EEF9;letter-spacing:-.02em">🧠 Threat Intelligence</div>
      <div style="font-size:13px;color:#8B949E;margin-top:4px">CVE lookups, CERT-In advisories, and threat context enrichment</div>
    </div>""",
    unsafe_allow_html=True,
)

if search:
    st.info(f"Search query active: {search}")

# ─── CVE Lookup ────────────────────────────────────────────────────────────────
ti1, ti2 = st.columns([1.6, 1], gap="medium")

with ti1:
    st.markdown(
        '<div class="glass"><div style="font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px">CVE Intelligence</div>',
        unsafe_allow_html=True,
    )
    cve_type = st.radio("Attack type", ["SQLi", "XSS", "LFI", "CMDi"], horizontal=True, label_visibility="collapsed")

    try:
        from cve_lookup import get_cve_card
        cve_d = get_cve_card(cve_type)
        score = cve_d.get("cvss_score", "N/A")
        sc_c = "#FF4D4D" if isinstance(score, (int, float)) and score >= 9 else "#FF8B5B" if isinstance(score, (int, float)) and score >= 7 else "#00C8FF"

        st.markdown(
            f"""<div style="background:rgba(8,11,16,.5);border:1px solid {sc_c}33;border-left:3px solid {sc_c};
                        border-radius:10px;padding:16px 18px;margin-top:12px">
              <div style="font-size:15px;font-weight:700;color:{sc_c};font-family:Space Mono,monospace">{cve_d.get("cve_id", "N/A")}</div>
              <div style="display:flex;align-items:center;gap:16px;margin-top:12px">
                <div>
                  <div style="font-size:32px;font-weight:700;color:{sc_c};font-family:Space Mono,monospace;line-height:1">{score}</div>
                  <div style="font-size:9px;color:#4A6080;font-family:Space Mono,monospace">CVSS</div>
                </div>
                <div>
                  <div style="background:{sc_c}18;color:{sc_c};border:1px solid {sc_c}44;padding:3px 10px;border-radius:6px;
                              font-size:10px;font-weight:600;font-family:Space Mono,monospace">{cve_d.get("severity", "?")}</div>
                  <div style="font-size:10px;color:#4A6080;font-family:Space Mono,monospace;margin-top:5px">Published: {cve_d.get("published", "N/A")}</div>
                </div>
              </div>
              <div style="font-size:12px;color:#8B949E;margin-top:12px;line-height:1.6">{cve_d.get("description", "")[:280]}...</div>
              {"<a href='" + cve_d.get("reference", "") + "' target='_blank' style='font-size:10px;color:#00C8FF;font-family:Space Mono,monospace;margin-top:8px;display:inline-block'>🔗 NVD Reference ↗</a>" if cve_d.get("reference") else ""}
            </div>""",
            unsafe_allow_html=True,
        )

        all_cves = cve_d.get("all_cves", [cve_d])
        if len(all_cves) > 1:
            with st.expander(f"All {len(all_cves)} CVEs for {cve_type}"):
                for cv in all_cves[1:]:
                    s2 = cv.get("cvss_score", "N/A")
                    sc3 = "#FF4D4D" if isinstance(s2, (int, float)) and s2 >= 9 else "#FF8B5B" if isinstance(s2, (int, float)) and s2 >= 7 else "#00C8FF"
                    st.markdown(
                        f"""<div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:8px;padding:10px 12px;margin-bottom:6px">
                          <span style="color:{sc3};font-weight:700;font-family:Space Mono,monospace;font-size:11px">{cv.get("cve_id")}</span>
                          <span style="color:#FFC857;font-size:10px;margin-left:8px;font-family:Space Mono,monospace">CVSS {s2}</span>
                          <div style="color:#8B949E;font-size:10px;margin-top:4px">{cv.get("description", "")[:120]}...</div>
                        </div>""",
                        unsafe_allow_html=True,
                    )
    except Exception as ex:
        st.error(f"CVE lookup error: {ex}")
    st.markdown("</div>", unsafe_allow_html=True)

with ti2:
    # CERT-In Feed
    st.markdown(
        '<div class="glass"><div style="font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px">🇮🇳 CERT-In Advisories</div>',
        unsafe_allow_html=True,
    )
    try:
        from certin_feed import fetch_certin_advisories, get_certin_summary
        with st.spinner("Loading advisories..."):
            advisories = fetch_certin_advisories(max_items=6)
            cs = get_certin_summary()

        st.markdown(
            f"""<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px">
              <div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:8px;padding:10px;text-align:center">
                <div style="font-size:18px;font-weight:700;color:#00C8FF;font-family:Space Mono,monospace">{cs["total"]}</div>
                <div style="font-size:9px;color:#4A6080;font-family:Space Mono,monospace">TOTAL</div>
              </div>
              <div style="background:rgba(8,11,16,.5);border:1px solid #FF4D4D33;border-radius:8px;padding:10px;text-align:center">
                <div style="font-size:18px;font-weight:700;color:#FF4D4D;font-family:Space Mono,monospace">{cs["critical"]}</div>
                <div style="font-size:9px;color:#4A6080;font-family:Space Mono,monospace">CRITICAL</div>
              </div>
              <div style="background:rgba(8,11,16,.5);border:1px solid #FF8B5B33;border-radius:8px;padding:10px;text-align:center">
                <div style="font-size:18px;font-weight:700;color:#FF8B5B;font-family:Space Mono,monospace">{cs["high"]}</div>
                <div style="font-size:9px;color:#4A6080;font-family:Space Mono,monospace">HIGH</div>
              </div>
            </div>""",
            unsafe_allow_html=True,
        )

        for adv in advisories:
            sev = adv.get("severity", "HIGH")
            sc = {"CRITICAL": "#FF4D4D", "HIGH": "#FF8B5B", "MEDIUM": "#FFC857", "LOW": "#00FF9C"}.get(sev, "#4A6080")
            st.markdown(
                f"""<div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-left:3px solid {sc};
                            border-radius:8px;padding:10px 14px;margin-bottom:8px">
                  <div style="display:flex;justify-content:space-between;align-items:center">
                    <div style="font-size:10px;font-weight:700;color:{sc};font-family:Space Mono,monospace">{adv.get("advisory_id", "")}</div>
                    <span style="background:{sc}18;color:{sc};border:1px solid {sc}44;padding:2px 8px;border-radius:4px;
                                 font-size:9px;font-family:Space Mono,monospace">{sev}</span>
                  </div>
                  <div style="font-size:11px;color:#CDD8EB;margin-top:5px">{adv.get("title", "")[:60]}</div>
                  <div style="font-size:10px;color:#8B949E;margin-top:4px;line-height:1.4">{adv.get("description", "")[:100]}...</div>
                </div>""",
                unsafe_allow_html=True,
            )
    except Exception as ex:
        st.error(f"CERT-In feed error: {ex}")
    st.markdown("</div>", unsafe_allow_html=True)

# ─── Footer ────────────────────────────────────────────────────────────────────
u = current_user()
st.caption(f"Signed in as: {u.get('name', 'Unknown')} ({u.get('provider', 'local')})")
c1, c2 = st.columns(2)
with c1:
    if st.button("Logout", use_container_width=True, key="ti_logout"):
        logout()
        st.switch_page("pages/00_Login.py")
with c2:
    if st.button("Open Fusion Dashboard", use_container_width=True, key="ti_dash"):
        st.switch_page("dashboard.py")
