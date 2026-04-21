import streamlit as st

import db as DB
from auth import current_user, require_auth
from ui_shell import inject_shell_styles, render_sidebar, render_top_nav

require_auth()

st.set_page_config(
    page_title="My Websites — AutoShield AI", page_icon="🗂️", layout="wide"
)
inject_shell_styles()
render_sidebar("my_websites")
search = render_top_nav("my_websites")

st.markdown(
    """<div style="margin-bottom:16px">
      <div style="font-size:24px;font-weight:800;color:#E7EEF9;letter-spacing:-.02em">🗂️ My Websites</div>
      <div style="font-size:13px;color:#8B949E;margin-top:4px">Register websites, issue API keys, and manage protected assets</div>
    </div>""",
    unsafe_allow_html=True,
)

if search:
    st.info(f"Search query active: {search}")

DB.init_db()

left, right = st.columns([1, 1.25], gap="medium")

with left:
    st.markdown(
        '<div class="glass"><div style="font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px">🧩 Add Website (Setup)</div>',
        unsafe_allow_html=True,
    )
    with st.form("add_website_form", clear_on_submit=True):
        name = st.text_input("Website Name", placeholder="Acme Production")
        domain = st.text_input("Domain", placeholder="acme.com")
        plan = st.selectbox("Plan", ["free", "pro", "enterprise"], index=0)
        submitted = st.form_submit_button(
            "Add Website", type="primary", use_container_width=True
        )

    if submitted:
        if not name.strip() or not domain.strip():
            st.warning("Website name and domain are required.")
        else:
            try:
                out = DB.create_site(name.strip(), domain.strip().lower(), plan=plan)
                st.success("Website added successfully.")
                st.code(
                    f"site_id: {out['site_id']}\napi_key: {out['api_key']}",
                    language="text",
                )
            except Exception as ex:
                st.error(f"Failed to add website: {ex}")
    st.markdown("</div>", unsafe_allow_html=True)

with right:
    st.markdown(
        '<div class="glass"><div style="font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px">🌐 Registered Websites</div>',
        unsafe_allow_html=True,
    )
    sites = DB.list_sites()
    if not sites:
        st.info("No websites registered yet.")
    else:
        for s in sites:
            cfg = s.get("config") if isinstance(s.get("config"), dict) else {}
            st.markdown(
                f"""<div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:10px;padding:12px 14px;margin-bottom:10px">
                  <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
                    <div style="font-size:13px;font-weight:700;color:#E7EEF9">{s.get("name", "-")}</div>
                    <span style="background:rgba(0,200,255,.12);color:#00C8FF;border:1px solid rgba(0,200,255,.25);padding:2px 8px;border-radius:999px;font-size:9px;font-family:Space Mono,monospace;text-transform:uppercase">{s.get("plan", "free")}</span>
                  </div>
                  <div style="font-size:11px;color:#8B949E;font-family:Space Mono,monospace;margin-top:6px">{s.get("domain", "-")}</div>
                  <div style="font-size:10px;color:#4A6080;font-family:Space Mono,monospace;margin-top:8px">site_id: {s.get("id", "-")}</div>
                  <div style="font-size:10px;color:#4A6080;font-family:Space Mono,monospace;margin-top:3px">api_key: {s.get("api_key", "-")}</div>
                </div>""",
                unsafe_allow_html=True,
            )
    st.markdown("</div>", unsafe_allow_html=True)

u = current_user()
st.caption(f"Signed in as: {u.get('name', 'Unknown')} ({u.get('provider', 'local')})")
