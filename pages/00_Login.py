import streamlit as st

from auth import render_login_page
from ui_shell import inject_shell_styles


st.set_page_config(
    page_title="AutoShield AI — Sign In",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

inject_shell_styles()

st.markdown(
    """
<style>
.stApp {
  background: #0B0F14 !important;
  color: #E7EEF9;
}

.stApp::before {
  content: '';
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse 500px 400px at 30% 20%, rgba(0,200,255,.04), transparent),
    radial-gradient(ellipse 400px 350px at 70% 80%, rgba(106,92,255,.03), transparent);
  pointer-events: none;
  z-index: 0;
}

.block-container {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding-top: 0 !important;
  padding-bottom: 0 !important;
  max-width: 520px !important;
  animation: auth-enter .5s cubic-bezier(.22,1,.36,1);
}

@keyframes auth-enter {
  from { opacity: 0; transform: translateY(16px) scale(.98); }
  to   { opacity: 1; transform: none; }
}

/* Auth card wrapper */
.auth-wrap { max-width: 520px; margin: 0 auto; width: 100%; }

.auth-card {
  background: rgba(17,22,28,.85);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(28,37,53,.8);
  border-radius: 20px;
  padding: 36px 32px 28px;
  box-shadow: 0 24px 64px rgba(0,0,0,.4), 0 0 0 1px rgba(255,255,255,.02) inset;
}

.auth-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 28px;
}

.auth-logo {
  width: 40px; height: 40px; border-radius: 12px;
  background: linear-gradient(135deg, #00C8FF, #6A5CFF);
  display: flex; align-items: center; justify-content: center;
  font-size: 20px; flex-shrink: 0;
}

.auth-brand-text h2 {
  font-size: 22px; font-weight: 800; color: #E7EEF9;
  margin: 0; letter-spacing: -.02em;
}

.auth-brand-text p {
  font-size: 12px; color: #8B949E; margin: 2px 0 0;
}

/* Form styling */
.stButton > button,
.stLinkButton > a {
  border-radius: 12px !important;
  min-height: 46px;
  font-weight: 600 !important;
  border: 1px solid #1C2535 !important;
  transition: all .25s cubic-bezier(.22,1,.36,1) !important;
}

.stButton > button[kind="primary"],
.stForm button {
  background: linear-gradient(135deg, #00C8FF, #6A5CFF) !important;
  color: white !important;
  border: none !important;
  box-shadow: 0 4px 16px rgba(0,200,255,.15) !important;
}

.stButton > button[kind="primary"]:hover,
.stForm button:hover {
  transform: translateY(-1px) !important;
  box-shadow: 0 8px 28px rgba(0,200,255,.25) !important;
}

.stButton > button:hover,
.stLinkButton > a:hover {
  transform: translateY(-1px);
  box-shadow: 0 8px 20px rgba(0,0,0,.28) !important;
}

.stTextInput > div > div > input {
  border-radius: 12px !important;
  background: rgba(8,11,16,.6) !important;
  border: 1px solid rgba(28,37,53,.8) !important;
  color: #E7EEF9 !important;
  padding: 12px 14px !important;
  transition: all .2s ease !important;
}

.stTextInput > div > div > input:focus {
  border-color: #00C8FF !important;
  box-shadow: 0 0 0 1px rgba(0,200,255,.3), 0 0 20px rgba(0,200,255,.08) !important;
}

.stRadio label { font-size: 13px !important; color: #CDD8EB !important; }
.stCaption { color: #8B949E !important; }

.stCheckbox label { color: #8B949E !important; font-size: 12px !important; }

div[data-testid="stForm"] {
  border: none !important;
  padding: 0 !important;
}

/* Divider */
hr { border-color: rgba(28,37,53,.6) !important; margin: 16px 0 !important; }

/* Footer hint */
.auth-footer {
  text-align: center;
  margin-top: 20px;
  font-size: 11px;
  color: #4A6080;
}
.auth-footer code {
  background: rgba(0,200,255,.06) !important;
  border: 1px solid rgba(0,200,255,.15) !important;
  color: #8DD9FF !important;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 10px;
}

/* Hide streamlit elements */
#MainMenu, footer, [data-testid="stDecoration"], [data-testid="stToolbar"] { display: none !important; }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class="auth-wrap">
  <div class="auth-card">
    <div class="auth-brand">
      <div class="auth-logo">🛡️</div>
      <div class="auth-brand-text">
        <h2>Welcome Back</h2>
        <p>Sign in to access your security dashboard</p>
      </div>
    </div>
""",
    unsafe_allow_html=True,
)

render_login_page(preferred_page="dashboard.py")

st.markdown(
    """
    <div class="auth-footer">
      Demo credentials: <code>admin / admin123</code> or <code>analyst / analyst123</code>
    </div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)
