import streamlit as st

st.set_page_config(page_title="AutoShield AI — Autonomous Cyber Defense", page_icon="🛡️", layout="wide")

# ═══════════════════ LANDING PAGE CSS ═══════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700;800;900&family=Space+Mono:wght@400;700&display=swap');

:root {
  --bg:#0B0F14;--surface:#11161C;--line:#1C2535;--text:#E7EEF9;--muted:#8B949E;
  --cyan:#00C8FF;--purple:#6A5CFF;--red:#FF4D4D;--green:#00FF9C;
  --font:'DM Sans',-apple-system,sans-serif;--mono:'Space Mono',monospace;
}

* { box-sizing:border-box; }

.stApp {
  background:var(--bg)!important;
  color:var(--text)!important;
  font-family:var(--font)!important;
}
.stApp > header { display:none!important; }
.block-container { max-width:1200px!important; margin:0 auto!important; padding:0!important; }
div[data-testid="stHorizontalBlock"] { gap:0!important; }

/* ═══ PARTICLE CANVAS ═══ */
.particle-bg {
  position:fixed; inset:0; z-index:0; pointer-events:none; overflow:hidden;
}
.particle-bg .p {
  position:absolute; border-radius:50%; opacity:0;
  animation: float-up linear infinite;
}
@keyframes float-up {
  0%   { transform:translateY(100vh) scale(0); opacity:0; }
  10%  { opacity:1; }
  90%  { opacity:1; }
  100% { transform:translateY(-10vh) scale(1); opacity:0; }
}

/* ═══ RADIAL GLOW (subtle) ═══ */
.glow-layer {
  position:fixed; inset:0; z-index:0; pointer-events:none;
  background:
    radial-gradient(ellipse 700px 500px at 15% 10%, rgba(0,200,255,.035), transparent),
    radial-gradient(ellipse 600px 400px at 80% 15%, rgba(106,92,255,.03), transparent),
    radial-gradient(ellipse 400px 300px at 50% 80%, rgba(0,255,156,.015), transparent);
}

/* ═══ NAV BAR ═══ */
.landing-nav {
  position:sticky; top:0; z-index:100;
  background:rgba(11,15,20,.88);
  backdrop-filter:blur(16px); -webkit-backdrop-filter:blur(16px);
  border-bottom:1px solid rgba(28,37,53,.6);
  padding:14px 0;
}
.nav-inner {
  max-width:1200px; margin:0 auto; padding:0 24px;
  display:flex; align-items:center; justify-content:space-between;
}
.nav-brand {
  display:flex; align-items:center; gap:10px;
}
.nav-logo {
  width:32px;height:32px;border-radius:10px;
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  display:flex;align-items:center;justify-content:center;font-size:16px;
}
.nav-name {
  font-size:16px;font-weight:700;color:var(--text);letter-spacing:-.02em;
}
.nav-links { display:flex; gap:32px; align-items:center; }
.nav-links a {
  color:var(--muted);font-size:13px;text-decoration:none;font-weight:500;
  transition:color .2s;
}
.nav-links a:hover { color:var(--text); }
.nav-cta {
  padding:8px 20px;border-radius:10px;font-size:13px;font-weight:600;
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  color:#fff;text-decoration:none;
  transition:all .25s cubic-bezier(.22,1,.36,1);
  box-shadow:0 4px 16px rgba(0,200,255,.15);
}
.nav-cta:hover {
  transform:translateY(-1px);
  box-shadow:0 8px 28px rgba(0,200,255,.25);
}

/* ═══ HERO ═══ */
.hero {
  padding:100px 24px 72px; text-align:center; position:relative; z-index:1;
}
.hero-badge {
  display:inline-flex; align-items:center; gap:8px;
  padding:6px 16px; border-radius:999px;
  border:1px solid rgba(0,200,255,.2);
  background:rgba(0,200,255,.06);
  font-size:12px; color:#8DD9FF; font-family:var(--mono);
  margin-bottom:28px;
  animation:hero-in .6s cubic-bezier(.22,1,.36,1) .1s both;
}
.hero-badge span { display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse-dot 1.5s ease infinite; }

.hero h1 {
  font-size:clamp(42px,5.5vw,72px); font-weight:800; line-height:1.06;
  letter-spacing:-.03em; color:var(--text); margin:0 auto;
  max-width:900px;
  animation:hero-in .6s cubic-bezier(.22,1,.36,1) .2s both;
}
.hero h1 em {
  font-style:normal;
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  -webkit-background-clip:text; -webkit-text-fill-color:transparent;
  background-clip:text;
}
.hero-sub {
  max-width:640px; margin:20px auto 0; color:var(--muted);
  font-size:17px; line-height:1.7; font-weight:400;
  animation:hero-in .6s cubic-bezier(.22,1,.36,1) .35s both;
}
.hero-ctas {
  display:flex; gap:14px; justify-content:center; margin-top:36px;
  animation:hero-in .6s cubic-bezier(.22,1,.36,1) .5s both;
}
.hero-cta-primary {
  padding:14px 32px; border-radius:12px; font-size:15px; font-weight:600;
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  color:#fff; text-decoration:none; cursor:pointer; border:none;
  transition:all .25s cubic-bezier(.22,1,.36,1);
  box-shadow:0 4px 24px rgba(0,200,255,.2);
}
.hero-cta-primary:hover {
  transform:translateY(-2px);
  box-shadow:0 8px 36px rgba(0,200,255,.3);
}
.hero-cta-secondary {
  padding:14px 32px; border-radius:12px; font-size:15px; font-weight:600;
  background:transparent; border:1px solid var(--line);
  color:var(--text); text-decoration:none; cursor:pointer;
  transition:all .25s cubic-bezier(.22,1,.36,1);
}
.hero-cta-secondary:hover {
  border-color:rgba(0,200,255,.4);
  background:rgba(0,200,255,.04);
  transform:translateY(-2px);
}

@keyframes hero-in {
  from { opacity:0; transform:translateY(20px); }
  to   { opacity:1; transform:none; }
}
@keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:.3} }

/* ═══ FLOATING DASHBOARD PREVIEW ═══ */
.preview-wrap {
  max-width:900px; margin:0 auto; padding:0 24px;
  position:relative; z-index:1;
  animation:hero-in .6s cubic-bezier(.22,1,.36,1) .65s both;
}
.preview-card {
  background:rgba(17,22,28,.95);
  border:1px solid rgba(28,37,53,.8);
  border-radius:16px;
  padding:20px 24px;
  backdrop-filter:blur(12px);
  box-shadow:0 24px 64px rgba(0,0,0,.4), 0 0 0 1px rgba(255,255,255,.03) inset;
}
.preview-bar {
  display:flex; justify-content:space-between; align-items:center;
  margin-bottom:16px; padding-bottom:12px; border-bottom:1px solid rgba(28,37,53,.6);
}
.preview-bar-left { display:flex; gap:6px; }
.preview-dot { width:10px;height:10px;border-radius:50%; }
.preview-bar-right { font-size:10px;color:var(--muted);font-family:var(--mono);letter-spacing:.06em; }
.preview-metrics {
  display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px;
}
.preview-metric {
  background:rgba(11,15,20,.6); border:1px solid var(--line); border-radius:10px;
  padding:12px; text-align:center;
}
.preview-metric .val { font-size:20px;font-weight:700;font-family:var(--mono);color:var(--text); }
.preview-metric .lbl { font-size:9px;color:var(--muted);font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em;margin-top:4px; }
.preview-terminal {
  background:rgba(8,11,16,.8); border:1px solid var(--line); border-radius:10px;
  padding:14px 16px; font-family:var(--mono); font-size:12px; line-height:1.8;
}
.preview-terminal .line { animation:term-in .3s ease both; }
.preview-terminal .line:nth-child(1) { animation-delay:.8s; }
.preview-terminal .line:nth-child(2) { animation-delay:1.1s; }
.preview-terminal .line:nth-child(3) { animation-delay:1.4s; }
.preview-terminal .line:nth-child(4) { animation-delay:1.7s; }
@keyframes term-in { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:none} }

/* ═══ SECTIONS ═══ */
.section {
  position:relative; z-index:1; padding:0 24px;
  animation:reveal .5s cubic-bezier(.22,1,.36,1) both;
}
.section-title {
  font-size:32px; font-weight:800; color:var(--text);
  letter-spacing:-.02em; margin-bottom:8px;
}
.section-sub {
  font-size:15px; color:var(--muted); line-height:1.6;
  max-width:560px;
}

/* ═══ TRUST BAR ═══ */
.trust-bar {
  display:grid; grid-template-columns:repeat(3,1fr); gap:16px;
  max-width:1200px; margin:72px auto 0; padding:0 24px;
  position:relative; z-index:1;
}
.trust-item {
  background:var(--surface); border:1px solid var(--line); border-radius:14px;
  padding:24px; text-align:center;
  transition:all .3s cubic-bezier(.22,1,.36,1);
}
.trust-item:hover {
  border-color:rgba(0,200,255,.2);
  transform:translateY(-3px);
  box-shadow:0 12px 32px rgba(0,0,0,.2);
}
.trust-val {
  font-size:36px; font-weight:800; font-family:var(--mono);
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  -webkit-background-clip:text; -webkit-text-fill-color:transparent;
  background-clip:text;
}
.trust-lbl {
  font-size:12px; color:var(--muted); font-family:var(--mono);
  text-transform:uppercase; letter-spacing:.1em; margin-top:6px;
}
.trust-sub {
  font-size:12px; color:var(--muted); margin-top:4px; opacity:.7;
}

/* ═══ FEATURES GRID ═══ */
.features {
  display:grid; grid-template-columns:repeat(4,1fr); gap:16px;
  margin-top:24px;
}
.feature-card {
  background:var(--surface); border:1px solid var(--line); border-radius:14px;
  padding:24px; position:relative; overflow:hidden;
  transition:all .3s cubic-bezier(.22,1,.36,1);
  cursor:default;
}
.feature-card::before {
  content:''; position:absolute; top:0; left:0; right:0; height:2px;
  background:linear-gradient(90deg,transparent,var(--cyan),transparent);
  opacity:0; transition:opacity .3s;
}
.feature-card:hover {
  border-color:rgba(0,200,255,.2);
  transform:translateY(-4px);
  box-shadow:0 16px 40px rgba(0,0,0,.25);
}
.feature-card:hover::before { opacity:1; }
.feature-icon {
  width:44px;height:44px;border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  font-size:22px;margin-bottom:16px;
}
.feature-title { font-size:16px; font-weight:700; color:var(--text); margin-bottom:8px; }
.feature-desc { font-size:13px; color:var(--muted); line-height:1.6; }

/* ═══ HOW IT WORKS ═══ */
.steps-flow {
  display:grid;grid-template-columns:repeat(5,1fr);gap:0;margin-top:32px;
  align-items:center;
}
.step-card {
  background:var(--surface);border:1px solid var(--line);border-radius:14px;
  padding:24px 20px;text-align:center;position:relative;
  transition:all .3s cubic-bezier(.22,1,.36,1);
}
.step-card:hover {
  border-color:rgba(0,200,255,.25);
  transform:translateY(-3px);
  box-shadow:0 12px 32px rgba(0,0,0,.2);
}
.step-num {
  width:32px;height:32px;border-radius:10px;
  background:rgba(0,200,255,.1);border:1px solid rgba(0,200,255,.2);
  display:inline-flex;align-items:center;justify-content:center;
  font-size:14px;font-weight:700;color:var(--cyan);font-family:var(--mono);
  margin-bottom:12px;
}
.step-title { font-size:15px;font-weight:700;color:var(--text);margin-bottom:6px; }
.step-desc { font-size:12px;color:var(--muted);line-height:1.5; }
.step-arrow {
  display:flex;align-items:center;justify-content:center;
  color:var(--muted);font-size:20px;opacity:.4;
}

/* ═══ CONNECT SECTION ═══ */
.connect-steps {
  display:grid; grid-template-columns:repeat(3,1fr); gap:20px; margin-top:28px;
}
.connect-step {
  background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:28px 24px;
  transition:all .3s cubic-bezier(.22,1,.36,1);position:relative;
}
.connect-step:hover {
  border-color:rgba(0,200,255,.2);transform:translateY(-3px);
  box-shadow:0 12px 32px rgba(0,0,0,.2);
}
.connect-num {
  width:28px;height:28px;border-radius:8px;background:rgba(0,200,255,.08);
  border:1px solid rgba(0,200,255,.15);display:inline-flex;align-items:center;
  justify-content:center;font-size:13px;font-weight:700;color:var(--cyan);
  font-family:var(--mono);margin-bottom:14px;
}
.connect-title { font-size:16px;font-weight:700;color:var(--text);margin-bottom:8px; }
.connect-desc { font-size:13px;color:var(--muted);line-height:1.6; }
.connect-visual {
  margin-top:14px;background:rgba(8,11,16,.6);border:1px solid var(--line);
  border-radius:8px;padding:10px 14px;font-family:var(--mono);font-size:11px;
  color:var(--cyan);
}

/* ═══ CTA SECTION ═══ */
.final-cta {
  text-align:center;padding:80px 24px 40px;margin-top:60px;
  position:relative;z-index:1;
}
.final-cta h2 {
  font-size:clamp(28px,4vw,44px);font-weight:800;color:var(--text);
  letter-spacing:-.02em;margin:0 0 14px;
}
.final-cta p {
  font-size:16px;color:var(--muted);max-width:520px;margin:0 auto 32px;
  line-height:1.7;
}
.final-cta-btn {
  display:inline-block;padding:16px 40px;border-radius:14px;font-size:16px;font-weight:700;
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  color:#fff;text-decoration:none;
  transition:all .3s cubic-bezier(.22,1,.36,1);
  box-shadow:0 6px 28px rgba(0,200,255,.2);
}
.final-cta-btn:hover {
  transform:translateY(-2px);
  box-shadow:0 10px 40px rgba(0,200,255,.35);
}

/* ═══ FOOTER ═══ */
.landing-footer {
  border-top:1px solid var(--line);
  padding:32px 24px;margin-top:40px;
  display:flex;justify-content:space-between;align-items:center;
  max-width:1200px;margin-left:auto;margin-right:auto;
}
.footer-brand { font-size:14px;font-weight:700;color:var(--text); }
.footer-sub { font-size:11px;color:var(--muted);margin-top:4px; }
.footer-links { display:flex;gap:24px; }
.footer-links a { font-size:12px;color:var(--muted);text-decoration:none;transition:color .2s; }
.footer-links a:hover { color:var(--text); }
.footer-copy { font-size:11px;color:var(--muted);font-family:var(--mono); }

/* ═══ RESPONSIVE ═══ */
@media(max-width:960px) {
  .features, .preview-metrics { grid-template-columns:repeat(2,1fr); }
  .steps-flow { grid-template-columns:1fr; }
  .step-arrow { display:none; }
  .connect-steps { grid-template-columns:1fr; }
  .trust-bar { grid-template-columns:1fr; }
  .landing-footer { flex-direction:column;gap:16px;text-align:center; }
}
@media(max-width:640px) {
  .features { grid-template-columns:1fr; }
  .hero h1 { font-size:36px; }
  .nav-links { display:none; }
}

/* ═══ SCROLL REVEAL ═══ */
@keyframes reveal {
  from { opacity:0; transform:translateY(24px); }
  to   { opacity:1; transform:none; }
}

/* ═══ HIDE STREAMLIT ELEMENTS ═══ */
#MainMenu, footer, [data-testid="stDecoration"], [data-testid="stToolbar"], [data-testid="stStatusWidget"] { display:none!important; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════ PARTICLES ═══════════════════
particles_html = ""
import random
for i in range(30):
    size = random.uniform(1.5, 3.5)
    left = random.uniform(0, 100)
    dur = random.uniform(12, 28)
    delay = random.uniform(0, 15)
    opacity = random.uniform(0.15, 0.4)
    color = random.choice(["rgba(0,200,255,{})".format(opacity), "rgba(106,92,255,{})".format(opacity), "rgba(0,255,156,{})".format(opacity * 0.6)])
    particles_html += f'<div class="p" style="width:{size}px;height:{size}px;left:{left}%;background:{color};animation-duration:{dur}s;animation-delay:{delay}s"></div>'

st.markdown(f"""
<div class="particle-bg">{particles_html}</div>
<div class="glow-layer"></div>
""", unsafe_allow_html=True)

# ═══════════════════ NAVIGATION ═══════════════════
st.markdown("""
<div class="landing-nav">
  <div class="nav-inner">
    <div class="nav-brand">
      <div class="nav-logo">🛡️</div>
      <div class="nav-name">AutoShield AI</div>
    </div>
    <div class="nav-links">
      <a href="#features">Features</a>
      <a href="#how-it-works">How It Works</a>
      <a href="#connect">Connect</a>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════ HERO ═══════════════════
st.markdown("""
<section class="hero">
  <div class="hero-badge">
    <span></span> REAL-TIME PROTECTION ACTIVE
  </div>
  <h1>Autonomous Cyber Defense<br/>for <em>Modern Infrastructure</em></h1>
  <div class="hero-sub">
    Real-time threat detection engine that identifies, scores, and automatically blocks
    malicious traffic before it reaches your infrastructure. Zero manual intervention required.
  </div>
</section>
""", unsafe_allow_html=True)

# CTA buttons via Streamlit (for proper navigation)
c1, c2, c3, c4, c5 = st.columns([1.5, 1, 0.4, 1, 1.5])
with c2:
    st.page_link("pages/00_Login.py", label="Start Protecting Your Site →", icon="🚀")
with c4:
    st.page_link("dashboard.py", label="View Live Demo", icon="🛡️")

# ═══════════════════ FLOATING DASHBOARD PREVIEW ═══════════════════
st.markdown("""
<div class="preview-wrap" style="margin-top:40px">
  <div class="preview-card">
    <div class="preview-bar">
      <div class="preview-bar-left">
        <div class="preview-dot" style="background:#FF5F57"></div>
        <div class="preview-dot" style="background:#FEBC2E"></div>
        <div class="preview-dot" style="background:#28C840"></div>
      </div>
      <div class="preview-bar-right">AUTOSHIELD FUSION CONSOLE — LIVE TELEMETRY</div>
    </div>
    <div class="preview-metrics">
      <div class="preview-metric">
        <div class="val" style="color:#FF4D4D">12</div>
        <div class="lbl">Active threats</div>
      </div>
      <div class="preview-metric">
        <div class="val" style="color:#00C8FF">2.4K</div>
        <div class="lbl">Requests/sec</div>
      </div>
      <div class="preview-metric">
        <div class="val" style="color:#00FF9C">847</div>
        <div class="lbl">Blocked IPs</div>
      </div>
      <div class="preview-metric">
        <div class="val" style="color:#6A5CFF">99.97%</div>
        <div class="lbl">Uptime</div>
      </div>
    </div>
    <div class="preview-terminal">
      <div class="line"><span style="color:#FF4D4D">[CRITICAL]</span> <span style="color:#8B949E">14:23:07</span> — SQLi injection detected from <span style="color:#E7EEF9">185.220.101.34</span> → <span style="color:#00FF9C">BLOCKED</span></div>
      <div class="line"><span style="color:#FFC857">[WARNING]</span>&nbsp; <span style="color:#8B949E">14:23:05</span> — XSS payload in /api/comments from <span style="color:#E7EEF9">91.132.147.22</span> → <span style="color:#00FF9C">BLOCKED</span></div>
      <div class="line"><span style="color:#00C8FF">[INFO]</span>&nbsp;&nbsp;&nbsp;&nbsp; <span style="color:#8B949E">14:23:02</span> — WAF rules synchronized across 136 edge nodes</div>
      <div class="line"><span style="color:#00FF9C">[OK]</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span style="color:#8B949E">14:22:58</span> — Threat model v3.7 deployed — 847 new signatures active</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════ TRUST BAR ═══════════════════
st.markdown("""
<div class="trust-bar">
  <div class="trust-item">
    <div class="trust-val">18.4M+</div>
    <div class="trust-lbl">Attacks Blocked</div>
    <div class="trust-sub">Across all protected domains</div>
  </div>
  <div class="trust-item">
    <div class="trust-val">4.2B</div>
    <div class="trust-lbl">Requests Processed</div>
    <div class="trust-sub">With sub-millisecond latency</div>
  </div>
  <div class="trust-item">
    <div class="trust-val">99.99%</div>
    <div class="trust-lbl">Uptime SLA</div>
    <div class="trust-sub">136 active monitoring nodes</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════ FEATURES ═══════════════════
st.markdown("""
<div class="section" style="margin-top:80px" id="features">
  <div class="section-title">Platform Capabilities</div>
  <div class="section-sub">Everything you need to detect, analyze, block, and report cyber threats in real-time.</div>
  <div class="features">
    <div class="feature-card">
      <div class="feature-icon" style="background:rgba(0,200,255,.08);border:1px solid rgba(0,200,255,.15)">⚡</div>
      <div class="feature-title">Real-Time Detection</div>
      <div class="feature-desc">Stream-driven detection engine with rapid signal-to-alert pipeline. Identifies SQLi, XSS, LFI, and command injection in milliseconds.</div>
    </div>
    <div class="feature-card">
      <div class="feature-icon" style="background:rgba(0,255,156,.08);border:1px solid rgba(0,255,156,.15)">🧱</div>
      <div class="feature-title">Auto-Blocking Firewall</div>
      <div class="feature-desc">Automated mitigation through adaptive rules, rate limiting, country blocking, and dynamic IP blocklists. Zero manual intervention.</div>
    </div>
    <div class="feature-card">
      <div class="feature-icon" style="background:rgba(106,92,255,.08);border:1px solid rgba(106,92,255,.15)">🧠</div>
      <div class="feature-title">Threat Intelligence</div>
      <div class="feature-desc">CVE and CERT-In advisory enrichment to prioritize incidents with real-world context. CVSS scoring and attack correlation.</div>
    </div>
    <div class="feature-card">
      <div class="feature-icon" style="background:rgba(255,77,77,.08);border:1px solid rgba(255,77,77,.15)">🌐</div>
      <div class="feature-title">Attack Visualization</div>
      <div class="feature-desc">Live geographic telemetry with GeoIP mapping, timeline-based incident replay, and real-time threat score gauges.</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════ LIVE DEMO PREVIEW ═══════════════════
st.markdown("""
<div class="section" style="margin-top:80px">
  <div class="section-title">SOC Dashboard Preview</div>
  <div class="section-sub">A real-time security operations center, right in your browser.</div>
  <div style="margin-top:28px;background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:24px;position:relative;overflow:hidden">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--line)">
      <div>
        <span style="font-size:14px;font-weight:700;color:var(--text)">Fusion Dashboard</span>
        <span style="margin-left:12px;padding:3px 10px;border-radius:6px;background:rgba(0,255,156,.08);border:1px solid rgba(0,255,156,.15);font-size:10px;color:var(--green);font-family:var(--mono)">LIVE</span>
      </div>
      <div style="font-size:11px;color:var(--muted);font-family:var(--mono)">THREAT LEVEL: <span style="color:var(--red)">ELEVATED</span></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">
      <div style="background:rgba(8,11,16,.5);border:1px solid var(--line);border-radius:10px;padding:16px;text-align:center">
        <div style="font-size:10px;color:var(--muted);font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">Threat Score</div>
        <div style="font-size:32px;font-weight:800;color:#FF4D4D;font-family:var(--mono);margin-top:4px">78</div>
        <div style="height:4px;background:#131b2a;border-radius:2px;margin-top:8px"><div style="height:100%;width:78%;background:linear-gradient(90deg,#FFC857,#FF4D4D);border-radius:2px"></div></div>
      </div>
      <div style="background:rgba(8,11,16,.5);border:1px solid var(--line);border-radius:10px;padding:16px;text-align:center">
        <div style="font-size:10px;color:var(--muted);font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">Block Rate</div>
        <div style="font-size:32px;font-weight:800;color:#00FF9C;font-family:var(--mono);margin-top:4px">94%</div>
        <div style="height:4px;background:#131b2a;border-radius:2px;margin-top:8px"><div style="height:100%;width:94%;background:var(--green);border-radius:2px"></div></div>
      </div>
      <div style="background:rgba(8,11,16,.5);border:1px solid var(--line);border-radius:10px;padding:16px;text-align:center">
        <div style="font-size:10px;color:var(--muted);font-family:var(--mono);text-transform:uppercase;letter-spacing:.08em">Active Rules</div>
        <div style="font-size:32px;font-weight:800;color:#00C8FF;font-family:var(--mono);margin-top:4px">847</div>
        <div style="height:4px;background:#131b2a;border-radius:2px;margin-top:8px"><div style="height:100%;width:85%;background:var(--cyan);border-radius:2px"></div></div>
      </div>
    </div>
    <div style="background:rgba(8,11,16,.5);border:1px solid var(--line);border-radius:10px;padding:14px 16px;font-family:var(--mono);font-size:11px;line-height:2">
      <span style="color:#FF4D4D">[CRITICAL]</span> SQLi pattern matched — src: 185.220.101.34 → rule: WAF-SQL-044 → <span style="color:#00FF9C">AUTO-BLOCKED</span><br/>
      <span style="color:#FFC857">[HIGH]</span>&nbsp;&nbsp;&nbsp;&nbsp; XSS reflected input — src: 91.132.147.22 → rule: WAF-XSS-018 → <span style="color:#00FF9C">AUTO-BLOCKED</span><br/>
      <span style="color:#00C8FF">[MEDIUM]</span>&nbsp; Rate limit triggered — src: 203.0.113.91 → 142 req/min → <span style="color:#FFC857">THROTTLED</span><br/>
      <span style="color:#8B949E">[INFO]</span>&nbsp;&nbsp;&nbsp;&nbsp; Geo-fence: 3 connections from blocked region → <span style="color:#00FF9C">DROPPED</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════ HOW IT WORKS ═══════════════════
st.markdown("""
<div class="section" style="margin-top:80px" id="how-it-works">
  <div class="section-title">How It Works</div>
  <div class="section-sub">Five stages of autonomous defense — from ingestion to incident reporting.</div>
  <div class="steps-flow">
    <div class="step-card">
      <div class="step-num">1</div>
      <div class="step-title">Traffic</div>
      <div class="step-desc">Ingest all HTTP requests and network signals in real-time</div>
    </div>
    <div class="step-arrow">→</div>
    <div class="step-card">
      <div class="step-num">2</div>
      <div class="step-title">Detection</div>
      <div class="step-desc">ML-powered analysis identifies attack patterns instantly</div>
    </div>
    <div class="step-arrow">→</div>
    <div class="step-card">
      <div class="step-num">3</div>
      <div class="step-title">Scoring</div>
      <div class="step-desc">Threat intelligence enrichment with CVE and CVSS correlation</div>
    </div>
    <div class="step-arrow">→</div>
    <div class="step-card">
      <div class="step-num">4</div>
      <div class="step-title">Blocking</div>
      <div class="step-desc">Automated response through firewall rules and IP blocks</div>
    </div>
    <div class="step-arrow">→</div>
    <div class="step-card">
      <div class="step-num">5</div>
      <div class="step-title">Reporting</div>
      <div class="step-desc">Generate SOC-grade incident reports with full audit trail</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════ CONNECT YOUR WEBSITE ═══════════════════
st.markdown("""
<div class="section" style="margin-top:80px" id="connect">
  <div class="section-title">Connect Your Website</div>
  <div class="section-sub">Get enterprise-grade protection in three simple steps.</div>
  <div class="connect-steps">
    <div class="connect-step">
      <div class="connect-num">1</div>
      <div class="connect-title">Add Your Domain</div>
      <div class="connect-desc">Enter your domain name and verify ownership through DNS TXT record or file upload.</div>
      <div class="connect-visual">
        <span style="color:#8B949E">domain:</span> example.com<br/>
        <span style="color:#8B949E">status:</span> <span style="color:#FFC857">pending verification</span>
      </div>
    </div>
    <div class="connect-step">
      <div class="connect-num">2</div>
      <div class="connect-title">Point Your DNS</div>
      <div class="connect-desc">Update your DNS records to route traffic through AutoShield's edge network.</div>
      <div class="connect-visual">
        <span style="color:#8B949E">CNAME:</span> proxy.autoshield.ai<br/>
        <span style="color:#8B949E">A:</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 104.26.8.142
      </div>
    </div>
    <div class="connect-step">
      <div class="connect-num">3</div>
      <div class="connect-title">Activate Protection</div>
      <div class="connect-desc">Enable real-time monitoring, auto-blocking, and threat intelligence for your site.</div>
      <div class="connect-visual">
        <span style="color:#8B949E">protection:</span> <span style="color:#00FF9C">● ACTIVE</span><br/>
        <span style="color:#8B949E">waf_rules:</span>&nbsp; <span style="color:#00C8FF">847 loaded</span>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════ FINAL CTA ═══════════════════
st.markdown("""
<div class="final-cta">
  <h2>Secure Your Infrastructure in Minutes</h2>
  <p>Move from reactive monitoring to proactive cyber defense. One control plane for detection, blocking, threat intelligence, and compliance reporting.</p>
</div>
""", unsafe_allow_html=True)

_, cta_col, _ = st.columns([1, 1.2, 1])
with cta_col:
    st.page_link("pages/00_Login.py", label="Get Started — It's Free →", icon="🚀")

# ═══════════════════ FOOTER ═══════════════════
st.markdown("""
<div class="landing-footer">
  <div>
    <div class="footer-brand">🛡️ AutoShield AI</div>
    <div class="footer-sub">Autonomous Cyber Defense Platform</div>
  </div>
  <div class="footer-links">
    <a href="#features">Features</a>
    <a href="#how-it-works">How It Works</a>
    <a href="#connect">Connect</a>
  </div>
  <div class="footer-copy">© 2024 AutoShield AI · Security · Compliance · Reliability</div>
</div>
""", unsafe_allow_html=True)
