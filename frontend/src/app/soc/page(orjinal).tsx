"use client";
import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  ShieldAlert, Activity, Search, WifiOff, Wifi, XOctagon, Loader2, Bot, Zap,
  Server, ShieldCheck, Lock, LogIn, Usb, FileWarning, Globe, LayoutDashboard,
  RefreshCw, Trash2, Plus, Copy, AlertTriangle, BarChart3, Terminal,
  Eye, BookOpen, Users, Cpu, Network, Database, TrendingUp, ChevronRight,
  Crosshair, Package, Clock, Filter, X, Check, Radio, HardDrive, Layers
} from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, AreaChart, Area
} from 'recharts';

// ─── TYPES ─────────────────────────────────────────────────────────────────

interface Alert {
  id: string;
  hostname: string;
  rule: string;
  severity: 'CRITICAL' | 'HIGH' | 'WARNING' | 'INFO';
  serial: string;
  pid: number;
  details: string;
  created_at: string;
  risk_score: number;
  username?: string;
  command_line?: string;
  type?: string;
}

interface CorrelationAlert {
  id: string;
  type?: string;
  rule: string;
  severity: string;
  description: string;
  hostname: string;
  user: string;
  timestamp: string;
  risk: { score: number; level: string };
  mitre?: { technique: string; tactic: string }[];
  evidence?: any[];
}

interface SigmaAlert extends CorrelationAlert {
  sigma_id?: string;
}

interface UEBAAnomaly {
  username: string;
  hostname: string;
  anomaly: string;
  score: number;
  description: string;
  timestamp: string;
}

interface Asset {
  hostname: string;
  last_seen: string;
  is_online: boolean;
  alert_count: number;
  max_risk: number;
  status: string;
}

interface UserProfile {
  username: string;
  observation_days: number;
  is_mature: boolean;
  typical_hours: string;
  known_hosts: string[];
  avg_risk_score: number;
  top_processes: [string, number][];
}

interface Rule {
  id?: string;
  name: string;
  keyword: string;
  risk_score: number;
  severity: string;
}

interface ProcessInfo {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
  status: string;
  user: string;
  cmdline?: string;
}

type NavTab = 'alerts' | 'correlation' | 'sigma' | 'hunting' | 'ueba' | 'assets';

// ─── HELPERS ───────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
let wsLock = false;

const fmt = (d: string) => {
  try {
    return new Date(d).toLocaleString('tr-TR', {
      month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  } catch { return d; }
};

const relativeTime = (d: string) => {
  const diff = Date.now() - new Date(d).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'az önce';
  if (mins < 60) return `${mins}dk önce`;
  if (mins < 1440) return `${Math.floor(mins / 60)}sa önce`;
  return `${Math.floor(mins / 1440)}g önce`;
};

// BOM ve özel karakter temizleyici
const sanitize = (str: string): string => {
  if (!str) return '';
  return str
    .replace(/^\uFEFF/, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\uFFFD]/g, '')
    .trim();
};

const sevColor = (s: string) => ({
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/20',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  WARNING:  'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  MEDIUM:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  INFO:     'text-sky-400 bg-sky-500/10 border-sky-500/20',
  LOW:      'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
}[s] || 'text-slate-400 bg-slate-500/10 border-slate-500/20');

const sevDot = (s: string) => ({
  CRITICAL: 'bg-red-500',
  HIGH:     'bg-orange-500',
  WARNING:  'bg-yellow-500',
  MEDIUM:   'bg-yellow-500',
  INFO:     'bg-sky-500',
  LOW:      'bg-emerald-500',
}[s] || 'bg-slate-500');

const riskBar = (score: number) => {
  if (score >= 80) return 'bg-red-500';
  if (score >= 60) return 'bg-orange-500';
  if (score >= 40) return 'bg-yellow-500';
  return 'bg-emerald-500';
};

// ─── MAIN COMPONENT ────────────────────────────────────────────────────────

export default function SOCDashboard() {

  // Auth
  const [token, setToken] = useState<string | null>(null);
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [loginError, setLoginError] = useState("");

  // Navigation
  const [activeTab, setActiveTab] = useState<NavTab>('alerts');

  // Core alert state
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [correlationAlerts, setCorrelationAlerts] = useState<CorrelationAlert[]>([]);
  const [sigmaAlerts, setSigmaAlerts] = useState<SigmaAlert[]>([]);
  const [uebaAnomalies, setUebaAnomalies] = useState<UEBAAnomaly[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [userProfiles, setUserProfiles] = useState<UserProfile[]>([]);

  // Stats
  const [stats, setStats] = useState({ total: 0, critical: 0, activeHosts: 0, last_24h: 0 });
  const [sigmaStats, setSigmaStats] = useState<any>({ total: 0, by_severity: {} });
  const [analyticsData, setAnalyticsData] = useState<any>({ severity_distribution: [], activity_trend: [] });

  // UI state
  const [searchTerm, setSearchTerm] = useState("");
  const [huntQuery, setHuntQuery] = useState("");
  const [huntResults, setHuntResults] = useState<any>(null);
  const [huntLoading, setHuntLoading] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [selectedLog, setSelectedLog] = useState<Alert | null>(null);
  const [selectedCorr, setSelectedCorr] = useState<CorrelationAlert | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [aiResult, setAiResult] = useState<string | null>(null);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [showCharts, setShowCharts] = useState(false);
  const [showProcessModal, setShowProcessModal] = useState(false);
  const [showPasswordChange, setShowPasswordChange] = useState(false);
  const [showUserMgmt, setShowUserMgmt] = useState(false);
  const [userList, setUserList] = useState<any[]>([]);
  const [pwForm, setPwForm] = useState({ current: "", next: "", confirm: "" });
  const [newUserForm, setNewUserForm] = useState({ username: "", password: "", role: "analyst", email: "" });
  const [showTenantMgmt, setShowTenantMgmt] = useState(false);
  const [show2FA, setShow2FA] = useState(false);
  const [twoFAStatus, setTwoFAStatus] = useState<{totp_enabled: boolean} | null>(null);
  const [twoFASetup, setTwoFASetup] = useState<{secret: string; qr_data_url: string | null; uri: string} | null>(null);
  const [twoFACode, setTwoFACode] = useState("");
  const [tenantList, setTenantList] = useState<any[]>([]);
  const [newTenantForm, setNewTenantForm] = useState({ name: "", contact_email: "", max_agents: 10, plan: "starter" });
  const [processList, setProcessList] = useState<ProcessInfo[]>([]);
  const [processLoading, setProcessLoading] = useState(false);
  const [processFilter, setProcessFilter] = useState("");
  const [newRule, setNewRule] = useState<Rule>({ name: "", keyword: "", risk_score: 50, severity: "WARNING" });
  const [notification, setNotification] = useState<{ msg: string; type: 'ok' | 'err' } | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const tokenRef = useRef<string | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(false);

  // ── Filtered alerts (client-side)
  const filteredAlerts = searchTerm.trim()
    ? alerts.filter(a => {
        const q = searchTerm.toLowerCase();
        return [a.rule, a.hostname, a.details, a.serial, a.command_line, a.username, String(a.pid), a.severity]
          .some(v => v?.toLowerCase().includes(q));
      })
    : alerts;

  // ─── AUTH ────────────────────────────────────────────────────────────────

  useEffect(() => {
    const t = localStorage.getItem('soc_token');
    if (t) { setToken(t); tokenRef.current = t; }
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    try {
      const fd = new FormData();
      fd.append("username", loginForm.username);
      fd.append("password", loginForm.password);
      const res = await fetch(`${API}/api/login`, { method: "POST", body: fd });
      if (res.ok) {
        const d = await res.json();
        setToken(d.access_token);
        tokenRef.current = d.access_token;
        localStorage.setItem('soc_token', d.access_token);
        if (d.password_change_required) {
          setShowPasswordChange(true);
        }
      } else {
        setLoginError("Kullanıcı adı veya şifre hatalı!");
      }
    } catch { setLoginError("Sunucuya erişilemiyor."); }
  };

  const headers = () => {
    const t = tokenRef.current || localStorage.getItem('soc_token') || token;
    return { "Authorization": `Bearer ${t}`, "Content-Type": "application/json" };
  };

  // fetch wrapper — 401 gelirse otomatik logout
  const authFetch = async (url: string, options: RequestInit = {}): Promise<Response> => {
    const res = await fetch(url, { ...options, headers: { ...headers(), ...(options.headers || {}) } });
    if (res.status === 401) {
      notify("Oturum süresi dolmuş — tekrar giriş yapın", "err");
      setToken(null);
      tokenRef.current = null;
      localStorage.removeItem('soc_token');
    }
    return res;
  };

  // ─── DATA FETCHING ───────────────────────────────────────────────────────

  const notify = (msg: string, type: 'ok' | 'err' = 'ok') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 3000);
  };

  const fetchAll = useCallback(async () => {
    if (!token) return;
    try {
      const [statsR, alertsR, analyticsR, assetsR, uebaR, sigmaR] = await Promise.allSettled([
        fetch(`${API}/api/stats`,            { headers: headers() }),
        fetch(`${API}/api/alerts`,           { headers: headers() }),
        fetch(`${API}/api/analytics`,        { headers: headers() }),
        fetch(`${API}/api/v1/assets`,        { headers: headers() }),
        fetch(`${API}/api/v1/ueba/profiles`, { headers: headers() }),
        fetch(`${API}/api/v1/sigma/stats`,   { headers: headers() }),
      ]);

      if (statsR.status === 'fulfilled' && statsR.value.ok) {
        const d = await statsR.value.json();
        setStats(prev => ({ ...prev, total: d.total_logs || 0, critical: d.critical_count || 0, last_24h: d.last_24h || 0 }));
      }
      if (alertsR.status === 'fulfilled' && alertsR.value.ok) {
        const d = await alertsR.value.json();
        setAlerts(d);
        setStats(prev => ({ ...prev, activeHosts: new Set(d.map((a: Alert) => a.hostname)).size }));
      }
      if (analyticsR.status === 'fulfilled' && analyticsR.value.ok) {
        setAnalyticsData(await analyticsR.value.json());
      }
      if (assetsR.status === 'fulfilled' && assetsR.value.ok) {
        const d = await assetsR.value.json();
        setAssets(d.assets || []);
      }
      if (uebaR.status === 'fulfilled' && uebaR.value.ok) {
        const d = await uebaR.value.json();
        setUserProfiles(d.profiles || []);
      }
      if (sigmaR.status === 'fulfilled' && sigmaR.value.ok) {
        setSigmaStats(await sigmaR.value.json());
      }
    } catch (e) { console.error("Fetch error:", e); }
  }, [token]);

  // ─── WEBSOCKET ───────────────────────────────────────────────────────────

  const connectWs = useCallback(() => {
    if (!token || !mountedRef.current || wsLock) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    wsLock = true;

    const ws = new WebSocket(`ws://localhost:8000/ws/alerts`);
    wsRef.current = ws;

    ws.onopen = () => {
      wsLock = false;
      if (mountedRef.current) setWsConnected(true);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (!mountedRef.current) return;

        if (msg.type === 'alert') {
          setAlerts(prev => [msg.data, ...prev].slice(0, 500));
          setStats(prev => ({
            ...prev,
            total: prev.total + 1,
            critical: msg.data.severity === 'CRITICAL' ? prev.critical + 1 : prev.critical
          }));
        } else if (msg.type === 'correlation_alert') {
          const d = msg.data as CorrelationAlert;
          // Sigma veya UEBA'dan mı geldi?
          if (d.rule?.startsWith('SIGMA:')) {
            setSigmaAlerts(prev => [d as SigmaAlert, ...prev].slice(0, 200));
          } else if (d.type === 'UEBA_ANOMALY') {
            setUebaAnomalies(prev => [{
              username: d.user, hostname: d.hostname,
              anomaly: d.rule, score: d.risk.score,
              description: d.description, timestamp: d.timestamp,
            }, ...prev].slice(0, 200));
          } else {
            setCorrelationAlerts(prev => [d, ...prev].slice(0, 200));
          }
        } else if (msg.type === 'ACTION_LOG') {
          const m = msg.message || "";
          if (m.includes("AI RAPORU") || m.includes("AI Raporu") || m.includes("\u{1F9E0}")) {
            const parts = m.split("AI RAPORU:");
            const clean = (parts.length > 1 ? parts[1] : m).trim();
            setAiResult(clean || m);
            setLoadingAction(null);
          } else if (m.includes("AI Devre")) {
            setAiResult("GROQ_API_KEY tanimli degil. .env dosyasina GROQ_API_KEY=... ekleyin.");
            setLoadingAction(null);
          } else if (m.includes("AI") && m.includes("Hata")) {
            setAiResult("AI Analiz hatasi: " + m);
            setLoadingAction(null);
          }        }
      } catch {}
    };

    ws.onerror = () => { wsLock = false; if (mountedRef.current) setWsConnected(false); };
    ws.onclose = () => {
      wsLock = false;
      if (mountedRef.current) {
        setWsConnected(false);
        reconnectRef.current = setTimeout(() => { if (mountedRef.current) connectWs(); }, 3000);
      }
    };
  }, [token]);

  useEffect(() => {
    if (token) {
      mountedRef.current = true;
      fetchAll();
      connectWs();
    }
    return () => {
      mountedRef.current = false;
      wsLock = false;
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [token, fetchAll, connectWs]);

  // ─── ACTIONS ─────────────────────────────────────────────────────────────

  const sendCommand = async (cmd: string, target: Alert | null) => {
    if (!target && cmd !== "CLEAR_LOGS") return;

    // Token kontrolü — eksikse kullanıcıyı uyar
    const currentToken = tokenRef.current || localStorage.getItem('soc_token');
    if (!currentToken) {
      notify("Oturum süresi dolmuş — lütfen tekrar giriş yapın", "err");
      setToken(null);
      tokenRef.current = null;
      localStorage.removeItem('soc_token');
      return;
    }
    // tokenRef'i güncelle (localStorage'dan geldiyse)
    if (!tokenRef.current && currentToken) tokenRef.current = currentToken;

    setLoadingAction(cmd);
    try {
      if (cmd === "CLEAR_LOGS") {
        await authFetch(`${API}/api/alerts/clear`, { method: "DELETE" });
        setAlerts([]); setStats({ total: 0, critical: 0, activeHosts: 0, last_24h: 0 });
        notify("Loglar temizlendi");
        setLoadingAction(null);
      } else if (cmd === "AI_ANALYZE") {
        setAiResult(null);
        const res = await authFetch(`${API}/api/actions/analyze`, {
          method: "POST",
          body: JSON.stringify({
            hostname: target?.hostname, pid: target?.pid,
            rule: target?.rule, severity: target?.severity,
            details: target?.details, serial: target?.serial,
            risk_score: target?.risk_score,
            command_line: target?.command_line,
          })
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: "Sunucu hatası" }));
          notify(err.detail || "AI analizi başlatılamadı", "err");
          setLoadingAction(null);
        } else {
          notify("AI analizi başlatıldı, bekleniyor...");
          // Timeout — 30s sonra hâlâ gelmemişse loading'i kapat
          setTimeout(() => setLoadingAction(null), 30000);
        }
      } else if (cmd === "KILL") {
        const res = await authFetch(`${API}/api/actions/kill`, {
          method: "POST",
          body: JSON.stringify({ hostname: target?.hostname, pid: target?.pid })
        });
        if (res.ok) notify(`PID ${target?.pid} sonlandırma komutu gönderildi`);
        else notify("Sonlandırma komutu gönderilemedi", "err");
        setLoadingAction(null);
      } else if (cmd === "KILL_BY_PID") {
        // Process listesinden doğrudan PID kill
        const { hostname, pid } = target as any;
        const res = await authFetch(`${API}/api/actions/kill`, {
          method: "POST",
          body: JSON.stringify({ hostname, pid })
        });
        if (res.ok) {
          notify(`PID ${pid} sonlandırıldı`);
          setProcessList(prev => prev.filter(p => p.pid !== pid));
        } else notify("Kill komutu gönderilemedi", "err");
        setLoadingAction(null);
      } else if (cmd === "USB_DISABLE") {
        const res = await authFetch(`${API}/api/actions/usb_disable`, {
          method: "POST",
          body: JSON.stringify({ hostname: target?.hostname })
        });
        if (res.ok) notify("USB devre dışı bırakma komutu gönderildi");
        else notify("USB komutu gönderilemedi", "err");
        setLoadingAction(null);
      } else if (cmd === "USB_ENABLE") {
        const res = await authFetch(`${API}/api/actions/usb_enable`, {
          method: "POST",
          body: JSON.stringify({ hostname: target?.hostname })
        });
        if (res.ok) notify("USB aktif etme komutu gönderildi");
        else notify("USB komutu gönderilemedi", "err");
        setLoadingAction(null);
      } else {
        const res = await authFetch(`${API}/api/actions/${cmd.toLowerCase()}`, {
          method: "POST",
          body: JSON.stringify({ hostname: target?.hostname, pid: target?.pid })
        });
        if (res.ok) notify(`${cmd} komutu gönderildi`);
        else notify(`${cmd} komutu gönderilemedi`, "err");
        setLoadingAction(null);
      }
    } catch { notify("Komut gönderilemedi — sunucu bağlantısı kesildi", "err"); setLoadingAction(null); }
  };

  const fetch2FAStatus = async () => {
    try {
      const res = await authFetch(`${API}/api/me/2fa-status`);
      if (res.ok) setTwoFAStatus(await res.json());
    } catch {}
  };

  const setup2FA = async () => {
    try {
      const res = await authFetch(`${API}/api/users/2fa/setup`, { method: "POST" });
      if (res.ok) setTwoFASetup(await res.json());
      else { const d = await res.json(); notify(d.detail || "2FA kurulamadı", "err"); }
    } catch { notify("Sunucu hatası", "err"); }
  };

  const verify2FA = async () => {
    try {
      const res = await authFetch(`${API}/api/users/2fa/verify`, {
        method: "POST",
        body: JSON.stringify({ code: twoFACode }),
      });
      if (res.ok) {
        notify("2FA aktifleştirildi ✓");
        setTwoFASetup(null);
        setTwoFACode("");
        fetch2FAStatus();
      } else {
        const d = await res.json();
        notify(d.detail || "Kod hatalı", "err");
      }
    } catch { notify("Sunucu hatası", "err"); }
  };

  const disable2FA = async () => {
    const pw = prompt("2FA'yı kapatmak için şifrenizi girin:");
    if (!pw) return;
    try {
      const res = await authFetch(`${API}/api/users/2fa/disable`, {
        method: "POST",
        body: JSON.stringify({ password: pw }),
      });
      if (res.ok) { notify("2FA kapatıldı"); fetch2FAStatus(); }
      else { const d = await res.json(); notify(d.detail || "Hata", "err"); }
    } catch { notify("Sunucu hatası", "err"); }
  };

  const fetchTenantList = async () => {
    try {
      const res = await authFetch(`${API}/api/tenants`);
      if (res.ok) setTenantList(await res.json());
    } catch {}
  };

  const createTenant = async () => {
    if (!newTenantForm.name) { notify("Müşteri adı zorunlu", "err"); return; }
    try {
      const res = await authFetch(`${API}/api/tenants`, {
        method: "POST",
        body: JSON.stringify(newTenantForm),
      });
      if (res.ok) {
        const d = await res.json();
        notify(`${d.name} oluşturuldu — Agent Key: ${d.agent_key}`);
        setNewTenantForm({ name: "", contact_email: "", max_agents: 10, plan: "starter" });
        fetchTenantList();
      } else {
        const d = await res.json();
        notify(d.detail || "Oluşturulamadı", "err");
      }
    } catch { notify("Sunucu hatası", "err"); }
  };

  const deleteTenant = async (id: string, name: string) => {
    if (!confirm(`"${name}" ve TÜM VERİLERİ silinecek. Emin misiniz?`)) return;
    try {
      const res = await authFetch(`${API}/api/tenants/${id}`, { method: "DELETE" });
      if (res.ok) { notify(`${name} silindi`); fetchTenantList(); }
      else notify("Silinemedi", "err");
    } catch { notify("Sunucu hatası", "err"); }
  };

  const fetchUserList = async () => {
    try {
      const res = await authFetch(`${API}/api/users`);
      if (res.ok) setUserList(await res.json());
      else notify("Kullanıcı listesi alınamadı", "err");
    } catch { notify("Sunucu hatası", "err"); }
  };

  const changePassword = async () => {
    if (pwForm.next !== pwForm.confirm) { notify("Şifreler eşleşmiyor", "err"); return; }
    if (pwForm.next.length < 8) { notify("En az 8 karakter gerekli", "err"); return; }
    try {
      const res = await authFetch(`${API}/api/users/change-password`, {
        method: "POST",
        body: JSON.stringify({ current_password: pwForm.current, new_password: pwForm.next }),
      });
      if (res.ok) {
        notify("Şifre başarıyla değiştirildi");
        setShowPasswordChange(false);
        setPwForm({ current: "", next: "", confirm: "" });
      } else {
        const d = await res.json();
        notify(d.detail || "Şifre değiştirilemedi", "err");
      }
    } catch { notify("Sunucu hatası", "err"); }
  };

  const createUser = async () => {
    if (!newUserForm.username || !newUserForm.password) { notify("Kullanıcı adı ve şifre zorunlu", "err"); return; }
    try {
      const res = await authFetch(`${API}/api/users`, {
        method: "POST",
        body: JSON.stringify(newUserForm),
      });
      if (res.ok) {
        notify(`${newUserForm.username} oluşturuldu`);
        setNewUserForm({ username: "", password: "", role: "analyst", email: "" });
        fetchUserList();
      } else {
        const d = await res.json();
        notify(d.detail || "Kullanıcı oluşturulamadı", "err");
      }
    } catch { notify("Sunucu hatası", "err"); }
  };

  const deleteUser = async (username: string) => {
    if (!confirm(`"${username}" silinsin mi?`)) return;
    try {
      const res = await authFetch(`${API}/api/users/${username}`, { method: "DELETE" });
      if (res.ok) { notify(`${username} silindi`); fetchUserList(); }
      else notify("Silinemedi", "err");
    } catch { notify("Sunucu hatası", "err"); }
  };

  const fetchProcessList = async (hostname: string) => {
    setProcessLoading(true);
    setProcessList([]);
    try {
      const res = await authFetch(`${API}/api/v1/processes/${encodeURIComponent(hostname)}`);
      if (res.ok) {
        const data = await res.json();
        setProcessList(data.processes || []);
      } else notify("Süreç listesi alınamadı", "err");
    } catch { notify("Sunucu hatası", "err"); }
    setProcessLoading(false);
  };

  const doHunt = async () => {
    if (!huntQuery.trim()) return;
    setHuntLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/hunt`, {
        method: "POST", headers: headers(),
        body: JSON.stringify({ query: huntQuery, limit: 50 })
      });
      if (res.ok) setHuntResults(await res.json());
      else notify("Sorgu başarısız", "err");
    } catch { notify("Sunucu hatası", "err"); }
    setHuntLoading(false);
  };

  const updateSigmaRules = async () => {
    setLoadingAction("SIGMA_UPDATE");
    try {
      const res = await fetch(`${API}/api/v1/sigma/update`, { method: "POST", headers: headers() });
      if (res.ok) {
        const d = await res.json();
        setSigmaStats((p: any) => ({ ...p, total: d.total }));
        notify(`${d.downloaded} yeni kural indirildi`);
      }
    } catch { notify("Güncelleme başarısız", "err"); }
    setLoadingAction(null);
  };

  const addRule = async () => {
    if (!newRule.name || !newRule.keyword) { notify("Kural adı ve kelime zorunlu!", "err"); return; }
    try {
      const res = await fetch(`${API}/api/rules`, { method: "POST", headers: headers(), body: JSON.stringify(newRule) });
      if (res.ok) {
        setShowRuleModal(false);
        setNewRule({ name: "", keyword: "", risk_score: 50, severity: "WARNING" });
        notify("Kural eklendi");
      } else { notify("Kural eklenemedi", "err"); }
    } catch { notify("Sunucu hatası", "err"); }
  };

  // ─── LOGIN SCREEN ─────────────────────────────────────────────────────────

  if (!token) {
    return (
      <div className="min-h-screen bg-[#030303] flex items-center justify-center font-mono relative overflow-hidden">
        {/* Scan lines */}
        <div className="absolute inset-0 pointer-events-none"
          style={{ backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.012) 2px, rgba(255,255,255,0.012) 4px)' }} />
        {/* Glow */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_30%,rgba(239,68,68,0.12),transparent_65%)] pointer-events-none" />

        <div className="w-full max-w-sm relative z-10">
          {/* Logo */}
          <div className="text-center mb-10">
            <div className="inline-flex items-center justify-center w-14 h-14 bg-red-500/10 border border-red-500/20 rounded-2xl mb-5 relative">
              <ShieldCheck size={26} className="text-red-400" />
              <span className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-pulse" />
            </div>
            <h1 className="text-3xl font-black tracking-[-0.05em] text-white">SOLIDTRACE</h1>
            <p className="text-[10px] tracking-[0.35em] text-red-500/70 uppercase mt-1 font-bold">SOC Platform v6.1</p>
          </div>

          <div className="bg-white/3 border border-white/7 rounded-2xl p-7 backdrop-blur-xl">
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="text-[9px] font-black text-red-400/70 uppercase tracking-[0.2em] block mb-1.5">Kullanıcı Adı</label>
                <input
                  type="text"
                  value={loginForm.username}
                  onChange={e => setLoginForm({ ...loginForm, username: e.target.value })}
                  className="w-full bg-black/60 border border-white/8 rounded-xl px-4 py-3 text-sm text-white font-mono placeholder:text-white/15 focus:border-red-500/40 focus:outline-none transition-colors"
                  placeholder="admin"
                  required
                />
              </div>
              <div>
                <label className="text-[9px] font-black text-red-400/70 uppercase tracking-[0.2em] block mb-1.5">Şifre</label>
                <input
                  type="password"
                  value={loginForm.password}
                  onChange={e => setLoginForm({ ...loginForm, password: e.target.value })}
                  className="w-full bg-black/60 border border-white/8 rounded-xl px-4 py-3 text-sm text-white font-mono placeholder:text-white/15 focus:border-red-500/40 focus:outline-none transition-colors"
                  placeholder="••••••••"
                  required
                />
              </div>
              {loginError && (
                <div className="text-red-400 text-xs bg-red-500/8 border border-red-500/15 rounded-xl py-2.5 px-4 text-center">
                  {loginError}
                </div>
              )}
              <button
                type="submit"
                className="w-full py-3.5 bg-red-600 hover:bg-red-500 active:scale-[0.98] text-white rounded-xl font-black text-[11px] uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-2 mt-2"
              >
                <LogIn size={14} /> GİRİŞ YAP
              </button>
            </form>
            <p className="text-center text-[9px] text-white/20 mt-5">
              Varsayılan: <span className="text-white/40">admin</span> / <span className="text-white/40">admin123</span>
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ─── DASHBOARD ────────────────────────────────────────────────────────────

  const navItems: { id: NavTab; label: string; icon: React.ReactNode; badge?: number }[] = [
    { id: 'alerts',      label: 'Olaylar',       icon: <Activity size={15} />,    badge: alerts.filter(a => a.severity === 'CRITICAL').length },
    { id: 'correlation', label: 'Korelasyon',    icon: <Layers size={15} />,      badge: correlationAlerts.length },
    { id: 'sigma',       label: 'Sigma',         icon: <BookOpen size={15} />,    badge: sigmaAlerts.length },
    { id: 'hunting',     label: 'Hunt',          icon: <Crosshair size={15} /> },
    { id: 'ueba',        label: 'UEBA',          icon: <Users size={15} />,       badge: uebaAnomalies.length },
    { id: 'assets',      label: 'Asset',         icon: <Package size={15} /> },
  ];

  return (
    <div className="min-h-screen bg-[#030303] text-white font-mono flex flex-col overflow-hidden select-none">

      <style jsx global>{`
        * { scrollbar-width: none !important; -ms-overflow-style: none !important; }
        ::-webkit-scrollbar { display: none !important; }
        .scan-lines {
          background-image: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.01) 2px, rgba(255,255,255,0.01) 4px);
          pointer-events: none;
        }
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .fade-in { animation: fadeSlideIn 0.2s ease; }
      `}</style>

      {/* Scan lines overlay */}
      <div className="fixed inset-0 scan-lines pointer-events-none z-0" />
      {/* Top glow */}
      <div className="fixed top-0 left-0 right-0 h-px bg-linear-to-r from-transparent via-red-500/40 to-transparent z-50" />

      {/* ── TOPBAR ── */}
      <header className="h-12 border-b border-white/6 bg-black/70 backdrop-blur-2xl flex items-center justify-between px-5 shrink-0 z-40 relative">
        <div className="flex items-center gap-5">
          <div className="flex items-center gap-2">
            <Radio size={14} className="text-red-500 animate-pulse" />
            <span className="text-[11px] font-black tracking-[0.25em] text-white">SOLIDTRACE</span>
            <span className="text-[9px] text-white/20 tracking-widest">SOC</span>
          </div>

          {/* NAV */}
          <nav className="flex items-center gap-1">
            {navItems.map(item => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all ${
                  activeTab === item.id
                    ? 'bg-white/7 text-white'
                    : 'text-white/30 hover:text-white/60 hover:bg-white/3'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
                {item.badge ? (
                  <span className={`ml-0.5 px-1.5 py-0.5 rounded-full text-[8px] font-black ${
                    item.badge > 0 ? 'bg-red-500/20 text-red-400' : 'bg-white/10 text-white/40'
                  }`}>{item.badge}</span>
                ) : null}
                {activeTab === item.id && (
                  <span className="absolute bottom-0 left-1/2 -translate-x-1/2 w-4 h-0.5 bg-red-500 rounded-full" />
                )}
              </button>
            ))}
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => { setShowPasswordChange(true); }}
            className="text-white/30 hover:text-white/60 transition p-1"
            title="Şifre Değiştir"
          >
            <Lock size={14}/>
          </button>
          <button
            onClick={() => { setShow2FA(true); fetch2FAStatus(); }}
            className="text-white/30 hover:text-white/60 transition p-1"
            title="İki Faktörlü Doğrulama (2FA)"
          >
            <ShieldCheck size={14}/>
          </button>
          <button
            onClick={() => { setShowTenantMgmt(true); fetchTenantList(); }}
            className="text-white/30 hover:text-white/60 transition p-1"
            title="Müşteri Yönetimi"
          >
            <Database size={14}/>
          </button>
          <button
            onClick={() => { setShowUserMgmt(true); fetchUserList(); }}
            className="text-white/30 hover:text-white/60 transition p-1"
            title="Kullanıcı Yönetimi"
          >
            <Users size={14}/>
          </button>
          <button onClick={fetchAll} className="text-white/30 hover:text-white/60 transition p-1">
            <RefreshCw size={13} />
          </button>
          <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-[9px] font-black border transition-all ${
            wsConnected
              ? 'border-emerald-500/25 bg-emerald-500/8 text-emerald-400'
              : 'border-red-500/25 bg-red-500/8 text-red-400 animate-pulse'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-emerald-400' : 'bg-red-500'}`} />
            {wsConnected ? 'LIVE' : 'OFFLINE'}
          </div>
          <button
            onClick={() => { setToken(null); tokenRef.current = null; localStorage.removeItem('soc_token'); }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/6 text-white/30 hover:text-white/60 text-[10px] font-bold transition-all"
          >
            <Lock size={11} /> Çıkış
          </button>
        </div>
      </header>

      {/* ── STATS BAR ── */}
      <div className="border-b border-white/5 bg-black/40 px-5 py-2 flex items-center gap-6 shrink-0 z-30">
        {[
          { label: 'KRİTİK', val: stats.critical,     color: 'text-red-400',     icon: <ShieldAlert size={12}/> },
          { label: 'TOPLAM', val: stats.total,         color: 'text-white/60',    icon: <Activity size={12}/> },
          { label: 'AJAN',   val: stats.activeHosts,   color: 'text-sky-400',     icon: <Server size={12}/> },
          { label: '24S',    val: stats.last_24h,      color: 'text-orange-400',  icon: <Clock size={12}/> },
          { label: 'SIGMA',  val: sigmaStats.total,    color: 'text-purple-400',  icon: <BookOpen size={12}/> },
          { label: 'UEBA',   val: userProfiles.length, color: 'text-amber-400',   icon: <Users size={12}/> },
          { label: 'ASSET',  val: assets.length,       color: 'text-emerald-400', icon: <Package size={12}/> },
        ].map(s => (
          <div key={s.label} className="flex items-center gap-2">
            <span className={`${s.color} opacity-50`}>{s.icon}</span>
            <div>
              <p className="text-[8px] text-white/25 uppercase tracking-[0.2em]">{s.label}</p>
              <p className={`text-sm font-black leading-none ${s.color}`}>{s.val}</p>
            </div>
          </div>
        ))}

        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => setShowRuleModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white/4 hover:bg-white/7 border border-white/6 rounded-lg text-[9px] font-black text-white/50 hover:text-white/80 uppercase tracking-widest transition-all"
          >
            <Plus size={11} /> Kural
          </button>
          <button
            onClick={() => { if (confirm("Loglar silinecek!")) sendCommand("CLEAR_LOGS", null); }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/5 hover:bg-red-500/10 border border-red-500/15 rounded-lg text-[9px] font-black text-red-500/60 hover:text-red-400 uppercase tracking-widest transition-all"
          >
            <Trash2 size={11} /> Temizle
          </button>
        </div>
      </div>

      {/* ── MAIN ── */}
      <main className="flex-1 overflow-hidden relative z-10">

        {/* ════ TAB: ALERTS ════ */}
        {activeTab === 'alerts' && (
          <div className="h-full flex flex-col">
            {/* Charts */}
            {showCharts && (
              <div className="grid grid-cols-3 gap-3 p-4 pb-0 shrink-0 fade-in">
                <div className="col-span-2 bg-white/2 border border-white/5 rounded-xl p-4">
                  <p className="text-[9px] text-white/30 uppercase tracking-[0.2em] mb-3 flex items-center gap-2"><TrendingUp size={11}/> Saatlik Aktivite</p>
                  <ResponsiveContainer width="100%" height={80}>
                    <AreaChart data={analyticsData.activity_trend}>
                      <defs>
                        <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <Area type="monotone" dataKey="count" stroke="#ef4444" strokeWidth={1.5} fill="url(#ag)" dot={false}/>
                      <Tooltip contentStyle={{ background: '#0a0a0a', border: '1px solid #222', fontSize: 10 }} />
                      <XAxis dataKey="time" hide />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
                <div className="bg-white/2 border border-white/5 rounded-xl p-4">
                  <p className="text-[9px] text-white/30 uppercase tracking-[0.2em] mb-3 flex items-center gap-2"><BarChart3 size={11}/> Dağılım</p>
                  <ResponsiveContainer width="100%" height={80}>
                    <BarChart data={analyticsData.severity_distribution} layout="vertical" margin={{left:-10}}>
                      <XAxis type="number" hide />
                      <YAxis dataKey="name" type="category" width={55} tick={{fontSize:8, fill:'#555'}} />
                      <Tooltip contentStyle={{ background: '#0a0a0a', border: '1px solid #222', fontSize: 10 }} />
                      <Bar dataKey="value" barSize={8} radius={[0,3,3,0]}>
                        {analyticsData.severity_distribution.map((e: any, i: number) => (
                          <Cell key={i} fill={e.name==='CRITICAL'?'#ef4444':e.name==='HIGH'?'#f97316':'#3b82f6'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Search bar */}
            <div className="p-4 pb-2 shrink-0 flex items-center gap-3">
              <div className="relative flex-1 max-w-sm">
                <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
                <input
                  type="text"
                  placeholder="Ara: kural, host, detay, PID..."
                  value={searchTerm}
                  onChange={e => setSearchTerm(e.target.value)}
                  className="w-full bg-white/3 border border-white/6 rounded-lg pl-8 pr-3 py-2 text-[11px] text-white/70 placeholder:text-white/20 focus:border-white/15 focus:outline-none transition-colors"
                />
                {searchTerm && (
                  <button onClick={() => setSearchTerm("")} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-white/20 hover:text-white/50 transition">
                    <X size={11} />
                  </button>
                )}
              </div>
              {searchTerm && (
                <span className="text-[10px] text-white/30">{filteredAlerts.length}/{alerts.length}</span>
              )}
              <div className="flex gap-2 ml-auto">
                <FilterBtn label="KRİTİK" active={searchTerm==='critical'} onClick={() => setSearchTerm(searchTerm==='critical'?'':'critical')} color="red" />
                <FilterBtn label="GRAFİK" active={showCharts} onClick={() => setShowCharts(!showCharts)} />
              </div>
            </div>

            {/* Table */}
            <div className="flex-1 overflow-auto px-4 pb-4">
              <table className="w-full text-left border-collapse table-fixed">
                <thead>
                  <tr className="text-[9px] text-white/25 uppercase tracking-[0.15em] border-b border-white/5">
                    <th className="py-2 px-3 w-8"></th>
                    <th className="py-2 px-3 w-28">Zaman</th>
                    <th className="py-2 px-3 w-20">Şiddet</th>
                    <th className="py-2 px-3 w-48">Kural</th>
                    <th className="py-2 px-3 w-28">Endpoint</th>
                    <th className="py-2 px-3">Detay</th>
                    <th className="py-2 px-3 w-16 text-right">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAlerts.length === 0 ? (
                    <tr><td colSpan={7} className="py-16 text-center text-white/20 text-sm">
                      <AlertTriangle size={24} className="mx-auto mb-2 opacity-30" />
                      {searchTerm ? `"${searchTerm}" için sonuç yok` : "Henüz log yok"}
                    </td></tr>
                  ) : filteredAlerts.map(a => (
                    <tr
                      key={a.id}
                      onClick={() => { setSelectedLog(a); setAiResult(null); }}
                      className={`group border-b border-white/3 hover:bg-white/2.5 cursor-pointer transition-colors ${a.severity==='CRITICAL'?'bg-red-500/2.5':''}`}
                    >
                      <td className="py-2.5 px-3">
                        <div className={`w-1.5 h-1.5 rounded-full ${sevDot(a.severity)} ${a.severity==='CRITICAL'?'animate-pulse':''}`} />
                      </td>
                      <td className="py-2.5 px-3 text-[10px] text-white/30 font-mono">{fmt(a.created_at)}</td>
                      <td className="py-2.5 px-3">
                        <span className={`text-[9px] font-black px-2 py-0.5 rounded border ${sevColor(a.severity)}`}>{a.severity}</span>
                      </td>
                      <td className="py-2.5 px-3 text-[11px] text-white/80 font-bold truncate">{a.rule}</td>
                      <td className="py-2.5 px-3 text-[10px] text-white/40 font-mono truncate">{a.hostname}</td>
                      <td className="py-2.5 px-3 text-[10px] text-white/50 font-mono truncate">{sanitize(a.details)}</td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <div className="w-12 h-1 bg-white/10 rounded-full overflow-hidden">
                            <div className={`h-full ${riskBar(a.risk_score)} rounded-full`} style={{ width: `${a.risk_score}%` }} />
                          </div>
                          <span className="text-[9px] text-white/30 w-6 text-right">{a.risk_score}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ════ TAB: CORRELATION ════ */}
        {activeTab === 'correlation' && (
          <div className="h-full overflow-auto p-4">
            <TabHeader title="Korelasyon Alarmları" subtitle="Zaman pencereli çok-olay tespiti" icon={<Layers size={16}/>} count={correlationAlerts.length} />
            <div className="space-y-2 mt-4">
              {correlationAlerts.length === 0 ? (
                <EmptyState msg="Henüz korelasyon alarmı yok — normal aktivite" />
              ) : correlationAlerts.map((a, i) => (
                <CorrCard key={i} alert={a} onClick={() => setSelectedCorr(a)} />
              ))}
            </div>
          </div>
        )}

        {/* ════ TAB: SIGMA ════ */}
        {activeTab === 'sigma' && (
          <div className="h-full overflow-auto p-4">
            <div className="flex items-center justify-between mb-4">
              <TabHeader title="Sigma Kural Motoru" subtitle={`${sigmaStats.total} kural aktif`} icon={<BookOpen size={16}/>} count={sigmaAlerts.length} />
              <button
                onClick={updateSigmaRules}
                disabled={loadingAction === 'SIGMA_UPDATE'}
                className="flex items-center gap-2 px-4 py-2 bg-purple-500/10 border border-purple-500/20 text-purple-400 rounded-lg text-[10px] font-black uppercase tracking-widest hover:bg-purple-500/15 transition-all disabled:opacity-40"
              >
                {loadingAction === 'SIGMA_UPDATE' ? <Loader2 size={12} className="animate-spin"/> : <RefreshCw size={12}/>}
                GitHub'dan Güncelle
              </button>
            </div>

            {/* Sigma stats */}
            <div className="grid grid-cols-4 gap-3 mb-4">
              {[
                { label: 'Toplam Kural', val: sigmaStats.total, color: 'text-purple-400' },
                { label: 'Critical', val: sigmaStats.by_severity?.CRITICAL || 0, color: 'text-red-400' },
                { label: 'High', val: sigmaStats.by_severity?.HIGH || 0, color: 'text-orange-400' },
                { label: 'Eşleşme', val: sigmaAlerts.length, color: 'text-white' },
              ].map(s => (
                <div key={s.label} className="bg-white/2 border border-white/5 rounded-xl p-4">
                  <p className="text-[9px] text-white/30 uppercase tracking-[0.15em] mb-1">{s.label}</p>
                  <p className={`text-2xl font-black ${s.color}`}>{s.val}</p>
                </div>
              ))}
            </div>

            <div className="space-y-2">
              {sigmaAlerts.length === 0 ? (
                <EmptyState msg="Sigma kural eşleşmesi bekleniyor..." />
              ) : sigmaAlerts.map((a, i) => (
                <CorrCard key={i} alert={a} onClick={() => setSelectedCorr(a)} badge="SIGMA" />
              ))}
            </div>
          </div>
        )}

        {/* ════ TAB: THREAT HUNTING ════ */}
        {activeTab === 'hunting' && (
          <div className="h-full overflow-auto p-4">
            <TabHeader title="Threat Hunting" subtitle="Proaktif tehdit arama — alan:değer sorgu dili" icon={<Crosshair size={16}/>} />

            {/* Query input */}
            <div className="mt-4 bg-white/2 border border-white/5 rounded-xl p-4">
              <p className="text-[9px] text-white/30 uppercase tracking-[0.2em] mb-3">Sorgu</p>
              <div className="flex gap-3">
                <div className="relative flex-1">
                  <Terminal size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
                  <input
                    type="text"
                    value={huntQuery}
                    onChange={e => setHuntQuery(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && doHunt()}
                    placeholder='type:PROCESS_CREATED AND details:*powershell* AND details:*base64*'
                    className="w-full bg-black/60 border border-white/8 rounded-lg pl-8 pr-4 py-3 text-[11px] text-white/80 font-mono placeholder:text-white/15 focus:border-white/20 focus:outline-none"
                  />
                </div>
                <button
                  onClick={doHunt}
                  disabled={huntLoading}
                  className="px-5 py-3 bg-red-600 hover:bg-red-500 active:scale-[0.98] text-white rounded-lg font-black text-[10px] uppercase tracking-widest flex items-center gap-2 transition-all disabled:opacity-40"
                >
                  {huntLoading ? <Loader2 size={13} className="animate-spin"/> : <Crosshair size={13}/>}
                  Ara
                </button>
              </div>

              {/* Preset queries */}
              <div className="mt-3 flex flex-wrap gap-2">
                {[
                  'type:PROCESS_CREATED AND details:*base64*',
                  'details:*mimikatz*',
                  'severity:CRITICAL',
                  'type:SCHTASK_CREATED',
                  'details:*psexec*',
                  'type:LOG_CLEARED',
                ].map(q => (
                  <button
                    key={q}
                    onClick={() => setHuntQuery(q)}
                    className="px-2.5 py-1 bg-white/3 hover:bg-white/6 border border-white/6 rounded-lg text-[9px] text-white/40 hover:text-white/70 font-mono transition-all"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>

            {/* Results */}
            {huntResults && (
              <div className="mt-4 fade-in">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-[10px] text-white/40">
                    <span className="text-white font-bold">{huntResults.total}</span> sonuç bulundu —
                    <span className="text-white/30 font-mono ml-1">{huntResults.took_ms}ms</span>
                  </p>
                </div>
                <div className="space-y-1.5">
                  {huntResults.results.map((r: any, i: number) => (
                    <div key={i} className="bg-white/2 border border-white/4 rounded-xl p-3 hover:bg-white/3.5 transition-colors">
                      <div className="flex items-center gap-3 mb-1">
                        <span className={`text-[9px] font-black px-2 py-0.5 rounded border ${sevColor(r.severity)}`}>{r.severity}</span>
                        <span className="text-[11px] text-white/70 font-bold">{r.rule || r.type}</span>
                        <span className="ml-auto text-[9px] text-white/25 font-mono">{r.hostname}</span>
                        <span className="text-[9px] text-white/20 font-mono">{fmt(r.created_at)}</span>
                      </div>
                      <p className="text-[10px] text-white/35 font-mono truncate">{r.details}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ════ TAB: UEBA ════ */}
        {activeTab === 'ueba' && (
          <div className="h-full overflow-auto p-4">
            <TabHeader title="UEBA — Davranış Analizi" subtitle="Kullanıcı baseline öğrenmesi ve anomali tespiti" icon={<Users size={16}/>} count={uebaAnomalies.length} />

            <div className="grid grid-cols-2 gap-4 mt-4">
              {/* Anomaliler */}
              <div>
                <p className="text-[9px] text-white/30 uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                  <AlertTriangle size={11}/> Son Anomaliler
                </p>
                <div className="space-y-2">
                  {uebaAnomalies.length === 0 ? (
                    <EmptyState msg="UEBA öğreniyor... Anomali tespit edilmedi" small />
                  ) : uebaAnomalies.map((a, i) => (
                    <div key={i} className="bg-white/2 border border-white/5 rounded-xl p-4 fade-in">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-black text-orange-400">{a.anomaly.replace('_', ' ')}</span>
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1 bg-white/10 rounded-full overflow-hidden">
                            <div className={`h-full ${riskBar(a.score)} rounded-full`} style={{ width: `${a.score}%` }} />
                          </div>
                          <span className="text-[10px] font-black text-white/60">{a.score}</span>
                        </div>
                      </div>
                      <p className="text-[10px] text-white/50 mb-1">{a.description}</p>
                      <div className="flex items-center gap-3 text-[9px] text-white/25">
                        <span className="font-mono text-sky-400/60">{a.username}</span>
                        <span>@</span>
                        <span className="font-mono">{a.hostname}</span>
                        <span className="ml-auto">{relativeTime(a.timestamp)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Profiller */}
              <div>
                <p className="text-[9px] text-white/30 uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                  <Users size={11}/> Kullanıcı Profilleri
                </p>
                <div className="space-y-2">
                  {userProfiles.length === 0 ? (
                    <EmptyState msg="Profil yükleniyor..." small />
                  ) : userProfiles.map((p, i) => (
                    <div key={i} className="bg-white/2 border border-white/5 rounded-xl p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <div className="w-7 h-7 rounded-lg bg-white/5 flex items-center justify-center text-[11px] font-black text-white/50">
                            {p.username[0]?.toUpperCase()}
                          </div>
                          <div>
                            <p className="text-[11px] font-bold text-white/80">{p.username}</p>
                            <p className="text-[9px] text-white/25">{p.observation_days}g gözlem {p.is_mature ? '✓' : '(öğreniyor)'}</p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-[9px] text-white/25">Ort. Risk</p>
                          <p className={`text-sm font-black ${p.avg_risk_score > 60 ? 'text-red-400' : p.avg_risk_score > 30 ? 'text-orange-400' : 'text-emerald-400'}`}>
                            {p.avg_risk_score}
                          </p>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[9px]">
                        <div className="bg-white/2.5 rounded-lg p-2">
                          <p className="text-white/25 mb-1">Çalışma Saati</p>
                          <p className="text-white/60 font-mono">{p.typical_hours}</p>
                        </div>
                        <div className="bg-white/2.5 rounded-lg p-2">
                          <p className="text-white/25 mb-1">Bilinen Makine</p>
                          <p className="text-white/60 font-mono">{p.known_hosts.length} host</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ════ TAB: ASSETS ════ */}
        {activeTab === 'assets' && (
          <div className="h-full overflow-auto p-4">
            <TabHeader title="Asset Envanteri" subtitle="Kayıtlı agent'lar ve online durumu" icon={<Package size={16}/>} count={assets.length} />
            <div className="mt-4 grid grid-cols-3 gap-3">
              {assets.length === 0 ? (
                <div className="col-span-3"><EmptyState msg="Henüz kayıtlı asset yok — agent'ları başlat" /></div>
              ) : assets.map((a, i) => (
                <div key={i} className={`bg-white/2 border rounded-xl p-4 transition-all hover:bg-white/3.5 ${a.is_online ? 'border-emerald-500/15' : 'border-white/5'}`}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${a.is_online ? 'bg-emerald-400 shadow-[0_0_6px_#34d399]' : 'bg-white/20'}`} />
                      <span className="text-[10px] font-bold text-white/80">{a.hostname}</span>
                    </div>
                    <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${a.is_online ? 'text-emerald-400 bg-emerald-500/10' : 'text-white/25 bg-white/5'}`}>
                      {a.is_online ? 'ONLINE' : 'OFFLINE'}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[9px]">
                    <div>
                      <p className="text-white/25">Son Görülme</p>
                      <p className="text-white/50 font-mono">{relativeTime(a.last_seen)}</p>
                    </div>
                    <div>
                      <p className="text-white/25">Max Risk</p>
                      <p className={`font-black ${a.max_risk > 70 ? 'text-red-400' : a.max_risk > 40 ? 'text-orange-400' : 'text-emerald-400'}`}>
                        {a.max_risk}
                      </p>
                    </div>
                    <div>
                      <p className="text-white/25">Alert Sayısı</p>
                      <p className="text-white/50">{a.alert_count}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* ── ALERT DETAIL MODAL ── */}
      {selectedLog && (
        <Modal onClose={() => setSelectedLog(null)}>
          <div className="p-6 border-b border-white/6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${selectedLog.severity==='CRITICAL' ? 'bg-red-500/15 text-red-400' : 'bg-white/5 text-white/50'}`}>
                <Bot size={18}/>
              </div>
              <div>
                <h2 className="text-sm font-black text-white">{selectedLog.rule}</h2>
                <p className="text-[9px] text-white/25 font-mono mt-0.5">{selectedLog.id.slice(0,20)}...</p>
              </div>
            </div>
            <button onClick={() => setSelectedLog(null)} className="text-white/25 hover:text-white/60 transition"><X size={16}/></button>
          </div>

          <div className="p-6 space-y-4 overflow-y-auto max-h-[60vh]">
            {/* Meta grid */}
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: 'Endpoint', val: selectedLog.hostname },
                { label: 'Kullanıcı', val: selectedLog.username || '—' },
                { label: 'PID', val: String(selectedLog.pid || 0) },
                { label: 'Risk', val: `${selectedLog.risk_score}/100`, bold: true, color: selectedLog.risk_score > 70 ? 'text-red-400' : 'text-emerald-400' },
              ].map(m => (
                <div key={m.label} className="bg-white/3 border border-white/5 rounded-xl p-3">
                  <p className="text-[8px] text-white/25 uppercase tracking-[0.15em] mb-1">{m.label}</p>
                  <p className={`text-[11px] font-mono truncate ${m.color || 'text-white/70'} ${m.bold ? 'font-black' : ''}`}>{m.val}</p>
                </div>
              ))}
            </div>

            {/* Severity + time */}
            <div className="flex items-center gap-3">
              <span className={`text-[9px] font-black px-3 py-1.5 rounded-lg border ${sevColor(selectedLog.severity)}`}>{selectedLog.severity}</span>
              <span className="text-[10px] text-white/30 font-mono">{fmt(selectedLog.created_at)}</span>
              <div className="ml-auto flex items-center gap-2">
                <div className="w-24 h-1.5 bg-white/10 rounded-full overflow-hidden">
                  <div className={`h-full ${riskBar(selectedLog.risk_score)} rounded-full`} style={{ width: `${selectedLog.risk_score}%` }} />
                </div>
              </div>
            </div>

            {/* Details */}
            <div className="bg-black/40 border border-white/6 rounded-xl p-4">
              <p className="text-[8px] text-white/25 uppercase tracking-[0.15em] mb-2">Detaylar</p>
              <code className="text-[10px] text-white/60 font-mono break-all leading-relaxed">{sanitize(selectedLog.details)}</code>
            </div>

            {/* Command line */}
            {selectedLog.command_line && (
              <div className="bg-black/40 border border-purple-500/15 rounded-xl p-4">
                <p className="text-[8px] text-purple-400/60 uppercase tracking-[0.15em] mb-2">Komut Satırı</p>
                <code className="text-[10px] text-purple-300/60 font-mono break-all leading-relaxed">{sanitize(selectedLog.command_line || '')}</code>
              </div>
            )}

            {/* Hardware ID */}
            <div className="flex items-center gap-3 bg-white/2 border border-white/4 rounded-xl p-3">
              <HardDrive size={12} className="text-white/20 shrink-0"/>
              <span className="text-[9px] text-white/25 uppercase tracking-[0.15em]">HW ID</span>
              <code className="text-[10px] text-sky-400/60 font-mono flex-1 truncate">{selectedLog.serial || 'SYS_INTERNAL'}</code>
              <button onClick={() => { navigator.clipboard.writeText(selectedLog.serial||''); notify("Kopyalandı"); }} className="text-white/20 hover:text-white/50 transition shrink-0">
                <Copy size={11}/>
              </button>
            </div>

            {/* AI Result */}
            {aiResult && (
              <div className="bg-sky-500/5 border border-sky-500/15 rounded-xl p-4 fade-in">
                <div className="flex items-center gap-2 mb-3">
                  <Zap size={13} className="text-sky-400"/>
                  <span className="text-[9px] text-sky-400 font-black uppercase tracking-[0.2em]">AI Analiz Raporu</span>
                </div>
                <pre className="text-[10px] text-white/60 font-mono whitespace-pre-wrap leading-relaxed">{aiResult}</pre>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="p-5 border-t border-white/5 bg-black/30 space-y-3">
            {/* Row 1: AI + Isolation */}
            <div className="flex flex-wrap gap-2">
              <ActionBtn label="AI Analiz" icon={<Bot size={14}/>} loading={loadingAction==='AI_ANALYZE'} onClick={() => sendCommand("AI_ANALYZE", selectedLog)} primary />
              <ActionBtn label="İzole Et" icon={<WifiOff size={14}/>} loading={loadingAction==='ISOLATE'} onClick={() => sendCommand("ISOLATE", selectedLog)} warn />
              <ActionBtn label="İzolasyon Kaldır" icon={<Wifi size={14}/>} loading={loadingAction==='UNISOLATE'} onClick={() => sendCommand("UNISOLATE", selectedLog)} />
            </div>
            {/* Row 2: USB + Process */}
            <div className="flex flex-wrap gap-2">
              <ActionBtn label="USB Devre Dışı" icon={<Usb size={14}/>} loading={loadingAction==='USB_DISABLE'} onClick={() => sendCommand("USB_DISABLE", selectedLog)} danger />
              <ActionBtn label="USB Aktif Et" icon={<Usb size={14}/>} loading={loadingAction==='USB_ENABLE'} onClick={() => sendCommand("USB_ENABLE", selectedLog)} />
              <ActionBtn label="Süreçleri Görüntüle" icon={<Cpu size={14}/>} loading={processLoading} onClick={() => { setShowProcessModal(true); fetchProcessList(selectedLog!.hostname); }} />
              {selectedLog.pid !== 0 && (
                <ActionBtn label={`PID ${selectedLog.pid} Sonlandır`} icon={<XOctagon size={14}/>} loading={loadingAction==='KILL'} onClick={() => sendCommand("KILL", selectedLog)} danger />
              )}
            </div>
          </div>
        </Modal>
      )}

      {/* ── CORRELATION DETAIL MODAL ── */}
      {selectedCorr && (
        <Modal onClose={() => setSelectedCorr(null)}>
          <div className="p-6 border-b border-white/6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`px-2 py-1 rounded text-[8px] font-black border ${
                (selectedCorr as any).sigma_id
                  ? 'bg-purple-500/10 border-purple-500/20 text-purple-400'
                  : 'bg-orange-500/10 border-orange-500/20 text-orange-400'
              }`}>
                {(selectedCorr as any).sigma_id ? 'SIGMA' : 'KORELASYON'}
              </div>
              <div>
                <h2 className="text-sm font-black text-white">{selectedCorr.description || selectedCorr.rule}</h2>
                <p className="text-[9px] text-white/25 font-mono mt-0.5">{selectedCorr.rule}</p>
              </div>
            </div>
            <button onClick={() => setSelectedCorr(null)} className="text-white/25 hover:text-white/60 transition"><X size={16}/></button>
          </div>
          <div className="p-6 space-y-4 overflow-y-auto max-h-[50vh]">
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Endpoint', val: selectedCorr.hostname },
                { label: 'Kullanıcı', val: selectedCorr.user || '—' },
                { label: 'Risk', val: `${selectedCorr.risk?.score ?? 0}/100` },
              ].map(m => (
                <div key={m.label} className="bg-white/3 border border-white/5 rounded-xl p-3">
                  <p className="text-[8px] text-white/25 uppercase tracking-[0.15em] mb-1">{m.label}</p>
                  <p className="text-[11px] font-mono text-white/70 truncate">{m.val}</p>
                </div>
              ))}
            </div>

            {/* Severity + time */}
            <div className="flex items-center gap-3">
              <span className={`text-[9px] font-black px-3 py-1.5 rounded-lg border ${sevColor(selectedCorr.severity)}`}>{selectedCorr.severity}</span>
              <span className="text-[10px] text-white/30 font-mono">{fmt(selectedCorr.timestamp)}</span>
            </div>

            {/* Description */}
            {selectedCorr.description && (
              <div className="bg-black/40 border border-white/6 rounded-xl p-4">
                <p className="text-[8px] text-white/25 uppercase tracking-[0.15em] mb-2">Açıklama</p>
                <p className="text-[11px] text-white/60 leading-relaxed">{selectedCorr.description}</p>
              </div>
            )}

            {/* MITRE */}
            {selectedCorr.mitre && selectedCorr.mitre.length > 0 && (
              <div className="bg-white/2 border border-white/4 rounded-xl p-4">
                <p className="text-[8px] text-white/25 uppercase tracking-[0.15em] mb-2">MITRE ATT&CK</p>
                <div className="flex flex-wrap gap-2">
                  {selectedCorr.mitre.map((m, i) => (
                    <span key={i} className="text-[9px] font-mono px-2 py-1 bg-red-500/10 border border-red-500/20 text-red-400 rounded">
                      {m.technique}{m.tactic ? ` — ${m.tactic}` : ''}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Evidence */}
            {selectedCorr.evidence && selectedCorr.evidence.length > 0 && (
              <div className="bg-black/40 border border-white/5 rounded-xl p-4">
                <p className="text-[8px] text-white/25 uppercase tracking-[0.15em] mb-2">Kanıt ({selectedCorr.evidence.length} olay)</p>
                <div className="space-y-1.5 max-h-40 overflow-auto">
                  {selectedCorr.evidence.map((ev: any, i: number) => (
                    <div key={i} className="text-[9px] font-mono text-white/40 bg-white/2 rounded px-3 py-1.5">
                      {ev.type} @ {ev.hostname} — {ev.user} — {relativeTime(ev.timestamp || '')}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Actions — Korelasyon/Sigma için de aksiyon butonları */}
          <div className="p-5 border-t border-white/5 bg-black/30 flex flex-wrap gap-2">
            {(() => {
              const fakeAlert: Alert = {
                id: selectedCorr.id,
                hostname: selectedCorr.hostname,
                rule: selectedCorr.rule,
                severity: selectedCorr.severity as any,
                serial: '',
                pid: 0,
                details: selectedCorr.description,
                created_at: selectedCorr.timestamp,
                risk_score: selectedCorr.risk?.score ?? 0,
                username: selectedCorr.user,
              };
              return (
                <>
                  <ActionBtn label="AI Analiz" icon={<Bot size={14}/>} loading={loadingAction==='AI_ANALYZE'} onClick={() => { setAiResult(null); sendCommand("AI_ANALYZE", fakeAlert); }} primary />
                  <ActionBtn label="İzole Et" icon={<WifiOff size={14}/>} loading={loadingAction==='ISOLATE'} onClick={() => sendCommand("ISOLATE", fakeAlert)} warn />
                  <ActionBtn label="USB Devre Dışı" icon={<Usb size={14}/>} loading={loadingAction==='USB_DISABLE'} onClick={() => sendCommand("USB_DISABLE", fakeAlert)} danger />
                  <ActionBtn label="Süreçleri Gör" icon={<Cpu size={14}/>} loading={processLoading} onClick={() => { setShowProcessModal(true); fetchProcessList(selectedCorr.hostname); }} />
                </>
              );
            })()}
          </div>
        </Modal>
      )}

      {/* ── RULE MODAL ── */}
      {showRuleModal && (
        <Modal onClose={() => setShowRuleModal(false)}>
          <div className="p-6 border-b border-white/6 flex items-center justify-between">
            <h2 className="text-sm font-black text-white flex items-center gap-2"><ShieldCheck size={16} className="text-red-400"/> Yeni Kural</h2>
            <button onClick={() => setShowRuleModal(false)} className="text-white/25 hover:text-white/60 transition"><X size={16}/></button>
          </div>
          <div className="p-6 space-y-4">
            {[
              { label: 'Kural Adı', key: 'name', placeholder: 'Örn: Mimikatz Tespiti' },
              { label: 'Anahtar Kelime', key: 'keyword', placeholder: 'Örn: mimikatz.exe' },
            ].map(f => (
              <div key={f.key}>
                <label className="text-[9px] text-white/30 uppercase tracking-[0.2em] block mb-1.5">{f.label}</label>
                <input
                  value={(newRule as any)[f.key]}
                  onChange={e => setNewRule({ ...newRule, [f.key]: e.target.value })}
                  className="w-full bg-black/50 border border-white/8 rounded-xl px-4 py-3 text-sm text-white font-mono placeholder:text-white/15 focus:border-white/20 focus:outline-none"
                  placeholder={f.placeholder}
                />
              </div>
            ))}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-[9px] text-white/30 uppercase tracking-[0.2em] block mb-1.5">Risk Skoru</label>
                <input type="number" min="0" max="100" value={newRule.risk_score}
                  onChange={e => setNewRule({ ...newRule, risk_score: parseInt(e.target.value) })}
                  className="w-full bg-black/50 border border-white/8 rounded-xl px-4 py-3 text-sm text-white focus:border-white/20 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-[9px] text-white/30 uppercase tracking-[0.2em] block mb-1.5">Şiddet</label>
                <select value={newRule.severity} onChange={e => setNewRule({ ...newRule, severity: e.target.value })}
                  className="w-full bg-black/50 border border-white/8 rounded-xl px-4 py-3 text-sm text-white focus:border-white/20 focus:outline-none"
                >
                  {['INFO','WARNING','HIGH','CRITICAL'].map(s => <option key={s}>{s}</option>)}
                </select>
              </div>
            </div>
          </div>
          <div className="p-5 border-t border-white/5">
            <button onClick={addRule} className="w-full py-3 bg-red-600 hover:bg-red-500 active:scale-[0.98] text-white rounded-xl font-black text-[10px] uppercase tracking-[0.2em] transition-all">
              Kaydet
            </button>
          </div>
        </Modal>
      )}

      {/* ── PROCESS LIST MODAL ── */}
      {showProcessModal && (
        <Modal onClose={() => { setShowProcessModal(false); setProcessList([]); setProcessFilter(""); }}>
          <div className="p-6 border-b border-white/6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-orange-500/10 border border-orange-500/20 rounded-xl flex items-center justify-center text-orange-400">
                <Cpu size={15}/>
              </div>
              <div>
                <h2 className="text-sm font-black text-white">Çalışan Süreçler</h2>
                <p className="text-[9px] text-white/25 font-mono mt-0.5">
                  {selectedLog?.hostname || "—"} · {processList.length} süreç
                </p>
              </div>
            </div>
            <button onClick={() => { setShowProcessModal(false); setProcessList([]); setProcessFilter(""); }} className="text-white/25 hover:text-white/60 transition"><X size={16}/></button>
          </div>
          <div className="px-6 pt-4 pb-2">
            <div className="flex items-center gap-2 bg-black/40 border border-white/6 rounded-xl px-3 py-2">
              <Search size={12} className="text-white/25 shrink-0"/>
              <input value={processFilter} onChange={e => setProcessFilter(e.target.value)} placeholder="Süreç adı veya PID filtrele..." className="flex-1 bg-transparent text-[11px] text-white/70 placeholder-white/20 outline-none font-mono"/>
              {processFilter && <button onClick={() => setProcessFilter("")} className="text-white/20 hover:text-white/50"><X size={11}/></button>}
            </div>
          </div>
          <div className="px-6 pb-4 overflow-y-auto max-h-[50vh]">
            {processLoading ? (
              <div className="flex items-center justify-center py-12 gap-3 text-white/30">
                <Loader2 size={16} className="animate-spin"/>
                <span className="text-xs">Yükleniyor...</span>
              </div>
            ) : processList.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 gap-2 text-white/20">
                <Cpu size={32}/>
                <p className="text-xs">Süreç listesi boş</p>
                <button onClick={() => fetchProcessList(selectedLog?.hostname || "")} className="mt-2 text-[10px] text-white/40 hover:text-white/70 border border-white/10 rounded-lg px-4 py-2 transition">Yeniden Dene</button>
              </div>
            ) : (
              <div className="space-y-1 mt-2">
                <div className="grid grid-cols-12 gap-2 text-[8px] text-white/20 uppercase tracking-widest px-3 py-1">
                  <span className="col-span-1">PID</span><span className="col-span-4">Ad</span>
                  <span className="col-span-2 text-right">CPU%</span><span className="col-span-2 text-right">RAM MB</span>
                  <span className="col-span-2">Kullanıcı</span><span className="col-span-1 text-right">Kill</span>
                </div>
                {processList
                  .filter(p => !processFilter || p.name.toLowerCase().includes(processFilter.toLowerCase()) || String(p.pid).includes(processFilter))
                  .sort((a, b) => b.cpu - a.cpu)
                  .map(p => (
                    <div key={p.pid} className={`grid grid-cols-12 gap-2 items-center px-3 py-2.5 rounded-xl border transition-all ${
                      p.cpu > 50 ? "bg-red-500/5 border-red-500/15" : p.cpu > 20 ? "bg-orange-500/5 border-orange-500/10" : "bg-white/2 border-white/4 hover:bg-white/3"
                    }`}>
                      <span className="col-span-1 text-[9px] font-mono text-white/40">{p.pid}</span>
                      <div className="col-span-4">
                        <p className="text-[10px] font-black text-white/70 truncate">{p.name}</p>
                        {p.cmdline && <p className="text-[8px] text-white/25 font-mono truncate mt-0.5">{p.cmdline}</p>}
                      </div>
                      <span className={`col-span-2 text-right text-[10px] font-mono font-black ${p.cpu > 50 ? "text-red-400" : p.cpu > 20 ? "text-orange-400" : "text-white/40"}`}>{p.cpu.toFixed(1)}%</span>
                      <span className="col-span-2 text-right text-[10px] font-mono text-white/40">{p.memory.toFixed(0)}</span>
                      <span className="col-span-2 text-[9px] text-white/30 font-mono truncate">{p.user}</span>
                      <div className="col-span-1 flex justify-end">
                        <button
                          onClick={() => {
                            if (!confirm(`PID ${p.pid} (${p.name}) sonlandırılsın mı?`)) return;
                            const h = selectedLog?.hostname || selectedCorr?.hostname || "";
                            authFetch(`${API}/api/actions/kill`, { method: "POST", body: JSON.stringify({ hostname: h, pid: p.pid }) })
                              .then(r => { if (r.ok) { notify(`PID ${p.pid} sonlandırıldı`); setProcessList(prev => prev.filter(x => x.pid !== p.pid)); } else notify("Kill başarısız", "err"); })
                              .catch(() => notify("Bağlantı hatası", "err"));
                          }}
                          className="w-6 h-6 flex items-center justify-center bg-red-500/10 hover:bg-red-500/25 border border-red-500/20 hover:border-red-500/40 text-red-400 rounded-lg transition-all"
                          title={`PID ${p.pid} sonlandır`}
                        >
                          <XOctagon size={11}/>
                        </button>
                      </div>
                    </div>
                  ))}
              </div>
            )}
          </div>
          <div className="p-4 border-t border-white/5 bg-black/30 flex items-center justify-between">
            <span className="text-[9px] text-white/25">{processList.length} süreç · {processList.filter(p => p.cpu > 0).length} aktif</span>
            <button onClick={() => fetchProcessList(selectedLog?.hostname || selectedCorr?.hostname || "")} className="flex items-center gap-1.5 text-[9px] text-white/40 hover:text-white/70 border border-white/8 rounded-lg px-3 py-1.5 transition">
              <RefreshCw size={10}/> Yenile
            </button>
          </div>
        </Modal>
      )}

      {/* ── 2FA MODAL ── */}
      {show2FA && (
        <Modal onClose={() => { setShow2FA(false); setTwoFASetup(null); setTwoFACode(""); }}>
          <div className="p-6 border-b border-white/6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-green-500/10 border border-green-500/20 rounded-xl flex items-center justify-center text-green-400">
                <ShieldCheck size={15}/>
              </div>
              <div>
                <h2 className="text-sm font-black text-white">İki Faktörlü Doğrulama</h2>
                <p className="text-[9px] text-white/30 mt-0.5">Google Authenticator uyumlu TOTP</p>
              </div>
            </div>
            <button onClick={() => { setShow2FA(false); setTwoFASetup(null); setTwoFACode(""); }} className="text-white/25 hover:text-white/60"><X size={16}/></button>
          </div>

          <div className="p-6 space-y-4">
            {/* Durum */}
            {twoFAStatus && !twoFASetup && (
              <div className={`flex items-center gap-3 p-4 rounded-xl border ${
                twoFAStatus.totp_enabled
                  ? "bg-green-500/5 border-green-500/20"
                  : "bg-white/3 border-white/8"
              }`}>
                <div className={`w-3 h-3 rounded-full ${twoFAStatus.totp_enabled ? "bg-green-400" : "bg-white/20"}`}/>
                <div className="flex-1">
                  <p className="text-[11px] font-black text-white/70">
                    {twoFAStatus.totp_enabled ? "2FA Aktif" : "2FA Kapalı"}
                  </p>
                  <p className="text-[9px] text-white/30">
                    {twoFAStatus.totp_enabled
                      ? "Hesabınız Google Authenticator ile korunuyor"
                      : "Hesabınızı korumak için 2FA aktifleştirin"}
                  </p>
                </div>
              </div>
            )}

            {/* QR kurulum ekranı */}
            {twoFASetup && (
              <div className="space-y-4">
                <div className="bg-white/3 border border-white/8 rounded-xl p-4 text-center">
                  {twoFASetup.qr_data_url ? (
                    <img src={twoFASetup.qr_data_url} alt="QR Code" className="w-40 h-40 mx-auto rounded-lg"/>
                  ) : (
                    <div className="w-40 h-40 mx-auto bg-black/40 border border-white/10 rounded-lg flex items-center justify-center">
                      <p className="text-[9px] text-white/30">QR oluşturulamadı</p>
                    </div>
                  )}
                  <p className="text-[9px] text-white/40 mt-3">Google Authenticator → + → QR kodu tara</p>
                </div>

                <div className="bg-black/40 border border-white/6 rounded-xl p-3">
                  <p className="text-[8px] text-white/30 mb-1">Manual giriş kodu</p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-[10px] text-green-400 font-mono tracking-widest">{twoFASetup.secret}</code>
                    <button onClick={() => { navigator.clipboard.writeText(twoFASetup!.secret); notify("Kopyalandı"); }}
                      className="text-white/20 hover:text-white/50"><Copy size={12}/></button>
                  </div>
                </div>

                <div>
                  <p className="text-[9px] text-white/30 mb-2">Authenticator'dan gelen 6 haneli kodu girin</p>
                  <input
                    value={twoFACode}
                    onChange={e => setTwoFACode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    placeholder="000000"
                    maxLength={6}
                    className="w-full bg-black/40 border border-white/10 rounded-xl px-3 py-3 text-center text-2xl font-mono text-white tracking-[0.5em] outline-none focus:border-green-500/40"
                  />
                </div>

                <button
                  onClick={verify2FA}
                  disabled={twoFACode.length !== 6}
                  className="w-full py-3 bg-green-600 hover:bg-green-500 disabled:opacity-30 disabled:cursor-not-allowed text-white text-[11px] font-black rounded-xl transition"
                >
                  Doğrula ve Aktifleştir
                </button>
              </div>
            )}
          </div>

          {/* Alt butonlar */}
          {!twoFASetup && (
            <div className="p-5 border-t border-white/5 bg-black/30 flex gap-2">
              {twoFAStatus?.totp_enabled ? (
                <button onClick={disable2FA} className="flex-1 py-2.5 bg-red-600/80 hover:bg-red-500 text-white text-[11px] font-black rounded-xl transition">
                  2FA'yı Kapat
                </button>
              ) : (
                <button onClick={setup2FA} className="flex-1 py-2.5 bg-green-600 hover:bg-green-500 text-white text-[11px] font-black rounded-xl transition">
                  2FA Kur
                </button>
              )}
              <button onClick={() => setShow2FA(false)} className="px-4 py-2.5 border border-white/8 hover:border-white/20 text-white/50 text-[11px] rounded-xl transition">
                Kapat
              </button>
            </div>
          )}
        </Modal>
      )}

      {/* ── ŞİFRE DEĞİŞTİRME MODAL ── */}
      {showPasswordChange && (
        <Modal onClose={() => { if (!showPasswordChange) return; setShowPasswordChange(false); }}>
          <div className="p-6 border-b border-white/6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-sky-500/10 border border-sky-500/20 rounded-xl flex items-center justify-center text-sky-400">
                <Lock size={15}/>
              </div>
              <div>
                <h2 className="text-sm font-black text-white">Şifre Değiştir</h2>
                <p className="text-[9px] text-white/30 mt-0.5">Güvenliğiniz için güçlü bir şifre seçin</p>
              </div>
            </div>
            <button onClick={() => setShowPasswordChange(false)} className="text-white/25 hover:text-white/60 transition"><X size={16}/></button>
          </div>
          <div className="p-6 space-y-3">
            {[
              { label: "Mevcut Şifre", key: "current", type: "password" },
              { label: "Yeni Şifre (min. 8 karakter)", key: "next", type: "password" },
              { label: "Yeni Şifre (tekrar)", key: "confirm", type: "password" },
            ].map(f => (
              <div key={f.key}>
                <p className="text-[9px] text-white/30 uppercase tracking-widest mb-1">{f.label}</p>
                <input
                  type={f.type}
                  value={(pwForm as any)[f.key]}
                  onChange={e => setPwForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                  className="w-full bg-black/40 border border-white/8 rounded-xl px-3 py-2.5 text-[11px] text-white/70 outline-none focus:border-sky-500/40 font-mono"
                />
              </div>
            ))}
            {pwForm.next && pwForm.confirm && pwForm.next !== pwForm.confirm && (
              <p className="text-[9px] text-red-400">Şifreler eşleşmiyor</p>
            )}
          </div>
          <div className="p-5 border-t border-white/5 bg-black/30 flex gap-2">
            <button
              onClick={changePassword}
              className="flex-1 py-2.5 bg-sky-600 hover:bg-sky-500 text-white text-[11px] font-black rounded-xl transition"
            >
              Şifreyi Değiştir
            </button>
            <button onClick={() => setShowPasswordChange(false)} className="px-4 py-2.5 border border-white/8 hover:border-white/20 text-white/50 text-[11px] rounded-xl transition">
              İptal
            </button>
          </div>
        </Modal>
      )}

      {/* ── MÜŞTERİ (TENANT) YÖNETİMİ MODAL ── */}
      {showTenantMgmt && (
        <Modal onClose={() => setShowTenantMgmt(false)}>
          <div className="p-6 border-b border-white/6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center justify-center text-emerald-400">
                <Database size={15}/>
              </div>
              <div>
                <h2 className="text-sm font-black text-white">Müşteri Yönetimi</h2>
                <p className="text-[9px] text-white/30 mt-0.5">{tenantList.length} müşteri · MSSP Paneli</p>
              </div>
            </div>
            <button onClick={() => setShowTenantMgmt(false)} className="text-white/25 hover:text-white/60"><X size={16}/></button>
          </div>

          <div className="p-6 overflow-y-auto max-h-[60vh] space-y-4">
            {/* Yeni müşteri formu */}
            <div className="bg-emerald-500/5 border border-emerald-500/15 rounded-xl p-4 space-y-3">
              <p className="text-[9px] text-emerald-400 uppercase tracking-widest font-black">Yeni Müşteri Ekle</p>
              <div className="grid grid-cols-2 gap-2">
                <div className="col-span-2">
                  <p className="text-[8px] text-white/25 mb-1">Firma Adı</p>
                  <input value={newTenantForm.name}
                    onChange={e => setNewTenantForm(p => ({...p, name: e.target.value}))}
                    placeholder="ABC Muhasebe Ltd."
                    className="w-full bg-black/40 border border-white/8 rounded-lg px-3 py-2 text-[10px] text-white/70 outline-none focus:border-emerald-500/40"/>
                </div>
                <div>
                  <p className="text-[8px] text-white/25 mb-1">İletişim E-posta</p>
                  <input value={newTenantForm.contact_email}
                    onChange={e => setNewTenantForm(p => ({...p, contact_email: e.target.value}))}
                    type="email" placeholder="bilgi@firma.com"
                    className="w-full bg-black/40 border border-white/8 rounded-lg px-3 py-2 text-[10px] text-white/70 outline-none"/>
                </div>
                <div>
                  <p className="text-[8px] text-white/25 mb-1">Max Agent</p>
                  <input value={newTenantForm.max_agents}
                    onChange={e => setNewTenantForm(p => ({...p, max_agents: Number(e.target.value)}))}
                    type="number" min={1} max={500}
                    className="w-full bg-black/40 border border-white/8 rounded-lg px-3 py-2 text-[10px] text-white/70 outline-none"/>
                </div>
                <div className="col-span-2">
                  <p className="text-[8px] text-white/25 mb-1">Plan</p>
                  <select value={newTenantForm.plan}
                    onChange={e => setNewTenantForm(p => ({...p, plan: e.target.value}))}
                    className="w-full bg-black/60 border border-white/8 rounded-lg px-3 py-2 text-[10px] text-white/70 outline-none">
                    <option value="starter">Starter (1-5 agent, 990₺/ay)</option>
                    <option value="pro">Pro (6-15 agent, 1.990₺/ay)</option>
                    <option value="enterprise">Enterprise (16-50 agent, 3.490₺/ay)</option>
                  </select>
                </div>
              </div>
              <button onClick={createTenant} className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-black rounded-xl transition">
                + Müşteri Oluştur
              </button>
            </div>

            {/* Müşteri listesi */}
            <div className="space-y-2">
              {tenantList.map(t => (
                <div key={t.id} className="bg-white/2 border border-white/5 rounded-xl p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <p className="text-[11px] font-black text-white/80">{t.name}</p>
                        <span className={`text-[7px] px-1.5 py-0.5 rounded font-black border ${
                          t.plan === 'enterprise' ? 'bg-purple-500/10 border-purple-500/20 text-purple-400' :
                          t.plan === 'pro' ? 'bg-sky-500/10 border-sky-500/20 text-sky-400' :
                          'bg-white/5 border-white/10 text-white/30'
                        }`}>{t.plan.toUpperCase()}</span>
                        {!t.license_ok && (
                          <span className="text-[7px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 font-black">LİMİT AŞILDI</span>
                        )}
                      </div>
                      <p className="text-[9px] text-white/25 mb-2">{t.contact_email || "—"}</p>
                      <div className="flex items-center gap-4 text-[8px] text-white/30">
                        <span>🖥 {t.active_agents || 0} / {t.max_agents} agent</span>
                        <span>📋 {t.total_alerts || 0} alert</span>
                      </div>
                      {/* Agent Key — kopyalanabilir */}
                      <div className="mt-2 flex items-center gap-2 bg-black/40 border border-white/5 rounded-lg px-2 py-1.5">
                        <span className="text-[7px] text-white/20 uppercase">Agent Key</span>
                        <code className="flex-1 text-[8px] text-emerald-400/70 font-mono truncate">{t.agent_key}</code>
                        <button onClick={() => { navigator.clipboard.writeText(t.agent_key); notify("Agent key kopyalandı"); }}
                          className="text-white/20 hover:text-white/50 transition shrink-0">
                          <Copy size={10}/>
                        </button>
                      </div>
                    </div>
                    <button onClick={() => deleteTenant(t.id, t.name)}
                      className="w-7 h-7 flex items-center justify-center bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400 rounded-lg transition shrink-0">
                      <Trash2 size={11}/>
                    </button>
                  </div>
                </div>
              ))}
              {tenantList.length === 0 && (
                <div className="flex flex-col items-center py-10 gap-2 text-white/20">
                  <Database size={28}/>
                  <p className="text-xs">Henüz müşteri eklenmedi</p>
                </div>
              )}
            </div>
          </div>
        </Modal>
      )}

      {/* ── KULLANICI YÖNETİMİ MODAL ── */}
      {showUserMgmt && (
        <Modal onClose={() => setShowUserMgmt(false)}>
          <div className="p-6 border-b border-white/6 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-purple-500/10 border border-purple-500/20 rounded-xl flex items-center justify-center text-purple-400">
                <Users size={15}/>
              </div>
              <div>
                <h2 className="text-sm font-black text-white">Kullanıcı Yönetimi</h2>
                <p className="text-[9px] text-white/30 mt-0.5">{userList.length} kullanıcı</p>
              </div>
            </div>
            <button onClick={() => setShowUserMgmt(false)} className="text-white/25 hover:text-white/60 transition"><X size={16}/></button>
          </div>

          <div className="p-6 overflow-y-auto max-h-[55vh] space-y-4">
            {/* Yeni kullanıcı formu */}
            <div className="bg-white/2 border border-white/6 rounded-xl p-4 space-y-3">
              <p className="text-[9px] text-white/40 uppercase tracking-widest font-black">Yeni Kullanıcı Ekle</p>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { label: "Kullanıcı Adı", key: "username", type: "text" },
                  { label: "Şifre", key: "password", type: "password" },
                  { label: "E-posta", key: "email", type: "email" },
                ].map(f => (
                  <div key={f.key} className={f.key === "email" ? "col-span-2" : ""}>
                    <p className="text-[8px] text-white/25 mb-1">{f.label}</p>
                    <input
                      type={f.type}
                      value={(newUserForm as any)[f.key]}
                      onChange={e => setNewUserForm(p => ({ ...p, [f.key]: e.target.value }))}
                      className="w-full bg-black/40 border border-white/8 rounded-lg px-3 py-2 text-[10px] text-white/70 outline-none focus:border-purple-500/40 font-mono"
                    />
                  </div>
                ))}
                <div>
                  <p className="text-[8px] text-white/25 mb-1">Rol</p>
                  <select
                    value={newUserForm.role}
                    onChange={e => setNewUserForm(p => ({ ...p, role: e.target.value }))}
                    className="w-full bg-black/60 border border-white/8 rounded-lg px-3 py-2 text-[10px] text-white/70 outline-none"
                  >
                    <option value="viewer">Viewer</option>
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
              </div>
              <button onClick={createUser} className="w-full py-2 bg-purple-600 hover:bg-purple-500 text-white text-[10px] font-black rounded-xl transition">
                + Kullanıcı Oluştur
              </button>
            </div>

            {/* Mevcut kullanıcılar */}
            <div className="space-y-1">
              {userList.map(u => (
                <div key={u.username} className="flex items-center gap-3 px-4 py-3 bg-white/2 border border-white/5 rounded-xl">
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center text-[10px] font-black ${
                    u.role === "admin" ? "bg-red-500/15 text-red-400 border border-red-500/20" :
                    u.role === "analyst" ? "bg-sky-500/15 text-sky-400 border border-sky-500/20" :
                    "bg-white/5 text-white/30 border border-white/10"
                  }`}>
                    {u.username[0].toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[10px] font-black text-white/70">{u.username}</p>
                    <p className="text-[8px] text-white/25">{u.email || "—"} · Son giriş: {u.last_login ? new Date(u.last_login).toLocaleDateString("tr-TR") : "Hiç"}</p>
                  </div>
                  <span className={`text-[8px] px-2 py-0.5 rounded font-black border ${
                    u.role === "admin" ? "bg-red-500/10 border-red-500/20 text-red-400" :
                    u.role === "analyst" ? "bg-sky-500/10 border-sky-500/20 text-sky-400" :
                    "bg-white/5 border-white/10 text-white/30"
                  }`}>{u.role.toUpperCase()}</span>
                  {u.password_change_required && (
                    <span className="text-[8px] px-2 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400">ŞİFRE DEĞİŞTİR</span>
                  )}
                  {u.username !== "admin" && (
                    <button onClick={() => deleteUser(u.username)} className="w-6 h-6 flex items-center justify-center bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400 rounded-lg transition">
                      <X size={11}/>
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </Modal>
      )}

      {/* ── NOTIFICATION TOAST ── */}
      {notification && (
        <div className={`fixed bottom-5 right-5 z-100 flex items-center gap-2.5 px-4 py-3 rounded-xl border text-[11px] font-bold shadow-2xl fade-in ${
          notification.type === 'ok'
            ? 'bg-emerald-950 border-emerald-500/25 text-emerald-300'
            : 'bg-red-950 border-red-500/25 text-red-300'
        }`}>
          {notification.type === 'ok' ? <Check size={13}/> : <AlertTriangle size={13}/>}
          {notification.msg}
        </div>
      )}
    </div>
  );
}

// ─── SHARED COMPONENTS ──────────────────────────────────────────────────────

const Modal = ({ children, onClose }: { children: React.ReactNode; onClose: () => void }) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xl" onClick={onClose}>
    <div className="bg-[#050505] border border-white/7 rounded-2xl w-full max-w-2xl max-h-[88vh] overflow-hidden shadow-2xl flex flex-col fade-in" onClick={e => e.stopPropagation()}>
      {children}
    </div>
  </div>
);

const TabHeader = ({ title, subtitle, icon, count }: { title: string; subtitle: string; icon: React.ReactNode; count?: number }) => (
  <div className="flex items-center gap-3">
    <div className="w-9 h-9 bg-white/4 border border-white/6 rounded-xl flex items-center justify-center text-white/40">
      {icon}
    </div>
    <div>
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-black text-white">{title}</h2>
        {count !== undefined && count > 0 && (
          <span className="text-[9px] font-black px-2 py-0.5 bg-red-500/15 text-red-400 rounded-full">{count}</span>
        )}
      </div>
      <p className="text-[9px] text-white/25 mt-0.5">{subtitle}</p>
    </div>
  </div>
);

const CorrCard = ({ alert, onClick, badge }: { alert: CorrelationAlert; onClick: () => void; badge?: string }) => (
  <div
    onClick={onClick}
    className="group bg-white/2 border border-white/5 hover:border-white/9 rounded-xl p-4 cursor-pointer transition-all hover:bg-white/3.5 fade-in"
  >
    <div className="flex items-start justify-between gap-3">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1.5">
          <span className={`text-[9px] font-black px-2 py-0.5 rounded border ${sevColor(alert.severity || alert.risk?.level)}`}>
            {alert.severity || alert.risk?.level}
          </span>
          {badge && <span className="text-[9px] font-black px-2 py-0.5 bg-purple-500/10 border border-purple-500/20 text-purple-400 rounded">{badge}</span>}
          <span className="text-[10px] font-bold text-white/70 truncate">{alert.description}</span>
        </div>
        <p className="text-[9px] text-white/30 font-mono">{alert.rule}</p>
        {alert.mitre && alert.mitre.length > 0 && (
          <div className="flex gap-1 mt-1.5">
            {alert.mitre.slice(0,3).map((m,i) => (
              <span key={i} className="text-[8px] font-mono px-1.5 py-0.5 bg-red-500/8 text-red-400/70 rounded border border-red-500/15">{m.technique}</span>
            ))}
          </div>
        )}
      </div>
      <div className="text-right shrink-0">
        <p className="text-[9px] text-white/30 font-mono">{alert.hostname}</p>
        <p className="text-[9px] text-sky-400/60 font-mono">{alert.user}</p>
        <p className="text-[8px] text-white/20 mt-1">{relativeTime(alert.timestamp)}</p>
        <div className="flex items-center gap-1.5 mt-1.5 justify-end">
          <div className="w-14 h-1 bg-white/10 rounded-full overflow-hidden">
            <div className={`h-full ${riskBar(alert.risk?.score || 0)} rounded-full`} style={{ width: `${alert.risk?.score || 0}%` }} />
          </div>
          <span className="text-[9px] text-white/30">{alert.risk?.score}</span>
        </div>
      </div>
    </div>
  </div>
);

const EmptyState = ({ msg, small }: { msg: string; small?: boolean }) => (
  <div className={`text-center text-white/20 ${small ? 'py-8' : 'py-16'}`}>
    <div className="w-8 h-8 bg-white/3 rounded-xl flex items-center justify-center mx-auto mb-2">
      <Eye size={14} className="opacity-40"/>
    </div>
    <p className="text-[10px]">{msg}</p>
  </div>
);

const FilterBtn = ({ label, active, onClick, color }: { label: string; active: boolean; onClick: () => void; color?: string }) => (
  <button
    onClick={onClick}
    className={`px-3 py-1.5 rounded-lg border text-[9px] font-black uppercase tracking-widest transition-all ${
      active
        ? color === 'red'
          ? 'bg-red-500/15 border-red-500/25 text-red-400'
          : 'bg-white/7 border-white/10 text-white'
        : 'bg-white/3 border-white/5 text-white/30 hover:text-white/50'
    }`}
  >
    {label}
  </button>
);

function ActionBtn({ label, icon, loading, onClick, primary, warn, danger }: {
  label: string;
  icon: React.ReactNode;
  loading: boolean;
  onClick: () => void;
  primary?: boolean;
  warn?: boolean;
  danger?: boolean;
}) {
  const cls = danger
    ? 'bg-red-600 hover:bg-red-500 text-white'
    : primary
    ? 'bg-sky-600 hover:bg-sky-500 text-white'
    : warn
    ? 'bg-orange-500/10 border border-orange-500/20 text-orange-400 hover:bg-orange-500/15'
    : 'bg-white/4 border border-white/7 text-white/50 hover:text-white/70 hover:bg-white/7';

  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-black text-[10px] uppercase tracking-widest transition-all active:scale-[0.97] disabled:opacity-30 ${cls}`}
    >
      <span className="shrink-0 flex items-center justify-center" style={{ width: 14, height: 14 }}>
        {loading ? <Loader2 size={13} className="animate-spin" /> : icon}
      </span>
      <span>{label}</span>
    </button>
  );
}