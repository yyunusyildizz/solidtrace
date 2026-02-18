"use client";
import { useState, useEffect, useRef } from 'react';

// --- TİP TANIMLAMALARI (INTERFACES) ---
interface Alert {
  id: string;
  created_at: string;
  hostname: string;
  username: string;
  rule: string;
  confidence: number;
  mitre_technique?: string;
  mitre_tactic?: string;
  risk_score: number;
  status: string;
  command_line?: string;
  raw_event?: any;
}

interface Stats {
  total_alerts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface MitreCoverage {
  techniques: string[];
  tactics: string[];
  technique_count: number;
  tactic_count: number;
}

interface RealtimeEvent {
  timestamp: string;
  event: {
    hostname?: string;
    user?: string;
    command_line?: string;
  };
  risk?: {
    score: number;
  };
  [key: string]: any; 
}

export default function SOCDashboard() {
  // --- URL AYARLARI ---
  const API_URL = typeof window !== 'undefined' 
    ? (window.location.hostname === 'localhost' ? 'http://localhost:8000' : 'https://your-api-domain.com')
    : 'http://localhost:8000';
    
  const WS_URL = typeof window !== 'undefined'
    ? (window.location.hostname === 'localhost' ? 'ws://localhost:8000' : 'wss://your-api-domain.com')
    : 'ws://localhost:8000';

  // --- STATE TANIMLAMALARI ---
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats>({
    total_alerts: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  const [mitreCoverage, setMitreCoverage] = useState<MitreCoverage>({
    techniques: [],
    tactics: [],
    technique_count: 0,
    tactic_count: 0
  });
  const [realtimeEvents, setRealtimeEvents] = useState<RealtimeEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [filter, setFilter] = useState<string>('all');
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  
  const wsRef = useRef<WebSocket | null>(null);

  // --- DATA FETCHING ---
  const fetchData = async () => {
    try {
      // 1. Alerts Çekme (Güvenli Yöntem)
      const alertsRes = await fetch(`${API_URL}/api/alerts?limit=50`);
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        // Backend bazen hata mesajı dönerse dizi olmaz, kontrol ediyoruz:
        if (Array.isArray(alertsData)) {
          setAlerts(alertsData);
        } else {
          setAlerts([]); // Dizi değilse boş yap
        }
      }

      // 2. İstatistikleri Çekme
      const statsRes = await fetch(`${API_URL}/api/stats`);
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      // 3. MITRE Coverage Çekme
      const mitreRes = await fetch(`${API_URL}/api/mitre/coverage`);
      if (mitreRes.ok) {
        const mitreData = await mitreRes.json();
        setMitreCoverage(mitreData);
      }

      setLoading(false);
    } catch (error) {
      console.error('Fetch error:', error);
      setLoading(false);
      // Hata durumunda verileri sıfırla/koru
      if (!alerts) setAlerts([]);
    }
  };

  // Initial Load & Interval
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  // --- WEBSOCKET CONNECTION ---
  const connectWebSocket = () => {
    try {
      const ws = new WebSocket(`${WS_URL}/ws/alerts`);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'alert') {
            setRealtimeEvents(prev => [data.data, ...prev.slice(0, 9)]);
            fetchData(); 
          }
        } catch (e) {
          console.error("WS Parse Error", e);
        }
      };

      ws.onerror = (error) => {
        // console.error('WebSocket error:', error); // Hata loglarını sessize alabiliriz
        setWsConnected(false);
      };

      ws.onclose = () => {
        setWsConnected(false);
        setTimeout(connectWebSocket, 5000);
      };

      wsRef.current = ws;
    } catch (error) {
      console.error('WebSocket connection error:', error);
    }
  };

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // --- ACTIONS ---
  const updateAlertStatus = async (alertId: string, status: string) => {
    try {
      await fetch(`${API_URL}/api/alerts/${alertId}/status?status=${status}`, {
        method: 'PATCH'
      });
      fetchData();
      setSelectedAlert(null);
    } catch (error) {
      console.error('Update error:', error);
    }
  };

  const generateTestAlert = async () => {
    try {
      await fetch(`${API_URL}/api/test/generate-alert`, { method: 'POST' });
      fetchData();
    } catch (error) {
      console.error('Test alert error:', error);
    }
  };

  // --- HELPERS ---
  // Güvenli Filtreleme (alerts undefined/null olsa bile çalışır)
  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  
  const filteredAlerts = safeAlerts.filter(alert => {
    if (filter === 'all') return true;
    if (filter === 'critical') return alert.risk_score >= 75;
    if (filter === 'high') return alert.risk_score >= 50 && alert.risk_score < 75;
    if (filter === 'medium') return alert.risk_score >= 25 && alert.risk_score < 50;
    if (filter === 'low') return alert.risk_score < 25;
    return alert.status === filter;
  });

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'red';
    if (score >= 50) return 'orange';
    if (score >= 25) return 'yellow';
    return 'green';
  };

  const getRiskLabel = (score: number) => {
    if (score >= 75) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    return 'LOW';
  };

  // --- RENDER ---
  if (loading) {
    return (
      <div className="min-h-screen bg-linear-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-white text-lg">Loading SOC Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-linear-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="absolute inset-0 bg-blue-500 blur-xl opacity-30 animate-pulse"></div>
                <span className="relative text-4xl">🛡️</span>
              </div>
              <div>
                <h1 className="text-2xl font-bold bg-linear-to-r from-blue-400 via-purple-500 to-pink-500 bg-clip-text text-transparent">
                  Security Operations Center
                </h1>
                <p className="text-xs text-slate-400">Real-time Threat Detection & Response</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className={`flex items-center gap-2 px-3 py-1 rounded-full border ${
                wsConnected ? 'bg-green-900/20 border-green-700' : 'bg-red-900/20 border-red-700'
              }`}>
                <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
                <span className="text-xs font-bold">{wsConnected ? 'LIVE' : 'OFFLINE'}</span>
              </div>
              
              <button
                onClick={generateTestAlert}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm transition"
              >
                Generate Test Alert
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        
        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
          <div className="bg-linear-to-br from-slate-800 to-slate-900 rounded-xl p-6 border border-slate-700">
            <div className="text-4xl font-bold text-white mb-2">{stats.total_alerts}</div>
            <div className="text-sm text-slate-400">Total Alerts</div>
          </div>
          
          <div className="bg-linear-to-br from-red-900/50 to-red-800/50 rounded-xl p-6 border border-red-700">
            <div className="text-4xl font-bold text-red-400 mb-2">{stats.critical}</div>
            <div className="text-sm text-slate-400">Critical</div>
          </div>
          
          <div className="bg-linear-to-br from-orange-900/50 to-orange-800/50 rounded-xl p-6 border border-orange-700">
            <div className="text-4xl font-bold text-orange-400 mb-2">{stats.high}</div>
            <div className="text-sm text-slate-400">High</div>
          </div>
          
          <div className="bg-linear-to-br from-yellow-900/50 to-yellow-800/50 rounded-xl p-6 border border-yellow-700">
            <div className="text-4xl font-bold text-yellow-400 mb-2">{stats.medium}</div>
            <div className="text-sm text-slate-400">Medium</div>
          </div>
          
          <div className="bg-linear-to-br from-green-900/50 to-green-800/50 rounded-xl p-6 border border-green-700">
            <div className="text-4xl font-bold text-green-400 mb-2">{stats.low}</div>
            <div className="text-sm text-slate-400">Low</div>
          </div>
        </div>

        {/* MITRE ATT&CK Coverage */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
            <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
              <span>🎯</span>
              MITRE ATT&CK Coverage
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center p-4 bg-blue-900/20 border border-blue-700 rounded-lg">
                <div className="text-3xl font-bold text-blue-400">{mitreCoverage.technique_count}</div>
                <div className="text-sm text-slate-400 mt-1">Techniques</div>
              </div>
              <div className="text-center p-4 bg-purple-900/20 border border-purple-700 rounded-lg">
                <div className="text-3xl font-bold text-purple-400">{mitreCoverage.tactic_count}</div>
                <div className="text-sm text-slate-400 mt-1">Tactics</div>
              </div>
            </div>
            <div className="mt-4">
              <div className="text-sm text-slate-400 mb-2">Detected Tactics:</div>
              <div className="flex flex-wrap gap-2">
                {mitreCoverage.tactics.map((tactic, idx) => (
                  <span key={idx} className="px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs">
                    {tactic}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
            <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
              <span>⚡</span>
              Real-time Events
            </h3>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {realtimeEvents.length === 0 ? (
                <div className="text-center py-8 text-slate-500 text-sm">
                  No real-time events yet
                </div>
              ) : (
                realtimeEvents.map((event, idx) => (
                  <div key={idx} className="p-3 bg-slate-800/50 border border-slate-700 rounded-lg">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">{event.event?.hostname || 'Unknown'}</span>
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        (event.risk?.score ?? 0) >= 75 ? 'bg-red-500/20 text-red-400' :
                        (event.risk?.score ?? 0) >= 50 ? 'bg-orange-500/20 text-orange-400' :
                          'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {event.risk?.score || 0}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Alert Filters */}
        <div className="mb-6 flex gap-2 flex-wrap">
          {[
            { id: 'all', label: 'All Alerts' },
            { id: 'critical', label: 'Critical' },
            { id: 'high', label: 'High' },
            { id: 'medium', label: 'Medium' },
            { id: 'low', label: 'Low' },
            { id: 'open', label: 'Open' },
            { id: 'investigating', label: 'Investigating' },
            { id: 'resolved', label: 'Resolved' }
          ].map(f => (
            <button
              key={f.id}
              onClick={() => setFilter(f.id)}
              className={`px-4 py-2 rounded-lg transition ${
                filter === f.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-800 text-slate-400 hover:bg-slate-700 border border-slate-700'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Alerts List */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-6 border-b border-slate-800">
            <h2 className="text-2xl font-bold">Security Alerts ({filteredAlerts.length})</h2>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-800 text-slate-300">
                <tr>
                  <th className="p-4 text-left">Time</th>
                  <th className="p-4 text-left">Risk</th>
                  <th className="p-4 text-left">Hostname</th>
                  <th className="p-4 text-left">User</th>
                  <th className="p-4 text-left">Rule</th>
                  <th className="p-4 text-left">MITRE</th>
                  <th className="p-4 text-left">Status</th>
                  <th className="p-4 text-left">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-slate-500">
                      No alerts found
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map((alert) => (
                    <tr key={alert.id} className="hover:bg-slate-800/50 transition">
                      <td className="p-4 text-sm text-slate-400">
                        {new Date(alert.created_at).toLocaleString()}
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          <div className={`w-12 h-12 rounded-full flex items-center justify-center text-lg font-bold bg-${getRiskColor(alert.risk_score)}-500/20 text-${getRiskColor(alert.risk_score)}-400 border border-${getRiskColor(alert.risk_score)}-500`}>
                            {alert.risk_score}
                          </div>
                          <span className={`text-xs font-bold text-${getRiskColor(alert.risk_score)}-400`}>
                            {getRiskLabel(alert.risk_score)}
                          </span>
                        </div>
                      </td>
                      <td className="p-4 font-mono text-sm">{alert.hostname}</td>
                      <td className="p-4 text-sm">{alert.username}</td>
                      <td className="p-4">
                        <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">
                          {alert.rule}
                        </span>
                      </td>
                      <td className="p-4">
                        {alert.mitre_technique && (
                          <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                            {alert.mitre_technique}
                          </span>
                        )}
                      </td>
                      <td className="p-4">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          alert.status === 'open' ? 'bg-red-500/20 text-red-400' :
                          alert.status === 'investigating' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-green-500/20 text-green-400'
                        }`}>
                          {alert.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="p-4">
                        <button
                          onClick={() => setSelectedAlert(alert)}
                          className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm transition"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-2xl font-bold">Alert Details</h2>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-slate-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>
            
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-slate-400 mb-1">Hostname</div>
                  <div className="font-mono text-lg">{selectedAlert.hostname}</div>
                </div>
                <div>
                  <div className="text-sm text-slate-400 mb-1">User</div>
                  <div className="text-lg">{selectedAlert.username}</div>
                </div>
                <div>
                  <div className="text-sm text-slate-400 mb-1">Rule</div>
                  <div className="text-lg">{selectedAlert.rule}</div>
                </div>
                <div>
                  <div className="text-sm text-slate-400 mb-1">Confidence</div>
                  <div className="text-lg">{(selectedAlert.confidence * 100).toFixed(0)}%</div>
                </div>
              </div>

              {selectedAlert.command_line && (
                <div>
                  <div className="text-sm text-slate-400 mb-2">Command Line</div>
                  <div className="p-4 bg-black rounded-lg font-mono text-sm overflow-x-auto">
                    {selectedAlert.command_line}
                  </div>
                </div>
              )}

              {selectedAlert.mitre_technique && (
                <div className="p-4 bg-purple-900/20 border border-purple-700 rounded-lg">
                  <div className="font-bold mb-2">MITRE ATT&CK</div>
                  <div className="flex items-center gap-4">
                    <div>
                      <span className="text-sm text-slate-400">Technique:</span>
                      <span className="ml-2 font-mono">{selectedAlert.mitre_technique}</span>
                    </div>
                    <div>
                      <span className="text-sm text-slate-400">Tactic:</span>
                      <span className="ml-2">{selectedAlert.mitre_tactic}</span>
                    </div>
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                <button
                  onClick={() => selectedAlert && updateAlertStatus(selectedAlert.id, 'investigating')}
                  className="flex-1 px-4 py-3 bg-yellow-600 hover:bg-yellow-700 rounded-lg transition"
                >
                  Mark as Investigating
                </button>
                <button
                  onClick={() => selectedAlert && updateAlertStatus(selectedAlert.id, 'resolved')}
                  className="flex-1 px-4 py-3 bg-green-600 hover:bg-green-700 rounded-lg transition"
                >
                  Mark as Resolved
                </button>
                <button
                  onClick={() => selectedAlert && updateAlertStatus(selectedAlert.id, 'false_positive')}
                  className="flex-1 px-4 py-3 bg-slate-700 hover:bg-slate-600 rounded-lg transition"
                >
                  False Positive
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}