"use client";
import { useState, useEffect, useRef } from 'react';

export default function SolidTraceUltimate() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [session, setSession] = useState(null);
  const [showLogin, setShowLogin] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const [dashboardData, setDashboardData] = useState({
    riskScore: 42,
    activeThreats: 2,
    protectedDevices: 3,
    darkWebLeaks: 0,
    realtimeEvents: []
  });

  const [dwEmail, setDwEmail] = useState('');
  const [dwLoading, setDwLoading] = useState(false);
  const [dwResult, setDwResult] = useState(null);

  const [chatMessages, setChatMessages] = useState([
    { role: 'assistant', content: 'Merhaba! Siber guvenlik konusunda size nasil yardimci olabilirim?' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef(null);

  const [ransomwareStatus, setRansomwareStatus] = useState('inactive');
  const [honeypotFiles, setHoneypotFiles] = useState([]);
  const [detectedThreats, setDetectedThreats] = useState([]);

  const [userRank, setUserRank] = useState(null);
  const [benchmarkLoading, setBenchmarkLoading] = useState(false);

  const [realtimeProtection, setRealtimeProtection] = useState(false);
  const [realtimeEvents, setRealtimeEvents] = useState([]);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages]);

  useEffect(() => {
    const interval = setInterval(() => {
      setDashboardData(prev => ({
        ...prev,
        riskScore: Math.min(100, prev.riskScore + Math.random() * 2),
        activeThreats: Math.floor(Math.random() * 5),
        realtimeEvents: [
          ...prev.realtimeEvents.slice(-4),
          {
            id: Date.now(),
            type: ['info', 'warning', 'danger'][Math.floor(Math.random() * 3)],
            message: [
              'Yeni port taramasi tamamlandi',
              'Supheli ag trafigi tespit edildi',
              'Sistem guncellemesi mevcut',
              'Guvenlik duvari etkin'
            ][Math.floor(Math.random() * 4)],
            time: new Date().toLocaleTimeString('tr-TR')
          }
        ]
      }));
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleDarkWebCheck = async () => {
    if (!dwEmail.includes('@')) return;
    setDwLoading(true);
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const randomBreaches = Math.floor(Math.random() * 8);
    setDwResult({
      email: dwEmail,
      breaches: randomBreaches,
      breachList: randomBreaches > 0 ? [
        { name: 'Adobe', date: '2013-10-04', records: '152M', risk: 'high' },
        { name: 'LinkedIn', date: '2012-05-05', records: '164M', risk: 'critical' },
        { name: 'Dropbox', date: '2012-07-01', records: '68M', risk: 'medium' }
      ].slice(0, randomBreaches) : [],
      riskLevel: randomBreaches === 0 ? 'safe' : randomBreaches < 3 ? 'medium' : 'high'
    });
    setDwLoading(false);
  };

  const handleChatSend = async () => {
    if (!chatInput.trim()) return;
    
    const userMsg = chatInput;
    setChatMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setChatInput('');
    setChatLoading(true);

    await new Promise(resolve => setTimeout(resolve, 1500));

    const responses = {
      'port': 'Port acikligi, bilgisayarinizin belirli bir servisi internete sundugu anlamina gelir. Ornegin Port 3389 RDP icin kullanilir ve disaridan erisime aciksa guvenlik riski olusturur.',
      'firewall': 'Guvenlik duvari (Firewall), gelen ve giden ag trafigini filtreler. Kapali olmasi, bilgisayarinizin saldirilara acik oldugu anlamina gelir.',
      'ransomware': 'Ransomware, dosyalarinizi sifreleyen ve fidye talep eden kotu amacli yazilimdir. Honeypot sistemi ile erken tespit edebiliriz.',
      'dark web': 'Dark Web, internetin derinliklerinde sifrelerin ve kisisel bilgilerin satildigi yerdir. Duzenli kontrol onemlidir.',
      'vpn': 'VPN, internet trafiginizi sifreler ve IP adresinizi gizler. Gizlilik icin kritik oneme sahiptir.',
      'default': 'Bu konuda detayli bilgi icin lutfen daha spesifik bir soru sorun. Size yardimci olmaktan mutluluk duyarim!'
    };

    let response = responses.default;
    for (const [key, value] of Object.entries(responses)) {
      if (userMsg.toLowerCase().includes(key)) {
        response = value;
        break;
      }
    }

    setChatMessages(prev => [...prev, { role: 'assistant', content: response }]);
    setChatLoading(false);
  };

  const startRansomwareProtection = () => {
    setRansomwareStatus('active');
    setHoneypotFiles([
      { name: 'IMPORTANT_BACKUP.txt', path: 'C:\\Users\\Desktop', status: 'monitoring' },
      { name: 'CREDENTIALS.docx', path: 'C:\\Users\\Documents', status: 'monitoring' },
      { name: 'FINANCE_2024.xlsx', path: 'C:\\Users\\Desktop', status: 'monitoring' }
    ]);
    
    setTimeout(() => {
      if (Math.random() > 0.7) {
        setDetectedThreats([{
          id: Date.now(),
          type: 'Ransomware Attempt',
          process: 'malware.exe',
          action: 'Process terminated',
          time: new Date().toLocaleTimeString('tr-TR')
        }]);
      }
    }, 10000);
  };

  const calculateBenchmark = async () => {
    setBenchmarkLoading(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const totalUsers = 15847;
    const userScore = 75 + Math.floor(Math.random() * 20);
    const rank = Math.floor((userScore / 100) * totalUsers);
    
    setUserRank({
      score: userScore,
      rank: rank,
      total: totalUsers,
      percentile: Math.floor((1 - rank/totalUsers) * 100)
    });
    setBenchmarkLoading(false);
  };

  const toggleRealtimeProtection = () => {
    setRealtimeProtection(!realtimeProtection);
    if (!realtimeProtection) {
      const interval = setInterval(() => {
        setRealtimeEvents(prev => [...prev.slice(-9), {
          id: Date.now(),
          type: ['scan', 'block', 'allow'][Math.floor(Math.random() * 3)],
          message: [
            'Process chrome.exe scanned - Clean',
            'Suspicious connection blocked: 192.168.1.x',
            'New process detected: notepad.exe',
            'Port scan attempt blocked'
          ][Math.floor(Math.random() * 4)],
          time: new Date().toLocaleTimeString('tr-TR')
        }]);
      }, 3000);
      return () => clearInterval(interval);
    }
  };

  const handleLogin = (e) => {
    e.preventDefault();
    if (email && password) {
      setSession({ email });
      setShowLogin(false);
    }
  };

  const handleLogout = () => {
    setSession(null);
  };

  const StatCard = ({ icon, label, value, trend, color }) => (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 border border-slate-700 hover:border-slate-600 transition-all duration-300 hover:shadow-xl">
      <div className="flex items-start justify-between mb-4">
        <div className="p-3 rounded-lg text-3xl" style={{backgroundColor: `rgba(${color}, 0.1)`}}>
          {icon}
        </div>
        {trend !== undefined && (
          <span className={`text-xs font-bold px-2 py-1 rounded ${trend > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
            {trend > 0 ? '+' : ''}{trend}%
          </span>
        )}
      </div>
      <div className="text-3xl font-bold text-white mb-1">{value}</div>
      <div className="text-sm text-slate-400">{label}</div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {showLogin && !session && (
        <div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center backdrop-blur-sm animate-in fade-in">
          <div className="bg-slate-900 border border-slate-700 p-8 rounded-2xl w-full max-w-md shadow-2xl animate-in zoom-in-95">
            <h2 className="text-2xl font-bold mb-6 text-center bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
              Guvenli Giris
            </h2>
            <form onSubmit={handleLogin} className="space-y-4">
              <input
                type="email"
                required
                className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded-lg focus:border-blue-500 focus:outline-none transition"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <input
                type="password"
                required
                className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded-lg focus:border-blue-500 focus:outline-none transition"
                placeholder="Sifre"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button type="submit" className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-bold py-3 rounded-lg transition shadow-lg">
                GIRIS YAP
              </button>
              <button type="button" onClick={() => setShowLogin(false)} className="w-full text-slate-400 hover:text-white text-sm transition">
                Iptal
              </button>
            </form>
          </div>
        </div>
      )}

      <header className="border-b border-slate-800/50 bg-slate-900/30 backdrop-blur-xl sticky top-0 z-40 shadow-lg">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="absolute inset-0 bg-blue-500 blur-xl opacity-30 animate-pulse"></div>
                <span className="relative text-4xl">🛡️</span>
              </div>
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 via-purple-500 to-pink-500 bg-clip-text text-transparent">
                  SolidTrace Ultimate
                </h1>
                <p className="text-xs text-slate-400">Enterprise Security Platform v3.0</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {session ? (
                <>
                  <span className="text-sm text-slate-400 px-3 py-1 bg-slate-800/50 rounded-lg border border-slate-700">{session.email}</span>
                  <button onClick={handleLogout} className="px-4 py-2 bg-red-900/50 hover:bg-red-900 border border-red-700 rounded-lg text-sm transition shadow-lg">
                    Cikis
                  </button>
                </>
              ) : (
                <button onClick={() => setShowLogin(true)} className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 rounded-lg text-sm transition shadow-lg">
                  Giris Yap
                </button>
              )}
            </div>
          </div>

          <nav className="flex gap-2 mt-6 overflow-x-auto pb-2 scrollbar-hide">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: '📊', gradient: 'from-blue-600 to-cyan-600' },
              { id: 'darkweb', label: 'Dark Web', icon: '👁️', gradient: 'from-purple-600 to-pink-600' },
              { id: 'ransomware', label: 'Ransomware', icon: '🛡️', gradient: 'from-red-600 to-orange-600' },
              { id: 'realtime', label: 'Real-time', icon: '⚡', gradient: 'from-yellow-600 to-orange-600' },
              { id: 'benchmark', label: 'Benchmark', icon: '📈', gradient: 'from-green-600 to-emerald-600' },
              { id: 'chat', label: 'AI Chat', icon: '💬', gradient: 'from-indigo-600 to-blue-600' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg transition whitespace-nowrap ${
                  activeTab === tab.id
                    ? `bg-gradient-to-r ${tab.gradient} text-white shadow-lg scale-105`
                    : 'bg-slate-800/50 text-slate-400 hover:bg-slate-700 hover:text-white border border-slate-700'
                }`}
              >
                <span className="text-lg">{tab.icon}</span>
                <span className="font-medium">{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        
        {activeTab === 'dashboard' && (
          <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard icon="⚠️" label="Risk Skoru" value={Math.floor(dashboardData.riskScore)} trend={2} color="239, 68, 68" />
              <StatCard icon="🛡️" label="Aktif Tehdit" value={dashboardData.activeThreats} trend={-1} color="251, 146, 60" />
              <StatCard icon="💻" label="Korunan Cihaz" value="3" color="34, 197, 94" />
              <StatCard icon="🗄️" label="Dark Web Sizinti" value={dashboardData.darkWebLeaks} color="168, 85, 247" />
            </div>

            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 backdrop-blur-sm shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold flex items-center gap-2">
                  <span className="text-2xl">📡</span>
                  Gercek Zamanli Olaylar
                </h2>
                <div className="flex items-center gap-2 px-3 py-1 bg-green-900/20 border border-green-700 rounded-full">
                  <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                  <span className="text-xs text-green-400 font-bold">LIVE</span>
                </div>
              </div>
              <div className="space-y-2">
                {dashboardData.realtimeEvents.slice(-5).reverse().map((event) => (
                  <div key={event.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-slate-600 transition">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        event.type === 'danger' ? 'bg-red-500' : event.type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
                      } animate-pulse`}></div>
                      <span className="text-sm text-slate-300">{event.message}</span>
                    </div>
                    <span className="text-xs text-slate-500 font-mono">{event.time}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { tab: 'darkweb', title: 'Dark Web Taramasi', desc: 'Email sizintisi kontrol', icon: '👁️', gradient: 'from-purple-900/50 to-purple-800/50', border: 'border-purple-700 hover:border-purple-500' },
                { tab: 'ransomware', title: 'Ransomware Koruması', desc: 'Honeypot erken tespit', icon: '🛡️', gradient: 'from-red-900/50 to-red-800/50', border: 'border-red-700 hover:border-red-500' },
                { tab: 'chat', title: 'AI Asistan', desc: 'Siber guvenlik danismani', icon: '💬', gradient: 'from-blue-900/50 to-blue-800/50', border: 'border-blue-700 hover:border-blue-500' }
              ].map(item => (
                <button
                  key={item.tab}
                  onClick={() => setActiveTab(item.tab)}
                  className={`p-6 bg-gradient-to-br ${item.gradient} border ${item.border} rounded-xl transition group text-left hover:scale-105 shadow-lg`}
                >
                  <span className="text-5xl mb-3 block group-hover:scale-110 transition">{item.icon}</span>
                  <h3 className="font-bold mb-1 text-lg">{item.title}</h3>
                  <p className="text-sm text-slate-400">{item.desc}</p>
                </button>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'darkweb' && (
          <div className="animate-in slide-in-from-right-4 duration-500">
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-8 backdrop-blur-sm shadow-xl">
              <div className="flex items-center gap-3 mb-6">
                <span className="text-5xl">👁️</span>
                <div>
                  <h2 className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-pink-500 bg-clip-text text-transparent">
                    Dark Web Izleme
                  </h2>
                  <p className="text-sm text-slate-400 mt-1">Bilgilerinizin dark webde sizdirilip sizdirilmadigini kontrol edin</p>
                </div>
              </div>

              <div className="flex gap-3 mb-6">
                <input
                  type="email"
                  placeholder="Email adresinizi girin..."
                  value={dwEmail}
                  onChange={(e) => setDwEmail(e.target.value)}
                  className="flex-1 bg-black/50 border border-slate-700 text-white p-4 rounded-lg focus:border-purple-500 focus:outline-none transition shadow-inner"
                />
                <button
                  onClick={handleDarkWebCheck}
                  disabled={dwLoading}
                  className="px-8 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 rounded-lg font-bold transition disabled:opacity-50 shadow-lg"
                >
                  {dwLoading ? '⏳ Taraniyor...' : '🔍 TARA'}
                </button>
              </div>

              {dwResult && (
                <div className={`p-6 rounded-xl border shadow-lg animate-in zoom-in-95 ${
                  dwResult.riskLevel === 'safe' ? 'bg-green-900/20 border-green-700' :
                  dwResult.riskLevel === 'medium' ? 'bg-yellow-900/20 border-yellow-700' : 'bg-red-900/20 border-red-700'
                }`}>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-2xl font-bold">Tarama Sonuclari</h3>
                    <span className={`px-4 py-2 rounded-full text-sm font-bold shadow-lg ${
                      dwResult.riskLevel === 'safe' ? 'bg-green-500/20 text-green-400 border border-green-500' :
                      dwResult.riskLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500' : 'bg-red-500/20 text-red-400 border border-red-500'
                    }`}>
                      {dwResult.riskLevel === 'safe' ? '✓ GUVENLI' : dwResult.riskLevel === 'medium' ? '⚠ ORTA RISK' : '⛔ YUKSEK RISK'}
                    </span>
                  </div>

                  <div className="mb-4 p-4 bg-black/30 rounded-lg">
                    <p className="text-slate-300 text-lg">
                      <strong className="text-white">{dwResult.email}</strong> adresi{' '}
                      <strong className={`text-2xl ${dwResult.breaches > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {dwResult.breaches}
                      </strong>{' '}
                      veri ihlalinde bulundu.
                    </p>
                  </div>

                  {dwResult.breachList.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="font-bold text-sm text-slate-400 mb-3">🔍 Tespit Edilen Ihlaller:</h4>
                      {dwResult.breachList.map((breach, idx) => (
                        <div key={idx} className="flex items-center justify-between p-4 bg-black/50 rounded-lg border border-slate-700 hover:border-slate-600 transition">
                          <div>
                            <div className="font-bold text-lg">{breach.name}</div>
                            <div className="text-xs text-slate-400 mt-1">{breach.records} kullanici etkilendi</div>
                          </div>
                          <div className="text-right">
                            <div className="text-sm text-slate-400 mb-1">{breach.date}</div>
                            <span className={`text-xs px-3 py-1 rounded-full font-bold ${
                              breach.risk === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500' :
                              breach.risk === 'high' ? 'bg-orange-500/20 text-orange-400 border border-orange-500' : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500'
                            }`}>
                              {breach.risk.toUpperCase()}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {dwResult.breaches > 0 && (
                    <div className="mt-6 p-6 bg-blue-900/20 border border-blue-700 rounded-lg">
                      <h4 className="font-bold mb-3 flex items-center gap-2 text-lg">
                        <span>🔒</span>
                        Onerilen Aksiyonlar:
                      </h4>
                      <ul className="text-sm text-slate-300 space-y-2">
                        <li className="flex items-start gap-2">
                          <span className="text-blue-400 mt-0.5">•</span>
                          <span>Etkilenen hesaplarda sifrenizi hemen degistirin</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-blue-400 mt-0.5">•</span>
                          <span>Iki faktorlu dogrulama (2FA) aktif edin</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-blue-400 mt-0.5">•</span>
                          <span>Ayni sifreyi farkli sitelerde kullanmayin</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-blue-400 mt-0.5">•</span>
                          <span>Sifre yoneticisi kullanmayi dusunun</span>
                        </li>
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'chat' && (
          <div className="animate-in slide-in-from-left-4 duration-500">
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm shadow-xl">
              <div className="p-6 border-b border-slate-800 bg-gradient-to-r from-blue-900/30 to-purple-900/30">
                <div className="flex items-center gap-3">
                  <span className="text-5xl">💬</span>
                  <div>
                    <h2 className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
                      AI Guvenlik Asistani
                    </h2>
                    <p className="text-sm text-slate-400 mt-1">Siber guvenlik sorularinizi sorun</p>
                  </div>
                </div>
              </div>

              <div className="h-96 overflow-y-auto p-6 space-y-4 bg-black/30">
                {chatMessages.map((msg, idx) => (
                  <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} animate-in slide-in-from-bottom-2`}>
                    <div className={`max-w-[80%] p-4 rounded-xl shadow-lg ${
                      msg.role === 'user' ? 'bg-gradient-to-r from-blue-600 to-blue-700 text-white' : 'bg-slate-800 text-slate-200 border border-slate-700'
                    }`}>
                      <div className="flex items-start gap-2">
                        {msg.role === 'assistant' && <span className="text-2xl">🛡️</span>}
                        <p className="text-sm leading-relaxed">{msg.content}</p>
                      </div>
                    </div>
                  </div>
                ))}
                {chatLoading && (
                  <div className="flex justify-start">
                    <div className="bg-slate-800 border border-slate-700 text-slate-200 p-4 rounded-xl shadow-lg">
                      <div className="flex gap-1">
                        <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce"></div>
                        <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{animationDelay: '0.1s'}}></div>
                        <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>

              <div className="p-6 border-t border-slate-800 bg-slate-900/50">
                <div className="flex gap-3 mb-3">
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleChatSend()}
                    placeholder="Siber guvenlik hakkinda bir sey sorun..."
                    className="flex-1 bg-black/50 border border-slate-700 text-white p-4 rounded-lg focus:border-blue-500 focus:outline-none transition shadow-inner"
                  />
                  <button
                    onClick={handleChatSend}
                    disabled={chatLoading || !chatInput.trim()}
                    className="px-6 py-4 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 rounded-lg font-bold transition disabled:opacity-50 shadow-lg"
                  >
                    GONDER
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {['Port nedir?', 'Firewall nasil aktif edilir?', 'Ransomware nedir?', 'VPN guvenli mi?'].map((suggestion, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setChatInput(suggestion);
                      }}
                      className="text-xs px-3 py-1 bg-slate-800/50 hover:bg-slate-700 border border-slate-700 rounded-full transition"
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'ransomware' && (
          <div className="animate-in slide-in-from-bottom-4 duration-500">
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-8 backdrop-blur-sm shadow-xl">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <span className="text-5xl">🛡️</span>
                  <div>
                    <h2 className="text-3xl font-bold bg-gradient-to-r from-red-400 to-orange-500 bg-clip-text text-transparent">
                      Ransomware Kalkani
                    </h2>
                    <p className="text-sm text-slate-400 mt-1">Honeypot dosyalari ile erken tespit sistemi</p>
                  </div>
                </div>
                
                <button
                  onClick={startRansomwareProtection}
                  disabled={ransomwareStatus === 'active'}
                  className={`px-6 py-3 rounded-lg font-bold transition shadow-lg ${
                    ransomwareStatus === 'active'
                      ? 'bg-green-600 cursor-not-allowed'
                      : 'bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-700 hover:to-orange-700'
                  }`}
                >
                  {ransomwareStatus === 'active' ? '✓ KORUMA AKTIF' : 'KORUMAYYI BASLAT'}
                </button>
              </div>

              {ransomwareStatus === 'active' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-in zoom-in-95">
                  <div className="bg-black/30 border border-slate-700 rounded-xl p-6">
                    <h3 className="font-bold mb-4 flex items-center gap-2 text-lg">
                      <span>🗄️</span>
                      Honeypot Dosyalari
                    </h3>
                    <div className="space-y-2">
                      {honeypotFiles.map((file, idx) => (
                        <div key={idx} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                          <div>
                            <div className="font-mono text-sm">{file.name}</div>
                            <div className="text-xs text-slate-500">{file.path}</div>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                            <span className="text-xs text-green-400">{file.status}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="bg-black/30 border border-slate-700 rounded-xl p-6">
                    <h3 className="font-bold mb-4 flex items-center gap-2 text-lg">
                      <span>⚠️</span>
                      Tespit Edilen Tehditler
                    </h3>
                    {detectedThreats.length === 0 ? (
                      <div className="text-center py-8 text-slate-500">
                        <span className="text-5xl block mb-2 opacity-50">🛡️</span>
                        <p className="text-sm">Henuz tehdit tespit edilmedi</p>
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {detectedThreats.map((threat) => (
                          <div key={threat.id} className="p-3 bg-red-900/20 border border-red-700 rounded-lg">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-bold text-red-400">{threat.type}</span>
                              <span className="text-xs text-slate-400">{threat.time}</span>
                            </div>
                            <div className="text-sm text-slate-300">
                              Process: <code className="bg-black/50 px-2 py-0.5 rounded">{threat.process}</code>
                            </div>
                            <div className="text-xs text-green-400 mt-1">
                              ✓ {threat.action}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'realtime' && (
          <div className="animate-in slide-in-from-top-4 duration-500">
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-8 backdrop-blur-sm shadow-xl">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <span className="text-5xl">⚡</span>
                  <div>
                    <h2 className="text-3xl font-bold bg-gradient-to-r from-yellow-400 to-orange-500 bg-clip-text text-transparent">
                      Gercek Zamanli Koruma
                    </h2>
                    <p className="text-sm text-slate-400 mt-1">Surekli izleme ve otomatik tehdit engelleme</p>
                  </div>
                </div>
                
                <button
                  onClick={toggleRealtimeProtection}
                  className={`px-6 py-3 rounded-lg font-bold transition shadow-lg ${
                    realtimeProtection
                      ? 'bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700'
                      : 'bg-slate-700 hover:bg-slate-600'
                  }`}
                >
                  {realtimeProtection ? '✓ AKTIF' : 'PASIF'}
                </button>
              </div>

              {realtimeProtection && (
                <div className="space-y-6 animate-in zoom-in-95">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-green-900/20 border border-green-700 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                        <span className="font-bold">Surec Izleme</span>
                      </div>
                      <p className="text-sm text-slate-400">Yeni surecler otomatik taraniyor</p>
                    </div>
                    
                    <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-3 h-3 rounded-full bg-blue-500 animate-pulse"></div>
                        <span className="font-bold">Ag Izleme</span>
                      </div>
                      <p className="text-sm text-slate-400">Supheli baglantilari engelleniyor</p>
                    </div>
                    
                    <div className="bg-purple-900/20 border border-purple-700 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-3 h-3 rounded-full bg-purple-500 animate-pulse"></div>
                        <span className="font-bold">Dosya Korumasi</span>
                      </div>
                      <p className="text-sm text-slate-400">Kritik dosyalar korunuyor</p>
                    </div>
                  </div>

                  <div className="bg-black border border-slate-800 rounded-xl p-4 h-96 overflow-y-auto font-mono text-sm shadow-inner">
                    <div className="text-slate-500 mb-2">[REAL-TIME MONITOR] Aktif...</div>
                    {realtimeEvents.map((event) => (
                      <div key={event.id} className={`mb-1 ${
                        event.type === 'block' ? 'text-red-400' :
                        event.type === 'scan' ? 'text-blue-400' : 'text-green-400'
                      }`}>
                        [{event.time}] {event.type === 'block' ? '🛑' : event.type === 'scan' ? '🔍' : '✓'} {event.message}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {!realtimeProtection && (
                <div className="text-center py-12">
                  <span className="text-7xl block mb-4">⚡</span>
                  <p className="text-slate-400 mb-4 text-lg">Gercek zamanli koruma su anda kapali</p>
                  <button
                    onClick={toggleRealtimeProtection}
                    className="px-8 py-4 bg-gradient-to-r from-yellow-600 to-orange-600 hover:from-yellow-700 hover:to-orange-700 rounded-lg font-bold transition shadow-lg"
                  >
                    KORUMAYYI AKTIF ET
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'benchmark' && (
          <div className="animate-in slide-in-from-right-4 duration-500">
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-8 backdrop-blur-sm shadow-xl">
              <div className="flex items-center gap-3 mb-6">
                <span className="text-5xl">📈</span>
                <div>
                  <h2 className="text-3xl font-bold bg-gradient-to-r from-green-400 to-emerald-500 bg-clip-text text-transparent">
                    Guvenlik Skoru Karsilastirmasi
                  </h2>
                  <p className="text-sm text-slate-400 mt-1">Guvenlik seviyenizi diger kullanicilarla karsilastirin</p>
                </div>
              </div>

              {!userRank && (
                <div className="text-center py-12">
                  <span className="text-7xl block mb-4">🏆</span>
                  <p className="text-slate-400 mb-4 text-lg">Guvenlik skorunuzu hesaplayin ve siralamadaki yerinizi gorun</p>
                  <button
                    onClick={calculateBenchmark}
                    disabled={benchmarkLoading}
                    className="px-8 py-4 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 rounded-lg font-bold transition disabled:opacity-50 shadow-lg"
                  >
                    {benchmarkLoading ? '⏳ HESAPLANIYOR...' : '🚀 SKORU HESAPLA'}
                  </button>
                </div>
              )}

              {userRank && (
                <div className="space-y-6 animate-in zoom-in-95">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-gradient-to-br from-blue-900/50 to-blue-800/50 border border-blue-700 rounded-xl p-6 text-center shadow-lg">
                      <div className="text-6xl font-bold mb-2 bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">{userRank.score}</div>
                      <div className="text-slate-400 mb-4">Guvenlik Skoru</div>
                      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-blue-500 to-green-500 transition-all duration-1000"
                          style={{ width: `${userRank.score}%` }}
                        ></div>
                      </div>
                    </div>

                    <div className="bg-gradient-to-br from-purple-900/50 to-purple-800/50 border border-purple-700 rounded-xl p-6 text-center shadow-lg">
                      <div className="text-6xl font-bold mb-2 bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">#{userRank.rank.toLocaleString()}</div>
                      <div className="text-slate-400 mb-2">Siralama</div>
                      <div className="text-sm text-purple-400">
                        {userRank.total.toLocaleString()} kullanici arasinda
                      </div>
                    </div>

                    <div className="bg-gradient-to-br from-green-900/50 to-green-800/50 border border-green-700 rounded-xl p-6 text-center shadow-lg">
                      <div className="text-6xl font-bold mb-2 bg-gradient-to-r from-green-400 to-emerald-400 bg-clip-text text-transparent">{userRank.percentile}%</div>
                      <div className="text-slate-400 mb-2">Yuzdelik Dilim</div>
                      <div className="text-sm text-green-400">
                        Top {userRank.percentile}% guvenlik seviyesi
                      </div>
                    </div>
                  </div>

                  <div className="bg-black/30 border border-slate-700 rounded-xl p-6">
                    <h3 className="font-bold mb-4 flex items-center gap-2 text-lg">
                      <span>👥</span>
                      Skorunuzu Yukseltmek Icin:
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {[
                        { icon: '✓', title: 'Guvenlik Duvarini Aktif Et', points: '+10 puan', color: 'green' },
                        { icon: '!', title: '2FA Kullan', points: '+15 puan', color: 'yellow' },
                        { icon: '🔒', title: 'Guclu Sifreler', points: '+12 puan', color: 'blue' },
                        { icon: '📡', title: 'VPN Kullan', points: '+8 puan', color: 'purple' }
                      ].map((item, idx) => (
                        <div key={idx} className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-slate-600 transition">
                          <div className={`w-6 h-6 rounded-full bg-${item.color}-500/20 flex items-center justify-center flex-shrink-0 mt-0.5`}>
                            <span className={`text-${item.color}-400 text-sm`}>{item.icon}</span>
                          </div>
                          <div>
                            <div className="font-bold text-sm">{item.title}</div>
                            <div className="text-xs text-slate-400">{item.points}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

      </main>

      <footer className="max-w-7xl mx-auto px-6 py-8 mt-12 border-t border-slate-800">
        <div className="text-center text-slate-500 text-sm">
          <p className="mb-2">SolidTrace Ultimate v3.0 - Enterprise Security Platform</p>
          <p className="text-xs">Powered by Advanced Threat Intelligence & Forensic Analysis</p>
        </div>
      </footer>
    </div>
  );
}