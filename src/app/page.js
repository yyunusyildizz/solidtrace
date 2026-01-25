import { useState, useEffect, useRef } from 'react';
import { Shield, AlertTriangle, Activity, Database, MessageSquare, Lock, Zap, Search, TrendingUp, Users, Award, Eye, Terminal, Globe, Cpu, HardDrive, Wifi } from 'lucide-react';

export default function SolidTraceUltimate() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [session, setSession] = useState(null);
  const [showLogin, setShowLogin] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  // Dashboard States
  const [dashboardData, setDashboardData] = useState({
    riskScore: 0,
    activeThreats: 0,
    protectedDevices: 0,
    darkWebLeaks: 0,
    realtimeEvents: []
  });

  // Dark Web Monitor States
  const [dwEmail, setDwEmail] = useState('');
  const [dwLoading, setDwLoading] = useState(false);
  const [dwResult, setDwResult] = useState(null);

  // AI Chat States
  const [chatMessages, setChatMessages] = useState([
    { role: 'assistant', content: 'Merhaba! Siber güvenlik konusunda size nasıl yardımcı olabilirim?' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef(null);

  // Ransomware Monitor States
  const [ransomwareStatus, setRansomwareStatus] = useState('inactive');
  const [honeypotFiles, setHoneypotFiles] = useState([]);
  const [detectedThreats, setDetectedThreats] = useState([]);

  // Benchmark States
  const [userRank, setUserRank] = useState(null);
  const [benchmarkLoading, setBenchmarkLoading] = useState(false);

  // Real-time Protection States
  const [realtimeProtection, setRealtimeProtection] = useState(false);
  const [realtimeEvents, setRealtimeEvents] = useState([]);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages]);

  // Simulated Dashboard Data
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
              'Yeni port taraması tamamlandı',
              'Şüpheli ağ trafiği tespit edildi',
              'Sistem güncellemesi mevcut',
              'Güvenlik duvarı etkin'
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
    
    // Simulate API call to haveibeenpwned
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
      'port': 'Port açıklığı, bilgisayarınızın belirli bir servisi internete sunduğu anlamına gelir. Örneğin Port 3389 RDP için kullanılır ve dışarıdan erişime açıksa güvenlik riski oluşturur.',
      'firewall': 'Güvenlik duvarı (Firewall), gelen ve giden ağ trafiğini filtreler. Kapalı olması, bilgisayarınızın saldırılara açık olduğu anlamına gelir.',
      'ransomware': 'Ransomware, dosyalarınızı şifreleyen ve fidye talep eden kötü amaçlı yazılımdır. Honeypot sistemi ile erken tespit edebiliriz.',
      'dark web': 'Dark Web, internetin derinliklerinde şifrelerin ve kişisel bilgilerin satıldığı yerdir. Düzenli kontrol önemlidir.',
      'vpn': 'VPN, internet trafiğinizi şifreler ve IP adresinizi gizler. Gizlilik için kritik öneme sahiptir.',
      'default': 'Bu konuda detaylı bilgi için lütfen daha spesifik bir soru sorun. Size yardımcı olmaktan mutluluk duyarım!'
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

  const StatCard = ({ icon: Icon, label, value, trend, color }) => (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-xl p-6 border border-slate-700 hover:border-slate-600 transition-all duration-300 hover:shadow-xl">
      <div className="flex items-start justify-between mb-4">
        <div className={`p-3 rounded-lg bg-${color}-500/10`}>
          <Icon className={`w-6 h-6 text-${color}-400`} />
        </div>
        {trend && (
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
    <div className="min-h-screen bg-black text-white">
      {/* Login Modal */}
      {showLogin && !session && (
        <div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 p-8 rounded-2xl w-full max-w-md">
            <h2 className="text-2xl font-bold mb-6 text-center">Güvenli Giriş</h2>
            <form onSubmit={handleLogin} className="space-y-4">
              <input
                type="email"
                required
                className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded-lg focus:border-blue-500 focus:outline-none"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <input
                type="password"
                required
                className="w-full bg-black/50 border border-slate-700 text-white p-3 rounded-lg focus:border-blue-500 focus:outline-none"
                placeholder="Şifre"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg transition"
              >
                GİRİŞ YAP
              </button>
              <button
                type="button"
                onClick={() => setShowLogin(false)}
                className="w-full text-slate-400 hover:text-white text-sm"
              >
                İptal
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-500" />
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
                  SolidTrace Ultimate
                </h1>
                <p className="text-xs text-slate-400">Enterprise Security Platform</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {session ? (
                <>
                  <span className="text-sm text-slate-400">{session.email}</span>
                  <button
                    onClick={handleLogout}
                    className="px-4 py-2 bg-red-900/50 hover:bg-red-900 border border-red-700 rounded-lg text-sm transition"
                  >
                    Çıkış
                  </button>
                </>
              ) : (
                <button
                  onClick={() => setShowLogin(true)}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm transition"
                >
                  Giriş Yap
                </button>
              )}
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex gap-2 mt-6 overflow-x-auto pb-2">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: Activity },
              { id: 'darkweb', label: 'Dark Web Monitor', icon: Eye },
              { id: 'ransomware', label: 'Ransomware Shield', icon: Shield },
              { id: 'realtime', label: 'Real-time Protection', icon: Zap },
              { id: 'benchmark', label: 'Benchmark', icon: TrendingUp },
              { id: 'chat', label: 'AI Assistant', icon: MessageSquare }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg transition whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-white'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        
        {/* DASHBOARD */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard icon={AlertTriangle} label="Risk Skoru" value={Math.floor(dashboardData.riskScore)} trend={2} color="red" />
              <StatCard icon={Shield} label="Aktif Tehdit" value={dashboardData.activeThreats} trend={-1} color="orange" />
              <StatCard icon={Cpu} label="Korunan Cihaz" value="3" color="green" />
              <StatCard icon={Database} label="Dark Web Sızıntı" value={dashboardData.darkWebLeaks} color="purple" />
            </div>

            {/* Real-time Events */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold flex items-center gap-2">
                  <Activity className="w-5 h-5 text-blue-400" />
                  Gerçek Zamanlı Olaylar
                </h2>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                  <span className="text-xs text-green-400">LIVE</span>
                </div>
              </div>
              <div className="space-y-2">
                {dashboardData.realtimeEvents.slice(-5).reverse().map((event) => (
                  <div key={event.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        event.type === 'danger' ? 'bg-red-500' :
                        event.type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
                      }`}></div>
                      <span className="text-sm text-slate-300">{event.message}</span>
                    </div>
                    <span className="text-xs text-slate-500">{event.time}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Quick Actions */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <button
                onClick={() => setActiveTab('darkweb')}
                className="p-6 bg-gradient-to-br from-purple-900/50 to-purple-800/50 border border-purple-700 rounded-xl hover:border-purple-500 transition group"
              >
                <Eye className="w-8 h-8 text-purple-400 mb-3 group-hover:scale-110 transition" />
                <h3 className="font-bold mb-1">Dark Web Taraması</h3>
                <p className="text-sm text-slate-400">Email sızıntılarını kontrol et</p>
              </button>
              
              <button
                onClick={() => setActiveTab('ransomware')}
                className="p-6 bg-gradient-to-br from-red-900/50 to-red-800/50 border border-red-700 rounded-xl hover:border-red-500 transition group"
              >
                <Shield className="w-8 h-8 text-red-400 mb-3 group-hover:scale-110 transition" />
                <h3 className="font-bold mb-1">Ransomware Koruması</h3>
                <p className="text-sm text-slate-400">Honeypot sistemi aktif et</p>
              </button>
              
              <button
                onClick={() => setActiveTab('chat')}
                className="p-6 bg-gradient-to-br from-blue-900/50 to-blue-800/50 border border-blue-700 rounded-xl hover:border-blue-500 transition group"
              >
                <MessageSquare className="w-8 h-8 text-blue-400 mb-3 group-hover:scale-110 transition" />
                <h3 className="font-bold mb-1">AI Asistan</h3>
                <p className="text-sm text-slate-400">Siber güvenlik danışmanın</p>
              </button>
            </div>
          </div>
        )}

        {/* DARK WEB MONITOR */}
        {activeTab === 'darkweb' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
              <div className="flex items-center gap-3 mb-6">
                <Eye className="w-8 h-8 text-purple-400" />
                <div>
                  <h2 className="text-2xl font-bold">Dark Web İzleme</h2>
                  <p className="text-sm text-slate-400">Bilgilerinizin dark web'de sızdırılıp sızdırılmadığını kontrol edin</p>
                </div>
              </div>

              <div className="flex gap-3 mb-6">
                <input
                  type="email"
                  placeholder="Email adresinizi girin..."
                  value={dwEmail}
                  onChange={(e) => setDwEmail(e.target.value)}
                  className="flex-1 bg-black/50 border border-slate-700 text-white p-4 rounded-lg focus:border-purple-500 focus:outline-none"
                />
                <button
                  onClick={handleDarkWebCheck}
                  disabled={dwLoading}
                  className="px-8 py-4 bg-purple-600 hover:bg-purple-700 rounded-lg font-bold transition disabled:opacity-50"
                >
                  {dwLoading ? 'Taranıyor...' : 'TARA'}
                </button>
              </div>

              {dwResult && (
                <div className={`p-6 rounded-xl border ${
                  dwResult.riskLevel === 'safe' ? 'bg-green-900/20 border-green-700' :
                  dwResult.riskLevel === 'medium' ? 'bg-yellow-900/20 border-yellow-700' :
                  'bg-red-900/20 border-red-700'
                }`}>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-xl font-bold">Tarama Sonuçları</h3>
                    <span className={`px-3 py-1 rounded-full text-sm font-bold ${
                      dwResult.riskLevel === 'safe' ? 'bg-green-500/20 text-green-400' :
                      dwResult.riskLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-red-500/20 text-red-400'
                    }`}>
                      {dwResult.riskLevel === 'safe' ? 'GÜVENLİ' :
                       dwResult.riskLevel === 'medium' ? 'ORTA RİSK' : 'YÜKSEK RİSK'}
                    </span>
                  </div>

                  <div className="mb-4">
                    <p className="text-slate-300">
                      <strong>{dwResult.email}</strong> adresi{' '}
                      <strong className={dwResult.breaches > 0 ? 'text-red-400' : 'text-green-400'}>
                        {dwResult.breaches}
                      </strong>{' '}
                      veri ihlalinde bulundu.
                    </p>
                  </div>

                  {dwResult.breachList.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="font-bold text-sm text-slate-400 mb-2">Tespit Edilen İhlaller:</h4>
                      {dwResult.breachList.map((breach, idx) => (
                        <div key={idx} className="flex items-center justify-between p-3 bg-black/30 rounded-lg">
                          <div>
                            <div className="font-bold">{breach.name}</div>
                            <div className="text-xs text-slate-400">{breach.records} kullanıcı etkilendi</div>
                          </div>
                          <div className="text-right">
                            <div className="text-sm text-slate-400">{breach.date}</div>
                            <span className={`text-xs px-2 py-0.5 rounded ${
                              breach.risk === 'critical' ? 'bg-red-500/20 text-red-400' :
                              breach.risk === 'high' ? 'bg-orange-500/20 text-orange-400' :
                              'bg-yellow-500/20 text-yellow-400'
                            }`}>
                              {breach.risk.toUpperCase()}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {dwResult.breaches > 0 && (
                    <div className="mt-4 p-4 bg-blue-900/20 border border-blue-700 rounded-lg">
                      <h4 className="font-bold mb-2 flex items-center gap-2">
                        <Lock className="w-4 h-4" />
                        Önerilen Aksiyonlar:
                      </h4>
                      <ul className="text-sm text-slate-300 space-y-1">
                        <li>• Etkilenen hesaplarda şifrenizi hemen değiştirin</li>
                        <li>• İki faktörlü doğrulama (2FA) aktif edin</li>
                        <li>• Aynı şifreyi farklı sitelerde kullanmayın</li>
                        <li>• Şifre yöneticisi kullanmayı düşünün</li>
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* RANSOMWARE PROTECTION */}
        {activeTab === 'ransomware' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <Shield className="w-8 h-8 text-red-400" />
                  <div>
                    <h2 className="text-2xl font-bold">Ransomware Kalkanı</h2>
                    <p className="text-sm text-slate-400">Honeypot dosyaları ile erken tespit sistemi</p>
                  </div>
                </div>
                
                <button
                  onClick={startRansomwareProtection}
                  disabled={ransomwareStatus === 'active'}
                  className={`px-6 py-3 rounded-lg font-bold transition ${
                    ransomwareStatus === 'active'
                      ? 'bg-green-600 cursor-not-allowed'
                      : 'bg-red-600 hover:bg-red-700'
                  }`}
                >
                  {ransomwareStatus === 'active' ? '✓ KORUMA AKTİF' : 'KORUMAYYI BAŞLAT'}
                </button>
              </div>

              {ransomwareStatus === 'active' && (
                <>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div className="bg-black/30 border border-slate-700 rounded-xl p-6">
                      <h3 className="font-bold mb-4 flex items-center gap-2">
                        <Database className="w-5 h-5 text-blue-400" />
                        Honeypot Dosyaları
                      </h3>
                      <div className="space-y-2">
                        {honeypotFiles.map((file, idx) => (
                          <div key={idx} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
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
                      <h3 className="font-bold mb-4 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                        Tespit Edilen Tehditler
                      </h3>
                      {detectedThreats.length === 0 ? (
                        <div className="text-center py-8 text-slate-500">
                          <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
                          <p className="text-sm">Henüz tehdit tespit edilmedi</p>
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

                  <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
                    <h4 className="font-bold mb-2 flex items-center gap-2">
                      <Zap className="w-4 h-4 text-blue-400" />
                      Nasıl Çalışır?
                    </h4>
                    <p className="text-sm text-slate-300">
                      Sistem kritik dizinlere (Desktop, Documents) tuzak dosyaları yerleştirir. 
                      Eğer bir ransomware bu dosyaları şifrelemeye çalışırsa, anında tespit edilir ve süreç durdurulur.
                    </p>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* REAL-TIME PROTECTION */}
        {activeTab === 'realtime' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <Zap className="w-8 h-8 text-yellow-400" />
                  <div>
                    <h2 className="text-2xl font-bold">Gerçek Zamanlı Koruma</h2>
                    <p className="text-sm text-slate-400">Sürekli izleme ve otomatik tehdit engelleme</p>
                  </div>
                </div>
                
                <button
                  onClick={toggleRealtimeProtection}
                  className={`px-6 py-3 rounded-lg font-bold transition ${
                    realtimeProtection
                      ? 'bg-green-600 hover:bg-green-700'
                      : 'bg-slate-700 hover:bg-slate-600'
                  }`}
                >
                  {realtimeProtection ? '✓ AKTİF' : 'PASİF'}
                </button>
              </div>

              {realtimeProtection && (
                <>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <div className="bg-green-900/20 border border-green-700 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                        <span className="font-bold">Süreç İzleme</span>
                      </div>
                      <p className="text-sm text-slate-400">Yeni süreçler otomatik taranıyor</p>
                    </div>
                    
                    <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-3 h-3 rounded-full bg-blue-500 animate-pulse"></div>
                        <span className="font-bold">Ağ İzleme</span>
                      </div>
                      <p className="text-sm text-slate-400">Şüpheli bağlantılar engelleniyor</p>
                    </div>
                    
                    <div className="bg-purple-900/20 border border-purple-700 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-3 h-3 rounded-full bg-purple-500 animate-pulse"></div>
                        <span className="font-bold">Dosya Koruması</span>
                      </div>
                      <p className="text-sm text-slate-400">Kritik dosyalar korunuyor</p>
                    </div>
                  </div>

                  <div className="bg-black border border-slate-800 rounded-xl p-4 h-96 overflow-y-auto font-mono text-sm">
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
                </>
              )}

              {!realtimeProtection && (
                <div className="text-center py-12">
                  <Zap className="w-16 h-16 mx-auto mb-4 text-slate-600" />
                  <p className="text-slate-400 mb-4">Gerçek zamanlı koruma şu anda kapalı</p>
                  <button
                    onClick={toggleRealtimeProtection}
                    className="px-6 py-3 bg-yellow-600 hover:bg-yellow-700 rounded-lg font-bold transition"
                  >
                    KORUMAYYI AKTİF ET
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* BENCHMARK */}
        {activeTab === 'benchmark' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
              <div className="flex items-center gap-3 mb-6">
                <TrendingUp className="w-8 h-8 text-green-400" />
                <div>
                  <h2 className="text-2xl font-bold">Güvenlik Skoru Karşılaştırması</h2>
                  <p className="text-sm text-slate-400">Güvenlik seviyenizi diğer kullanıcılarla karşılaştırın</p>
                </div>
              </div>

              {!userRank && (
                <div className="text-center py-12">
                  <Award className="w-16 h-16 mx-auto mb-4 text-slate-600" />
                  <p className="text-slate-400 mb-4">Güvenlik skorunuzu hesaplayın ve sıralamadaki yerinizi görün</p>
                  <button
                    onClick={calculateBenchmark}
                    disabled={benchmarkLoading}
                    className="px-8 py-4 bg-green-600 hover:bg-green-700 rounded-lg font-bold transition disabled:opacity-50"
                  >
                    {benchmarkLoading ? 'HESAPLANIYOR...' : 'SKORU HESAPLA'}
                  </button>
                </div>
              )}

              {userRank && (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-gradient-to-br from-blue-900/50 to-blue-800/50 border border-blue-700 rounded-xl p-6 text-center">
                      <div className="text-5xl font-bold mb-2">{userRank.score}</div>
                      <div className="text-slate-400">Güvenlik Skoru</div>
                      <div className="mt-4 h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-blue-500 to-green-500 transition-all duration-1000"
                          style={{ width: `${userRank.score}%` }}
                        ></div>
                      </div>
                    </div>

                    <div className="bg-gradient-to-br from-purple-900/50 to-purple-800/50 border border-purple-700 rounded-xl p-6 text-center">
                      <div className="text-5xl font-bold mb-2">#{userRank.rank.toLocaleString()}</div>
                      <div className="text-slate-400">Sıralama</div>
                      <div className="text-sm text-purple-400 mt-2">
                        {userRank.total.toLocaleString()} kullanıcı arasında
                      </div>
                    </div>

                    <div className="bg-gradient-to-br from-green-900/50 to-green-800/50 border border-green-700 rounded-xl p-6 text-center">
                      <div className="text-5xl font-bold mb-2">{userRank.percentile}%</div>
                      <div className="text-slate-400">Yüzdelik Dilim</div>
                      <div className="text-sm text-green-400 mt-2">
                        Kullanıcıların %{userRank.percentile}'inden daha güvenli
                      </div>
                    </div>
                  </div>

                  <div className="bg-black/30 border border-slate-700 rounded-xl p-6">
                    <h3 className="font-bold mb-4 flex items-center gap-2">
                      <Users className="w-5 h-5 text-blue-400" />
                      Skorunuzu Yükseltmek İçin:
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg">
                        <div className="w-6 h-6 rounded-full bg-green-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-green-400 text-sm">✓</span>
                        </div>
                        <div>
                          <div className="font-bold text-sm">Güvenlik Duvarını Aktif Et</div>
                          <div className="text-xs text-slate-400">+10 puan</div>
                        </div>
                      </div>
                      
                      <div className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg">
                        <div className="w-6 h-6 rounded-full bg-yellow-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-yellow-400 text-sm">!</span>
                        </div>
                        <div>
                          <div className="font-bold text-sm">2FA Kullan</div>
                          <div className="text-xs text-slate-400">+15 puan</div>
                        </div>
                      </div>
                      
                      <div className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg">
                        <div className="w-6 h-6 rounded-full bg-blue-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-blue-400 text-sm">🔒</span>
                        </div>
                        <div>
                          <div className="font-bold text-sm">Güçlü Şifreler</div>
                          <div className="text-xs text-slate-400">+12 puan</div>
                        </div>
                      </div>
                      
                      <div className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg">
                        <div className="w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <span className="text-purple-400 text-sm">📡</span>
                        </div>
                        <div>
                          <div className="font-bold text-sm">VPN Kullan</div>
                          <div className="text-xs text-slate-400">+8 puan</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* AI CHAT */}
        {activeTab === 'chat' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <div className="p-6 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <MessageSquare className="w-8 h-8 text-blue-400" />
                  <div>
                    <h2 className="text-2xl font-bold">AI Güvenlik Asistanı</h2>
                    <p className="text-sm text-slate-400">Siber güvenlik sorularınızı sorun</p>
                  </div>
                </div>
              </div>

              <div className="h-96 overflow-y-auto p-6 space-y-4 bg-black/30">
                {chatMessages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div
                      className={`max-w-[80%] p-4 rounded-xl ${
                        msg.role === 'user'
                          ? 'bg-blue-600 text-white'
                          : 'bg-slate-800 text-slate-200'
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        {msg.role === 'assistant' && (
                          <Shield className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                        )}
                        <p className="text-sm leading-relaxed">{msg.content}</p>
                      </div>
                    </div>
                  </div>
                ))}
                {chatLoading && (
                  <div className="flex justify-start">
                    <div className="bg-slate-800 text-slate-200 p-4 rounded-xl">
                      <div className="flex gap-1">
                        <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce"></div>
                        <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce delay-75"></div>
                        <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce delay-150"></div>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>

              <div className="p-6 border-t border-slate-800">
                <div className="flex gap-3">
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleChatSend()}
                    placeholder="Siber güvenlik hakkında bir şey sorun..."
                    className="flex-1 bg-black/50 border border-slate-700 text-white p-4 rounded-lg focus:border-blue-500 focus:outline-none"
                  />
                  <button
                    onClick={handleChatSend}
                    disabled={chatLoading || !chatInput.trim()}
                    className="px-6 py-4 bg-blue-600 hover:bg-blue-700 rounded-lg font-bold transition disabled:opacity-50"
                  >
                    GÖNDER
                  </button>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {['Port nedir?', 'Firewall nasıl aktif edilir?', 'Ransomware nedir?', 'VPN güvenli mi?'].map((suggestion, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setChatInput(suggestion);
                        handleChatSend();
                      }}
                      className="text-xs px-3 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-full transition"
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

      </main>
    </div>
  );
}