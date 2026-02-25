"""
SolidTrace ML Anomaly Engine - v2.0 (REVISED)
Düzeltmeler:
  - Port 666 yazım hatası düzeltildi → merkezi SUSPICIOUS_PORTS kullanılıyor
  - Multi-feature anomali tespiti eklendi (cmd_len + port + hour_of_day)
  - IsolationForest çok boyutlu özelliklerle yeniden eğitiliyor
"""

import numpy as np
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("SolidTraceAPI")

# FIX: Merkezi port listesi — soc_engine ile senkron
SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}

# Şüpheli komut kelimeleri için ağırlıklar
SUSPICIOUS_KEYWORDS = {
    "mimikatz": 80, "lsass": 70, "sekurlsa": 70, "procdump": 65,
    "-enc": 50, "-encodedcommand": 50,
    "psexec": 45, "wmic": 35, "winrm": 35,
    "schtasks": 30, "bcdedit": 30,
    "whoami": 20, "net user": 25, "net localgroup": 25,
}


def extract_features(event: dict) -> np.ndarray:
    """
    Event'ten çok boyutlu özellik vektörü çıkar.
    Feature 0: Komut satırı uzunluğu (normalize edilmiş)
    Feature 1: Port şüphe skoru (0 veya 1)
    Feature 2: Günün saati anomali skoru (gece = daha şüpheli)
    Feature 3: Şüpheli kelime ağırlık toplamı (normalize edilmiş)
    """
    from datetime import datetime

    cmd = str(event.get("command_line", "") or "").lower()
    port = event.get("destination_port") or 0
    hour = datetime.utcnow().hour

    # Feature 0: Komut uzunluğu (0-1 arası normalize)
    cmd_len_score = min(len(cmd) / 1000.0, 1.0)

    # Feature 1: Şüpheli port
    port_score = 1.0 if int(port) in SUSPICIOUS_PORTS else 0.0

    # Feature 2: Çalışma saati anomalisi (22:00-06:00 = yüksek risk)
    hour_score = 1.0 if (hour >= 22 or hour <= 6) else 0.2

    # Feature 3: Şüpheli kelime ağırlıkları
    keyword_score = min(
        sum(weight for kw, weight in SUSPICIOUS_KEYWORDS.items() if kw in cmd) / 100.0,
        1.0
    )

    return np.array([[cmd_len_score, port_score, hour_score, keyword_score]])


class MLEngine:
    """
    Multi-feature ML Anomaly Detection Engine.
    Kendini dummy data ile başlatır, çalışma zamanında yeni olaylarla güncellenir.
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.is_ready = False
        self.event_buffer = []      # Gerçek veriler birikmesi için buffer
        self.retrain_threshold = 50  # Bu kadar gerçek event gelince yeniden eğit

        self._bootstrap()

    def _bootstrap(self):
        """Dummy data ile motoru başlat (sıfır downtime garantisi)"""
        try:
            # FIX: 4 boyutlu dummy data — gerçek feature uzayını temsil ediyor
            dummy = np.array([
                [0.0, 0.0, 0.2, 0.0],   # Normal gün içi kısa komut
                [0.1, 0.0, 0.2, 0.0],
                [0.2, 0.0, 0.2, 0.1],
                [0.5, 0.0, 0.5, 0.2],   # Orta riskli
                [0.9, 1.0, 0.2, 0.5],   # Yüksek riskli
                [1.0, 1.0, 1.0, 0.8],   # Çok yüksek riskli
                [1.0, 1.0, 1.0, 1.0],   # Maksimum risk
            ])
            self.scaler.fit(dummy)
            self.model.fit(self.scaler.transform(dummy))
            self.is_ready = True
            logger.info("🧠 [ML_ANOMALY] Motor 4-feature dummy data ile başlatıldı.")
        except Exception as e:
            logger.error(f"⚠️ [ML_ANOMALY] Bootstrap hatası: {e}")

    def _maybe_retrain(self):
        """Buffer dolunca gerçek verilerle yeniden eğit"""
        if len(self.event_buffer) >= self.retrain_threshold:
            try:
                data = np.vstack(self.event_buffer)
                self.scaler.fit(data)
                self.model.fit(self.scaler.transform(data))
                logger.info(f"🔄 [ML_ANOMALY] {len(self.event_buffer)} gerçek event ile yeniden eğitildi.")
                self.event_buffer = []  # Buffer'ı temizle
            except Exception as e:
                logger.error(f"⚠️ [ML_ANOMALY] Yeniden eğitim hatası: {e}")

    def analyze(self, event: dict) -> dict:
        """Event'i analiz et, anomali skoru ve bulgular döndür."""
        if not self.is_ready:
            return {"ml_score": 0, "findings": []}

        try:
            features = extract_features(event)

            # Buffer'a ekle ve gerekirse yeniden eğit
            self.event_buffer.append(features)
            self._maybe_retrain()

            # Model tahmini (-1 = anomali, 1 = normal)
            scaled = self.scaler.transform(features)
            prediction = self.model.predict(scaled)[0]
            # decision_function: daha negatif = daha anormal
            anomaly_score = self.model.decision_function(scaled)[0]

            risk_score = 0
            findings = []

            # IsolationForest anomali tespiti
            if prediction == -1:
                # Skoru 0-100 arasına normalize et
                normalized = max(0, min(int((-anomaly_score) * 100), 100))
                risk_score = max(risk_score, normalized)
                findings.append({
                    "rule": "ML Anomaly",
                    "confidence": round(min((-anomaly_score) * 2, 1.0), 2),
                    "severity": "high" if normalized > 50 else "medium",
                    "details": f"IsolationForest anomaly score: {anomaly_score:.3f}"
                })

            # Kural destekli ek kontroller
            cmd = str(event.get("command_line", "") or "").lower()
            port = event.get("destination_port") or 0

            if len(cmd) > 500:
                risk_score = max(risk_score, 40)
                findings.append({
                    "rule": "ML Anomaly",
                    "confidence": 0.8,
                    "severity": "high",
                    "details": f"Unusually long command ({len(cmd)} chars)"
                })

            # FIX: Artık merkezi SUSPICIOUS_PORTS kullanılıyor
            if int(port) in SUSPICIOUS_PORTS:
                risk_score = max(risk_score, 50)
                findings.append({
                    "rule": "ML Anomaly",
                    "confidence": 0.9,
                    "severity": "critical",
                    "details": f"Known suspicious port: {port}"
                })

            return {
                "ml_score": min(risk_score, 100),
                "findings": findings
            }

        except Exception as e:
            logger.error(f"ML Analiz Hatası: {e}")
            return {"ml_score": 0, "findings": []}
