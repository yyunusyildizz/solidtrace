Apply files to:
- app/detection/sigma_engine.py
- app/detection/correlation_engine.py
- app/api/routes_alerts.py
- app/api/routes_sigma.py
- app/detection/threat_intel.py

This patch focuses on the product-quality blockers shown by your logs:
- benign/devtool events still producing SIGMA_ALERT fan-out
- noisy correlation alerts still filling the UI
- historical low-value alerts obscuring current signal
- duplicate threat_intel implementations risking import confusion
