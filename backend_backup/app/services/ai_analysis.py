"""
app.services.ai_analysis
========================
GROQ LLM entegrasyonu — SOC analiz raporları.
broadcast_fn dışarıdan enjekte edilir (bağımlılık tersine çevirme).
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Optional

logger = logging.getLogger("SolidTrace.AI")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")


async def perform_groq_analysis(
    data: dict,
    broadcast_fn: Optional[Callable] = None,
) -> None:
    """
    GROQ Llama-3 ile SOC analizi yap, sonucu broadcast_fn ile yayınla.
    data: ActionRequest.dict() veya alert dict.
    """
    async def _broadcast(msg: dict):
        if broadcast_fn:
            await broadcast_fn(msg)

    try:
        from groq import Groq
        local_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
    except Exception as e:
        logger.error(f"AI Client başlatılamadı: {e}")
        local_client = None

    if not local_client:
        await _broadcast({"type": "ACTION_LOG", "message": "❌ AI Devre Dışı (GROQ_API_KEY eksik)"})
        return

    await _broadcast({"type": "ACTION_LOG", "message": f"🤖 AI Analizi: {data.get('rule', '?')}"})

    system_prompt = """Sen dünyanın en yetkin SOC merkezinde 'Senior Tier 3 SOC Analisti'sin.

Kurallar:
1. Genel geçer tavsiyeler değil, spesifik teknik aksiyon ver.
2. MITRE ATT&CK teknik kodlarını mutlaka kullan (T1059, T1003 vb.)
3. False Positive ise açıkça belirt.
4. Türkçe, profesyonel, maks. 200 kelime."""

    # details / command_line / description alanlarından birini kullan
    context = (
        data.get("details")
        or data.get("command_line")
        or data.get("description")
        or "Detay yok"
    )

    user_prompt = f"""
ANALİZ EDİLECEK LOG:
Host:    {data.get('hostname', 'unknown')}
PID:     {data.get('pid', 0)}
Kural:   {data.get('rule', '?')}
Detay:   {context}
Risk:    {data.get('risk_score', 0)} | Şiddet: {data.get('severity', '?')}
"""

    try:
        completion = local_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=500,
        )
        report = completion.choices[0].message.content
        await _broadcast({"type": "ACTION_LOG", "message": f"🧠 AI RAPORU:\n{report}"})
        logger.info(f"AI Analizi tamamlandı: {data.get('hostname')}")
    except Exception as e:
        logger.error(f"AI Sorgu Hatası: {e}")
        await _broadcast({"type": "ACTION_LOG", "message": f"❌ AI Hatası: {e}"})
