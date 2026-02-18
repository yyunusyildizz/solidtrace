import { NextResponse } from 'next/server';
import Groq from "groq-sdk";

// Groq Kurulumu (API Key .env dosyasından gelir)
const groq = new Groq({
    apiKey: process.env.GROQ_API_KEY
});

export async function POST(req) {
    try {
        const body = await req.json();
        const { scanData } = body;

        // Yapay Zekaya Gönderilecek Emir (Prompt)
        const prompt = `
        Sen uzman bir Siber Güvenlik Analistisin. Aşağıdaki teknik tarama raporunu incele ve yönetici özeti çıkar.
        
        TEKNİK VERİ:
        ${JSON.stringify(scanData)}

        GÖREV:
        1. Kritik riskleri kırmızı ile belirt.
        2. Eğer sistem temizse "Güvenli" olduğunu söyle.
        3. Teknik terim kullanma, son kullanıcının anlayacağı dilde özetle.
        4. Türkçe yanıt ver.
        `;

        const completion = await groq.chat.completions.create({
            messages: [{ role: "user", content: prompt }],
            model: "llama3-8b-8192", // Hızlı ve Ücretsiz model
        });

        const aiResponse = completion.choices[0]?.message?.content || "Analiz yapılamadı.";

        return NextResponse.json({ result: aiResponse });

    } catch (error) {
        return NextResponse.json({ error: error.message }, { status: 500 });
    }
}