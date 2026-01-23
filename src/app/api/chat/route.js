import { NextResponse } from 'next/server';
import Groq from "groq-sdk";

export async function POST(req) {
  // 1. Anahtar Kontrolü
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return NextResponse.json({ error: "Sunucu Hatası: API Anahtarı eksik." }, { status: 500 });
  }

  try {
    const groq = new Groq({ apiKey: apiKey });
    const body = await req.json();

    // 2. Groq İsteği (GÜNCEL MODEL)
    const chatCompletion = await groq.chat.completions.create({
      messages: [{ role: "user", content: body.prompt }],
      // model: "llama3-8b-8192", // ❌ ESKİSİ (Bunu sildik)
      model: "llama-3.3-70b-versatile", // ✅ YENİSİ (Canavar gibi çalışır)
      temperature: 0.5,
      max_tokens: 1024,
    });

    return NextResponse.json({ content: chatCompletion.choices[0]?.message?.content || "" });

  } catch (error) {
    console.error("Groq Hatası:", error);
    return NextResponse.json({ error: "Yapay zeka yanıt veremedi: " + error.message }, { status: 500 });
  }
}