import { NextResponse } from 'next/server';

export async function POST(req) {
  try {
    // Frontend'den gelen prompt'u al
    const { prompt } = await req.json();
    const apiKey = process.env.NEXT_PUBLIC_GROQ_API_KEY;

    if (!apiKey) {
      return NextResponse.json({ error: "API Anahtarı Sunucuda Bulunamadı" }, { status: 500 });
    }

    // Groq'a isteği SUNUCU (Backend) atıyor. CORS derdi yok!
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.5
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json({ error: data.error?.message || "Groq API Hatası" }, { status: response.status });
    }

    // Cevabı Frontend'e geri yolla
    return NextResponse.json({ content: data.choices[0].message.content });

  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}