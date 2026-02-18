import { NextResponse } from 'next/server';
import Groq from "groq-sdk";

export async function POST(req) {
  try {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) {
      throw new Error("GROQ_API_KEY bulunamadı!");
    }

    const groq = new Groq({ apiKey: apiKey });
    const { prompt } = await req.json();

    const chatCompletion = await groq.chat.completions.create({
      messages: [{ role: "user", content: prompt }],
      // 👇 ESKİSİ buydu: "mixtral-8x7b-32768" (Bunu sildik)
      // ✅ YENİSİ bu:
      model: "llama-3.3-70b-versatile", 
      temperature: 0.5,
      max_tokens: 1024,
    });

    return NextResponse.json({ 
        content: chatCompletion.choices[0]?.message?.content || "{}" 
    });

  } catch (error) {
    console.error("AI Error:", error.message);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}