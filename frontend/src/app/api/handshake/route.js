import { createClient } from '@supabase/supabase-js';
import { NextResponse } from 'next/server';

export async function POST(req) {
  const { token } = await req.json();
  const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_KEY);

  // Veritabanında bu ID'ye sahip, 'agent_bekliyor' durumundaki kaydı bul
  const { data, error } = await supabase
    .from('taramalar')
    .select('id')
    .eq('id', token)
    .eq('durum', 'agent_bekliyor')
    .single();

  if (error || !data) return NextResponse.json({ error: "Geçersiz Token" }, { status: 401 });

  // Ajana sadece o an kullanacağı "Sırları" gönder
  return NextResponse.json({
    url: process.env.NEXT_PUBLIC_SUPABASE_URL,
    key: process.env.NEXT_PUBLIC_SUPABASE_KEY,
    scan_id: data.id
  });
}