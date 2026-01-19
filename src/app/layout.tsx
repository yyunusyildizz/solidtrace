import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

// Projenin Google aramalarında ve sekme isminde nasıl görüneceğini ayarlarız
export const metadata = {
  title: "SolidTrace | Digital Footprint & Risk Analyzer",
  description: "Next-Gen Cyber Threat Intelligence Platform powered by Gemini 2.5",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    // suppressHydrationWarning: Tarayıcı eklentilerinin (şifre yöneticileri vb.) 
    // HTML yapısına müdahale etmesinden kaynaklanan kırmızı hataları susturur.
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
        suppressHydrationWarning
      >
        {children}
      </body>
    </html>
  );
}