import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import GalaxyBackground from "@/components/GalaxyBackground";
import AppShell from "@/components/AppShell";
import "./globals.css";

const inter = Inter({ variable: "--font-inter", subsets: ["latin"], weight: ["200", "300", "400", "500", "600"] });
const jetbrains = JetBrains_Mono({ variable: "--font-jetbrains", subsets: ["latin"], weight: ["400", "500"] });

export const metadata: Metadata = {
  title: "Aleph · SecOps Workspace",
  description: "AI-powered security operations: hunt, investigate, engineer detections.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable} antialiased`}>
      <body className="min-h-screen">
        <GalaxyBackground />
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
