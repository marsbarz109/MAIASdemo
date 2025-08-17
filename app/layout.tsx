import './globals.css';
import type { ReactNode } from 'react';
export const metadata = {
  title: 'MAIAS Demo',
  description: 'Multi-Agent Orchestration Demo'
};

export default function RootLayout({
  children
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen">{children}</body>
    </html>
  );
}

