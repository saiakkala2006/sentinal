import type { Metadata } from 'next';
import './globals.css';
import { Toaster } from 'react-hot-toast';

export const metadata: Metadata = {
  title: 'Sentinel — Self-Healing Email Threat-Detection System',
  description: 'AI-powered Digital Twin email defense with VPN-resistant Bayesian attribution and multi-agent autonomous response.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#070B14] text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-black">
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#111827',
              color: '#F8FAFC',
              border: '1px solid rgba(6, 182, 212, 0.3)',
              boxShadow: '0 10px 25px rgba(0, 0, 0, 0.5)',
            },
          }}
        />
        {children}
      </body>
    </html>
  );
}
