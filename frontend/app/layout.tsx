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
    <html lang="en">
      <body className="bg-[#F5F2EC] text-[#2C2A26] min-h-screen antialiased selection:bg-green-200 selection:text-green-900">
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#FDFCF8',
              color: '#2C2A26',
              border: '1px solid rgba(74, 124, 89, 0.3)',
              boxShadow: '0 8px 24px rgba(74, 124, 89, 0.12), 0 2px 8px rgba(0,0,0,0.06)',
              borderRadius: '12px',
              fontFamily: 'Inter, sans-serif',
              fontSize: '13px',
            },
            success: {
              iconTheme: { primary: '#4A7C59', secondary: '#FDFCF8' },
            },
            error: {
              iconTheme: { primary: '#B85C6A', secondary: '#FDFCF8' },
            },
          }}
        />
        {children}
      </body>
    </html>
  );
}
