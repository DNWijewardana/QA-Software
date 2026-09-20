import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import Link from 'next/link';
import './globals.css';

export const metadata: Metadata = {
  title: 'QA Engineering Platform',
  description: 'Evidence-driven software quality assessment — honest about what was tested and what was not.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main">
          Skip to main content
        </a>
        <header className="site-header">
          <div className="inner">
            <h1>
              <Link href="/" style={{ color: 'inherit', textDecoration: 'none' }}>
                QA Engineering Platform
              </Link>
            </h1>
            <nav aria-label="Primary" className="site-nav">
              <Link href="/">Scans</Link>
              <Link href="/audit">Audit log</Link>
            </nav>
            <span className="tag">Evidence-driven · SAFE&nbsp;STATIC</span>
          </div>
        </header>
        <main id="main">{children}</main>
      </body>
    </html>
  );
}
