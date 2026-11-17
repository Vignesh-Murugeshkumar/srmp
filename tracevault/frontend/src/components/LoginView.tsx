import React, { useState } from 'react';
import { api } from '../api/client';
import { auth } from '../api/auth';

export const LoginView: React.FC = () => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('tracevault-admin');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await api.login(username.trim(), password);
      auth.set({ token: res.access_token, user: res.user });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-6 text-ink">
      <div className="w-full max-w-md bg-panel border border-line p-6">
        <div className="flex items-center justify-between border-b border-line pb-4 mb-5">
          <div>
            <div className="text-xs font-mono uppercase tracking-widest text-accent">TRACEVAULT // FORENSICS</div>
            <h1 className="text-lg font-semibold text-ink-bright mt-0.5">
              Endpoint Evidence Reconstruction Workstation
            </h1>
          </div>
          <span className="px-2 py-0.5 text-2xs font-mono border border-line bg-bg-2 text-muted">v0.1.0</span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono uppercase text-muted mb-1">Analyst Identifier</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-bg border border-line px-3 py-2 text-sm font-mono text-ink-bright focus:outline-none focus:border-accent"
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-muted mb-1">Passphrase</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-bg border border-line px-3 py-2 text-sm font-mono text-ink-bright focus:outline-none focus:border-accent"
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <div className="border border-critical bg-critical/10 px-3 py-2 text-xs text-critical font-mono">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full bg-accent text-bg font-mono font-semibold text-xs uppercase tracking-wider py-2.5 hover:bg-accent/90 disabled:opacity-50"
          >
            {busy ? 'Authenticating...' : 'Unlock Forensic Workstation'}
          </button>
        </form>

        <div className="mt-5 pt-4 border-t border-line-soft text-2xs font-mono text-muted space-y-1">
          <div>AUTHORIZED DIGITAL FORENSIC ANALYSTS ONLY</div>
          <div>All evidence acquisitions, hash verifications, and report exports are recorded in audit_logs.</div>
        </div>
      </div>
    </div>
  );
};
