import React, { useEffect } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { auth } from '../api/auth';
import { useWorkstation } from './WorkstationContext';

const NAV_ITEMS = [
  { to: '/', code: '01', label: 'Command Center', sub: 'Endpoint & Scan Pipeline' },
  { to: '/universe', code: '02', label: 'Evidence Universe', sub: 'Correlation Graph' },
  { to: '/temporal', code: '03', label: 'Temporal Studio', sub: 'Chronology & Time Travel' },
  { to: '/artifacts', code: '04', label: 'Artifact Explorer', sub: 'Raw Forensic Sources' },
  { to: '/incidents', code: '05', label: 'Incident Reconstruction', sub: 'Hypotheses & Reports' },
];

export const AppShell: React.FC = () => {
  const qc = useQueryClient();
  const { activeInvestigationId, setActiveInvestigationId, activeInvestigation, setActiveInvestigation } =
    useWorkstation();

  const invQuery = useQuery({
    queryKey: ['investigations'],
    queryFn: () => api.investigations(1, 100),
  });

  const endpointsQuery = useQuery({
    queryKey: ['endpoints'],
    queryFn: () => api.endpoints(),
  });

  useEffect(() => {
    const items = invQuery.data?.items ?? [];
    if (items.length > 0 && !activeInvestigationId) {
      // Prefer real non-demo investigation if present, otherwise first available
      const preferred = items.find((i) => !i.is_demo) ?? items[0];
      setActiveInvestigationId(preferred.id);
      setActiveInvestigation(preferred);
    } else if (activeInvestigationId) {
      const match = items.find((i) => i.id === activeInvestigationId) ?? null;
      setActiveInvestigation(match);
    }
  }, [invQuery.data, activeInvestigationId, setActiveInvestigationId, setActiveInvestigation]);

  const handleSeedDemo = async () => {
    const demoInv = await api.seedDemo();
    await qc.invalidateQueries({ queryKey: ['investigations'] });
    await qc.invalidateQueries({ queryKey: ['endpoints'] });
    setActiveInvestigationId(demoInv.id);
    setActiveInvestigation(demoInv);
  };

  const activeEndpoint = endpointsQuery.data?.find((e) => e.id === activeInvestigation?.endpoint_id);

  return (
    <div className="h-screen w-screen overflow-hidden flex flex-col bg-bg text-ink select-none">
      {/* Top Forensic Case Bar */}
      <header className="h-11 bg-bg-2 border-b border-line px-3 flex items-center justify-between shrink-0">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <span className="inline-block w-2 h-2 bg-accent" />
            <span className="font-mono font-bold tracking-wider text-ink-bright text-xs">TRACEVAULT</span>
            <span className="text-2xs font-mono text-muted border-l border-line pl-2">FORENSIC WORKSTATION</span>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-2xs font-mono uppercase text-muted">Active Case:</span>
            <select
              value={activeInvestigationId ?? ''}
              onChange={(e) => setActiveInvestigationId(e.target.value || null)}
              className="bg-panel border border-line px-2.5 py-1 text-xs font-mono text-ink-bright focus:outline-none focus:border-accent min-w-[280px]"
            >
              {(invQuery.data?.items ?? []).length === 0 && (
                <option value="">— No Investigations Created —</option>
              )}
              {(invQuery.data?.items ?? []).map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.is_demo ? '[DEMO] ' : ''}
                  {inv.title} ({inv.endpoint_hostname})
                </option>
              ))}
            </select>
          </div>

          {activeEndpoint && (
            <div className="hidden xl:flex items-center space-x-3 text-2xs font-mono border-l border-line pl-3">
              <span className="text-muted">
                HOST: <strong className="text-ink-bright">{activeEndpoint.hostname}</strong>
              </span>
              <span className="text-muted">
                OS: <strong className="text-ink">{activeEndpoint.os_name} ({activeEndpoint.os_build})</strong>
              </span>
              <span className="text-muted">
                PRIVILEGE:{' '}
                <strong className={activeEndpoint.is_elevated ? 'text-verified' : 'text-suspicious'}>
                  {activeEndpoint.is_elevated ? 'ELEVATED (ADMIN)' : 'MEDIUM (USER)'}
                </strong>
              </span>
              <span className="flex items-center space-x-1">
                <span
                  className={`inline-block w-1.5 h-1.5 rounded-full ${
                    activeEndpoint.agent_status === 'online'
                      ? 'bg-verified'
                      : activeEndpoint.agent_status === 'stale'
                        ? 'bg-suspicious'
                        : 'bg-muted'
                  }`}
                />
                <span className="uppercase text-muted">{activeEndpoint.agent_status}</span>
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center space-x-3">
          {auth.session?.user.role === 'admin' && (
            <button
              onClick={handleSeedDemo}
              className="px-2.5 py-1 text-2xs font-mono border border-suspicious/60 text-suspicious hover:bg-suspicious/10"
              title="Load synthetic multi-source demonstration dataset (flagged is_demo=true)"
            >
              + Load Synthetic Demo Case
            </button>
          )}
          <div className="text-2xs font-mono text-muted border-l border-line pl-3">
            {auth.session?.user.username} <span className="uppercase text-accent">[{auth.session?.user.role}]</span>
          </div>
          <button
            onClick={() => auth.set(null)}
            className="text-2xs font-mono text-muted hover:text-critical px-2 py-1 border border-line"
          >
            Sign Out
          </button>
        </div>
      </header>

      {/* Unmissable Demonstration Mode Banner when viewing a synthetic demo investigation */}
      {activeInvestigation?.is_demo && (
        <div className="bg-suspicious/15 border-b border-suspicious px-4 py-1 text-2xs font-mono text-suspicious flex items-center justify-between shrink-0">
          <span>
            DEMONSTRATION DATASET ACTIVE (is_demo=true) — Viewing synthetic spear-phishing & persistence scenario on
            DEMO-WORKSTATION-07. Real endpoint investigations are strictly separated.
          </span>
          <span className="uppercase font-semibold">SYNTHETIC CASE</span>
        </div>
      )}

      {/* Main Workstation Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Environment Rail */}
        <aside className="w-52 bg-bg-2 border-r border-line flex flex-col justify-between shrink-0">
          <nav className="p-2 space-y-1">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `block px-2.5 py-2 border transition-colors ${
                    isActive
                      ? 'bg-panel-2 border-accent text-ink-bright'
                      : 'border-transparent text-muted hover:bg-panel hover:text-ink'
                  }`
                }
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-xs">{item.label}</span>
                  <span className="font-mono text-2xs text-accent">{item.code}</span>
                </div>
                <div className="text-2xs text-muted mt-0.5">{item.sub}</div>
              </NavLink>
            ))}
          </nav>

          <div className="p-2.5 border-t border-line text-2xs font-mono text-muted space-y-1">
            <div className="text-ink-bright">INTEGRITY POLICY</div>
            <div>SHA-256 Verified Chain</div>
            <div>No Inferred Time Edges</div>
          </div>
        </aside>

        {/* Active Investigation Screen */}
        <main className="flex-1 overflow-hidden bg-bg select-text">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
