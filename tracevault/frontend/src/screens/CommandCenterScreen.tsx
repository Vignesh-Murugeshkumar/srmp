import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, wsUrl } from '../api/client';
import { ARTIFACT_SOURCES, type ArtifactSource, type ScanProgress } from '../api/types';
import { useWorkstation } from '../components/WorkstationContext';
import { formatBytes, formatIso, SEVERITY_COLORS, SOURCE_COLORS, SOURCE_LABELS } from '../theme/tokens';

const STAGE_ORDER: (ArtifactSource | 'processing')[] = [
  'evtx',
  'registry',
  'prefetch',
  'amcache',
  'browser',
  'filesystem',
  'processing',
];

const AVAILABILITY_BADGES: Record<string, { label: string; cls: string }> = {
  available: { label: 'AVAILABLE', cls: 'text-verified border-verified/50 bg-verified/10' },
  collected: { label: 'COLLECTED', cls: 'text-accent border-accent/50 bg-accent/10' },
  partially_accessible: { label: 'PARTIAL', cls: 'text-suspicious border-suspicious/50 bg-suspicious/10' },
  permission_denied: { label: 'PERMISSION DENIED', cls: 'text-suspicious border-suspicious/50 bg-suspicious/10' },
  not_found: { label: 'NOT FOUND', cls: 'text-muted border-line bg-bg-2' },
  unsupported: { label: 'UNSUPPORTED', cls: 'text-muted border-line bg-bg-2' },
};

export const CommandCenterScreen: React.FC = () => {
  const nav = useNavigate();
  const qc = useQueryClient();
  const { activeInvestigation, setActiveInvestigationId } = useWorkstation();

  const [scanType, setScanType] = useState<'quick' | 'full'>('quick');
  const [timeWindowHours, setTimeWindowHours] = useState<number>(72);
  const [selectedSources, setSelectedSources] = useState<ArtifactSource[]>([...ARTIFACT_SOURCES]);
  const [newInvTitle, setNewInvTitle] = useState('');
  const [selectedEndpointForNewInv, setSelectedEndpointForNewInv] = useState('');
  const [liveProgress, setLiveProgress] = useState<ScanProgress | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const endpointsQuery = useQuery({
    queryKey: ['endpoints'],
    queryFn: () => api.endpoints(),
    refetchInterval: 8000,
  });

  const endpointId = activeInvestigation?.endpoint_id ?? endpointsQuery.data?.[0]?.id ?? null;

  const epStatusQuery = useQuery({
    queryKey: ['endpointStatus', endpointId],
    queryFn: () => api.endpointStatus(endpointId!),
    enabled: Boolean(endpointId),
    refetchInterval: 6000,
  });

  const summaryQuery = useQuery({
    queryKey: ['summary', activeInvestigation?.id],
    queryFn: () => api.summary(activeInvestigation!.id),
    enabled: Boolean(activeInvestigation?.id),
    refetchInterval: 5000,
  });

  const findingsQuery = useQuery({
    queryKey: ['findings', activeInvestigation?.id],
    queryFn: () => api.findings(activeInvestigation!.id),
    enabled: Boolean(activeInvestigation?.id),
  });

  const activeScanId = summaryQuery.data?.latest_scan?.id ?? epStatusQuery.data?.last_scan?.id ?? null;

  const scanProgressQuery = useQuery({
    queryKey: ['scanProgress', activeScanId],
    queryFn: () => api.scanProgress(activeScanId!),
    enabled: Boolean(activeScanId),
    refetchInterval: (q) => {
      const st = q.state.data?.scan.status;
      return st === 'queued' || st === 'collecting' || st === 'processing' ? 2000 : false;
    },
  });

  const activeScanStatus = summaryQuery.data?.latest_scan?.status ?? epStatusQuery.data?.last_scan?.status ?? null;
  const isScanActive = activeScanStatus !== null && ['queued', 'collecting', 'processing'].includes(activeScanStatus);

  // Subscribe to WebSocket scan progress ONLY while a scan is actively running
  useEffect(() => {
    if (!activeScanId || !isScanActive) {
      return;
    }
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(wsUrl(`/ws/scans/${activeScanId}`));
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === 'progress') {
            setLiveProgress(msg.data as ScanProgress);
          } else if (msg.type === 'status') {
            qc.invalidateQueries({ queryKey: ['summary', activeInvestigation?.id] });
            qc.invalidateQueries({ queryKey: ['findings', activeInvestigation?.id] });
            qc.invalidateQueries({ queryKey: ['scanProgress', activeScanId] });
          }
        } catch {
          /* ignore malformed ws frame */
        }
      };
    } catch {
      /* polling fallback active via scanProgressQuery */
    }
    return () => {
      try {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.close();
        }
      } catch {
        /* ignore */
      }
    };
  }, [activeScanId, isScanActive, activeInvestigation?.id, qc]);

  const effectiveProgress = liveProgress ?? scanProgressQuery.data ?? null;
  const activeEndpoint = endpointsQuery.data?.find((e) => e.id === endpointId) ?? null;

  const toggleSource = (s: ArtifactSource) => {
    setSelectedSources((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));
  };

  const handleStartScan = async () => {
    if (!activeInvestigation || !endpointId) return;
    setActionError(null);
    try {
      await api.startScan(endpointId, {
        investigation_id: activeInvestigation.id,
        scan_type: scanType,
        time_window_hours: scanType === 'quick' ? timeWindowHours : null,
        sources: selectedSources,
      });
      await qc.invalidateQueries({ queryKey: ['summary', activeInvestigation.id] });
      await qc.invalidateQueries({ queryKey: ['endpointStatus', endpointId] });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to queue scan');
    }
  };

  const handleCancelScan = async () => {
    if (!activeScanId) return;
    try {
      await api.cancelScan(activeScanId);
      await qc.invalidateQueries({ queryKey: ['scanProgress', activeScanId] });
      await qc.invalidateQueries({ queryKey: ['summary', activeInvestigation?.id] });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Cancel failed');
    }
  };

  const handleCreateInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    const epTarget = selectedEndpointForNewInv || endpointsQuery.data?.[0]?.id;
    if (!epTarget || !newInvTitle.trim()) return;
    setActionError(null);
    try {
      const created = await api.createInvestigation({
        title: newInvTitle.trim(),
        endpoint_id: epTarget,
      });
      setNewInvTitle('');
      await qc.invalidateQueries({ queryKey: ['investigations'] });
      setActiveInvestigationId(created.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Could not create investigation');
    }
  };

  const summary = summaryQuery.data;
  const stagesByKey = new Map((effectiveProgress?.stages ?? []).map((st) => [st.stage, st]));

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4">
      {/* Row 1: Endpoint Identity & New Case / Enrollment Controls */}
      <div className="grid grid-cols-12 gap-4">
        {/* Endpoint Identity Area */}
        <section className="col-span-8 bg-panel border border-line p-3.5">
          <div className="flex items-center justify-between border-b border-line-soft pb-2 mb-3">
            <div>
              <div className="text-2xs font-mono uppercase text-accent">ENDPOINT IDENTITY & TELEMETRY</div>
              <h2 className="text-sm font-semibold text-ink-bright">
                {activeEndpoint ? `${activeEndpoint.hostname} (${activeEndpoint.os_name})` : 'No Endpoint Registered'}
              </h2>
            </div>
            {activeEndpoint && (
              <div className="flex items-center space-x-2 text-2xs font-mono">
                <span className="px-2 py-0.5 border border-line bg-bg-2">
                  GUID: {activeEndpoint.machine_id.slice(0, 18)}...
                </span>
                <span
                  className={`px-2 py-0.5 border ${
                    activeEndpoint.agent_status === 'online'
                      ? 'border-verified text-verified bg-verified/10'
                      : 'border-line text-muted bg-bg-2'
                  }`}
                >
                  AGENT: {activeEndpoint.agent_status.toUpperCase()}
                </span>
              </div>
            )}
          </div>

          {activeEndpoint ? (
            <div className="grid grid-cols-4 gap-3 text-xs font-mono">
              <div className="bg-bg-2 border border-line-soft p-2">
                <div className="text-2xs text-muted">OS VERSION / BUILD</div>
                <div className="text-ink-bright mt-0.5">
                  {activeEndpoint.os_version} (Build {activeEndpoint.os_build}) / {activeEndpoint.architecture}
                </div>
              </div>
              <div className="bg-bg-2 border border-line-soft p-2">
                <div className="text-2xs text-muted">COLLECTION USER & INTEGRITY</div>
                <div className="text-ink-bright mt-0.5">
                  {activeEndpoint.collection_user}{' '}
                  <span className={activeEndpoint.is_elevated ? 'text-verified' : 'text-suspicious'}>
                    [{activeEndpoint.is_elevated ? 'Admin' : 'Non-Elevated'}]
                  </span>
                </div>
              </div>
              <div className="bg-bg-2 border border-line-soft p-2">
                <div className="text-2xs text-muted">AGENT VERSION / LAST SEEN</div>
                <div className="text-ink-bright mt-0.5">
                  v{activeEndpoint.agent_version} — {formatIso(activeEndpoint.last_seen)}
                </div>
              </div>
              <div className="bg-bg-2 border border-line-soft p-2">
                <div className="text-2xs text-muted">STORAGE VOLUMES</div>
                <div className="text-ink-bright mt-0.5">
                  {(activeEndpoint.storage ?? []).map((v) => `${v.drive} (${v.filesystem}, ${formatBytes(v.free_bytes)} free)`).join(', ') || 'N/A'}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-bg-2 border border-line p-3 text-xs font-mono text-muted space-y-1.5">
              <div className="text-ink-bright">Authorize and register a Windows Endpoint Collector:</div>
              <pre className="bg-bg p-2 border border-line text-accent overflow-x-auto">
                python -m tracevault_collector register --server http://127.0.0.1:8000 --enrollment-key dev-enrollment-key{'\n'}
                python -m tracevault_collector agent --server http://127.0.0.1:8000
              </pre>
            </div>
          )}
        </section>

        {/* Scan Control & Case Creation */}
        <section className="col-span-4 bg-panel border border-line p-3.5 flex flex-col justify-between">
          <div>
            <div className="text-2xs font-mono uppercase text-accent">FORENSIC COLLECTION CONTROL</div>
            <h2 className="text-sm font-semibold text-ink-bright mb-2">Initiate Endpoint Acquisition</h2>

            <div className="grid grid-cols-2 gap-2 mb-2.5">
              <button
                type="button"
                onClick={() => setScanType('quick')}
                className={`py-1.5 px-2 border text-xs font-mono ${
                  scanType === 'quick' ? 'border-accent bg-accent/15 text-ink-bright' : 'border-line bg-bg-2 text-muted'
                }`}
              >
                Quick Scan ({timeWindowHours}h)
              </button>
              <button
                type="button"
                onClick={() => setScanType('full')}
                className={`py-1.5 px-2 border text-xs font-mono ${
                  scanType === 'full' ? 'border-accent bg-accent/15 text-ink-bright' : 'border-line bg-bg-2 text-muted'
                }`}
              >
                Full Forensic Scan
              </button>
            </div>

            {scanType === 'quick' && (
              <div className="flex items-center justify-between text-2xs font-mono mb-2">
                <span className="text-muted">Time Window (hours):</span>
                <input
                  type="number"
                  min={1}
                  max={720}
                  value={timeWindowHours}
                  onChange={(e) => setTimeWindowHours(Number(e.target.value) || 24)}
                  className="w-20 bg-bg border border-line px-2 py-0.5 text-ink-bright text-right"
                />
              </div>
            )}

            <div className="flex flex-wrap gap-1 mb-3">
              {ARTIFACT_SOURCES.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSource(s)}
                  className={`px-2 py-0.5 text-2xs font-mono border uppercase ${
                    selectedSources.includes(s)
                      ? 'border-accent text-ink-bright bg-panel-2'
                      : 'border-line text-muted bg-bg opacity-60'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            {actionError && <div className="text-2xs font-mono text-critical">{actionError}</div>}
            <div className="flex space-x-2">
              <button
                type="button"
                disabled={!activeInvestigation || !endpointId || selectedSources.length === 0}
                onClick={handleStartScan}
                className="flex-1 bg-accent text-bg font-mono font-semibold text-xs uppercase py-2 hover:bg-accent/90 disabled:opacity-40"
              >
                Start {scanType === 'quick' ? 'Quick' : 'Full'} Scan
              </button>
              {effectiveProgress &&
                ['queued', 'collecting'].includes(effectiveProgress.scan.status) && (
                  <button
                    type="button"
                    onClick={handleCancelScan}
                    className="px-3 py-2 border border-critical text-critical font-mono text-xs uppercase hover:bg-critical/10"
                  >
                    Cancel
                  </button>
                )}
            </div>

            {/* Quick inline investigation creator if user wants a new case on an endpoint */}
            {(endpointsQuery.data?.length ?? 0) > 0 && (
              <form onSubmit={handleCreateInvestigation} className="pt-2 border-t border-line-soft flex space-x-1.5">
                <select
                  value={selectedEndpointForNewInv || endpointsQuery.data?.[0]?.id || ''}
                  onChange={(e) => setSelectedEndpointForNewInv(e.target.value)}
                  className="bg-bg border border-line px-1.5 py-1 text-2xs font-mono text-ink max-w-[115px]"
                >
                  {(endpointsQuery.data ?? []).map((ep) => (
                    <option key={ep.id} value={ep.id}>
                      {ep.hostname}
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  placeholder="New investigation title..."
                  value={newInvTitle}
                  onChange={(e) => setNewInvTitle(e.target.value)}
                  className="flex-1 bg-bg border border-line px-2 py-1 text-2xs font-mono text-ink-bright"
                />
                <button
                  type="submit"
                  className="px-2.5 py-1 border border-line bg-panel-2 text-2xs font-mono text-accent hover:border-accent"
                >
                  + Case
                </button>
              </form>
            )}
          </div>
        </section>
      </div>

      {/* Row 2: Dense Investigation Readout Strip */}
      <section className="bg-panel border border-line px-4 py-2.5 flex items-center justify-between font-mono text-xs">
        <div className="flex items-center space-x-6">
          <div>
            <span className="text-muted text-2xs uppercase mr-2">ARTIFACTS ACQUIRED:</span>
            <strong className="text-ink-bright">{summary?.evidence_collected ?? 0}</strong>
          </div>
          <div className="border-l border-line pl-6">
            <span className="text-muted text-2xs uppercase mr-2">RAW RECORDS:</span>
            <strong className="text-ink-bright">{summary?.records_total ?? 0}</strong>
          </div>
          <div className="border-l border-line pl-6">
            <span className="text-muted text-2xs uppercase mr-2">NORMALIZED EVENTS:</span>
            <strong className="text-ink-bright">{summary?.events_total ?? 0}</strong>
          </div>
          <div className="border-l border-line pl-6">
            <span className="text-muted text-2xs uppercase mr-2">CORRELATED EVENTS:</span>
            <strong className="text-accent">{summary?.correlated_events ?? 0}</strong>
          </div>
          <div className="border-l border-line pl-6">
            <span className="text-muted text-2xs uppercase mr-2">HIGH-CONFIDENCE EDGES:</span>
            <strong className="text-relation">{summary?.high_confidence_relationships ?? 0}</strong>
          </div>
          <div className="border-l border-line pl-6">
            <span className="text-muted text-2xs uppercase mr-2">SUSPICIOUS FINDINGS:</span>
            <strong className={(summary?.suspicious_findings ?? 0) > 0 ? 'text-suspicious' : 'text-ink'}>
              {summary?.suspicious_findings ?? 0}
            </strong>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-2xs">
          <span className="text-verified">SHA-256 VERIFIED: {summary?.integrity.verified ?? 0}</span>
          <span className={(summary?.integrity.mismatched ?? 0) > 0 ? 'text-critical font-bold' : 'text-muted'}>
            MISMATCH: {summary?.integrity.mismatched ?? 0}
          </span>
        </div>
      </section>

      {/* Row 3: Animated Stage-by-Stage Collection & Processing Pipeline */}
      <section className="bg-panel border border-line p-3.5">
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-2xs font-mono uppercase text-accent">COLLECTION & RECONSTRUCTION PIPELINE</div>
            <h3 className="text-xs font-semibold text-ink-bright">
              Stage Telemetry{' '}
              {effectiveProgress?.scan && (
                <span className="font-mono text-muted ml-2">
                  [Scan {effectiveProgress.scan.id.slice(0, 8)} — {effectiveProgress.scan.status.toUpperCase()}]
                </span>
              )}
            </h3>
          </div>
          <button
            onClick={() => nav('/universe')}
            className="px-3 py-1 bg-panel-2 border border-accent text-accent text-2xs font-mono uppercase hover:bg-accent hover:text-bg"
          >
            Open Evidence Universe →
          </button>
        </div>

        <div className="grid grid-cols-7 gap-2.5">
          {STAGE_ORDER.map((stageName) => {
            const st = stagesByKey.get(stageName);
            const srcSummary = summary?.sources.find((s) => s.source === stageName);
            const status = st?.status ?? (srcSummary?.status === 'collected' ? 'completed' : 'pending');
            const records = st?.records ?? srcSummary?.records ?? 0;
            const color =
              stageName === 'processing'
                ? '#8C9CFF'
                : SOURCE_COLORS[stageName as ArtifactSource] || '#67C8D8';

            return (
              <div key={stageName} className="bg-bg-2 border border-line p-2.5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold uppercase" style={{ color }}>
                      {stageName === 'filesystem' ? 'NTFS / FS' : stageName}
                    </span>
                    <span
                      className={`text-2xs font-mono uppercase px-1.5 py-0.5 border ${
                        status === 'completed'
                          ? 'border-verified/50 text-verified bg-verified/10'
                          : status === 'partial'
                            ? 'border-suspicious/50 text-suspicious bg-suspicious/10'
                            : status === 'running'
                              ? 'border-accent text-accent animate-pulse'
                              : 'border-line text-muted'
                      }`}
                    >
                      {status}
                    </span>
                  </div>

                  <div className="mt-2 font-mono text-sm text-ink-bright">
                    {records.toLocaleString()} <span className="text-2xs text-muted">recs</span>
                  </div>
                  {st?.duration_ms !== undefined && st?.duration_ms !== null && (
                    <div className="text-2xs font-mono text-muted">{st.duration_ms} ms</div>
                  )}
                </div>

                <div className="mt-2">
                  <div className="w-full h-1 bg-bg border border-line-soft overflow-hidden">
                    <div
                      className="h-full transition-all duration-300"
                      style={{
                        width: `${Math.round((st?.progress ?? (status === 'completed' ? 1 : 0)) * 100)}%`,
                        backgroundColor: color,
                      }}
                    />
                  </div>
                  {st?.errors && st.errors.length > 0 && (
                    <div className="text-2xs font-mono text-suspicious mt-1 truncate" title={st.errors.join('; ')}>
                      ! {st.errors[0]}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {effectiveProgress?.scan.limitations && effectiveProgress.scan.limitations.length > 0 && (
          <div className="mt-3 pt-2.5 border-t border-line-soft text-2xs font-mono text-suspicious space-y-0.5">
            <div className="uppercase font-semibold">Recorded Collection Limitations (Honest Status):</div>
            {effectiveProgress.scan.limitations.slice(0, 4).map((lim, i) => (
              <div key={i}>• {lim}</div>
            ))}
          </div>
        )}
      </section>

      {/* Row 4: Artifact Discovery Matrix & Detection Findings Preview */}
      <div className="grid grid-cols-12 gap-4">
        {/* Artifact Discovery Table */}
        <section className="col-span-7 bg-panel border border-line p-3.5">
          <div className="text-2xs font-mono uppercase text-accent">ENDPOINT ARTIFACT DISCOVERY</div>
          <h3 className="text-xs font-semibold text-ink-bright mb-2.5">
            Source Availability & Access Status on {activeEndpoint?.hostname ?? 'Endpoint'}
          </h3>

          <div className="overflow-x-auto max-h-72 overflow-y-auto border border-line-soft">
            <table className="w-full text-left border-collapse font-mono text-2xs">
              <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                <tr>
                  <th className="p-2 border-b border-line">Source</th>
                  <th className="p-2 border-b border-line">Artifact</th>
                  <th className="p-2 border-b border-line">Location</th>
                  <th className="p-2 border-b border-line">Status</th>
                  <th className="p-2 border-b border-line">Access Note</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-soft">
                {(epStatusQuery.data?.discovery ?? []).map((d) => {
                  const badge = AVAILABILITY_BADGES[d.availability] ?? AVAILABILITY_BADGES.not_found;
                  return (
                    <tr key={d.artifact_key} className="hover:bg-panel-2">
                      <td className="p-2 uppercase" style={{ color: SOURCE_COLORS[d.source] }}>
                        {d.source}
                      </td>
                      <td className="p-2 text-ink-bright">{d.name}</td>
                      <td className="p-2 text-muted truncate max-w-[200px]" title={d.location}>
                        {d.location}
                      </td>
                      <td className="p-2">
                        <span className={`px-1.5 py-0.5 border ${badge.cls}`}>{badge.label}</span>
                      </td>
                      <td className="p-2 text-muted truncate max-w-[180px]" title={d.access_note ?? ''}>
                        {d.access_note ?? '—'}
                      </td>
                    </tr>
                  );
                })}
                {(epStatusQuery.data?.discovery ?? []).length === 0 && (
                  <tr>
                    <td colSpan={5} className="p-4 text-center text-muted">
                      No discovery telemetry received for this endpoint yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Rule-Based Threat Findings Preview */}
        <section className="col-span-5 bg-panel border border-line p-3.5">
          <div className="flex items-center justify-between mb-2.5">
            <div>
              <div className="text-2xs font-mono uppercase text-accent">FORENSIC ANALYTICS</div>
              <h3 className="text-xs font-semibold text-ink-bright">Rule-Based Detections & ATT&CK Mapping</h3>
            </div>
            <button
              onClick={() => nav('/incidents')}
              className="text-2xs font-mono text-accent hover:underline"
            >
              Inspect All →
            </button>
          </div>

          <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
            {(findingsQuery.data ?? []).map((f) => (
              <div key={f.id} className="bg-bg-2 border border-line p-2.5">
                <div className="flex items-center justify-between">
                  <span
                    className="text-2xs font-mono uppercase font-semibold px-1.5 py-0.5 border"
                    style={{
                      color: SEVERITY_COLORS[f.severity],
                      borderColor: SEVERITY_COLORS[f.severity],
                    }}
                  >
                    {f.severity} // {f.rule_id}
                  </span>
                  {f.mitre && (
                    <span className="text-2xs font-mono text-secondary">
                      {f.mitre.technique_id} ({f.mitre.tactic})
                    </span>
                  )}
                </div>
                <div className="text-xs font-medium text-ink-bright mt-1">{f.name}</div>
                <div className="text-2xs text-muted mt-0.5">{f.description}</div>
                <div className="text-2xs font-mono text-muted mt-1 flex items-center justify-between">
                  <span>Entity: {f.affected_entity_label ?? '—'}</span>
                  <span>
                    Confidence: {Math.round(f.confidence * 100)}% ({f.supporting_event_ids.length} ev)
                  </span>
                </div>
              </div>
            ))}
            {(findingsQuery.data ?? []).length === 0 && (
              <div className="bg-bg-2 border border-line-soft p-4 text-xs font-mono text-muted">
                No suspicious rule-based findings triggered in this investigation.
                <div className="mt-1 text-2xs">
                  {SOURCE_LABELS.evtx}, Registry, Browser, and Filesystem events can be explored in Evidence Universe.
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
};
