import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, downloadAuthenticated } from '../api/client';
import { INCIDENT_STATUSES, type IncidentCase, type IncidentStatus } from '../api/types';
import { useWorkstation } from '../components/WorkstationContext';
import { formatIso, SEVERITY_COLORS } from '../theme/tokens';

export const IncidentReconstructionScreen: React.FC = () => {
  const qc = useQueryClient();
  const { activeInvestigation } = useWorkstation();
  const invId = activeInvestigation?.id ?? null;

  const [newTitle, setNewTitle] = useState('');
  const [newHypothesis, setNewHypothesis] = useState('');
  const [newUser, setNewUser] = useState('');
  const [newProc, setNewProc] = useState('');
  const [noteBody, setNoteBody] = useState('');
  const [reportBusy, setReportBusy] = useState(false);

  const incidentsQuery = useQuery({
    queryKey: ['incidents', invId],
    queryFn: () => api.incidents(invId!),
    enabled: Boolean(invId),
  });

  const findingsQuery = useQuery({
    queryKey: ['findings', invId],
    queryFn: () => api.findings(invId!),
    enabled: Boolean(invId),
  });

  const riskQuery = useQuery({
    queryKey: ['risk', invId],
    queryFn: () => api.risk(invId!),
    enabled: Boolean(invId),
  });

  const notesQuery = useQuery({
    queryKey: ['notes', invId],
    queryFn: () => api.notes(invId!),
    enabled: Boolean(invId),
  });

  const reportsQuery = useQuery({
    queryKey: ['reports', invId],
    queryFn: () => api.reports(invId!),
    enabled: Boolean(invId),
  });

  const custodyQuery = useQuery({
    queryKey: ['custody', invId],
    queryFn: () => api.custody(invId!),
    enabled: Boolean(invId),
  });

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!invId || !newTitle.trim()) return;
    await api.createIncident(invId, {
      title: newTitle.trim(),
      hypothesis: newHypothesis.trim() || null,
      affected_user: newUser.trim() || null,
      affected_process: newProc.trim() || null,
    });
    setNewTitle('');
    setNewHypothesis('');
    setNewUser('');
    setNewProc('');
    await qc.invalidateQueries({ queryKey: ['incidents', invId] });
  };

  const handleUpdateIncidentStatus = async (ic: IncidentCase, status: IncidentStatus) => {
    await api.updateIncident(ic.id, { status });
    await qc.invalidateQueries({ queryKey: ['incidents', invId] });
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!invId || !noteBody.trim()) return;
    await api.addNote(invId, { body: noteBody.trim() });
    setNoteBody('');
    await qc.invalidateQueries({ queryKey: ['notes', invId] });
  };

  const handleGenerateReport = async (format: 'pdf' | 'json') => {
    if (!invId) return;
    setReportBusy(true);
    try {
      const rep = await api.createReport(invId, { format });
      await qc.invalidateQueries({ queryKey: ['reports', invId] });
      await qc.invalidateQueries({ queryKey: ['custody', invId] });
      await downloadAuthenticated(
        rep.download_url,
        `TraceVault_Report_${invId.slice(0, 8)}.${format}`,
      );
    } finally {
      setReportBusy(false);
    }
  };

  const risk = riskQuery.data;

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4">
      {/* Row 1: Explainable Risk Assessment & Forensic Report Generation */}
      <div className="grid grid-cols-12 gap-4">
        <section className="col-span-8 bg-panel border border-line p-3.5">
          <div className="flex items-center justify-between border-b border-line-soft pb-2 mb-2.5">
            <div>
              <div className="text-2xs font-mono uppercase text-accent">EXPLAINABLE RISK ASSESSMENT</div>
              <h2 className="text-sm font-semibold text-ink-bright">
                Deterministic Indicator Breakdown (Never Auto-Labels Compromised)
              </h2>
            </div>
            <div className="font-mono text-right">
              <span className="text-lg font-bold text-ink-bright">{risk?.score ?? 0}</span>
              <span className="text-xs text-muted">/100</span>{' '}
              <span className="ml-2 px-2 py-0.5 text-2xs uppercase border border-line bg-bg-2">
                {risk?.level ?? 'minimal'}
              </span>
            </div>
          </div>

          <p className="text-xs text-muted mb-3">{risk?.explanation}</p>

          <div className="space-y-1.5 max-h-40 overflow-y-auto">
            {(risk?.factors ?? []).map((f) => (
              <div
                key={f.finding_id}
                className="bg-bg-2 border border-line-soft px-3 py-1.5 flex items-center justify-between font-mono text-2xs"
              >
                <div>
                  <div className="text-ink-bright font-semibold">{f.name}</div>
                  <div className="text-muted">{f.explanation}</div>
                </div>
                <span className="text-suspicious font-bold">+{f.contribution} pts</span>
              </div>
            ))}
          </div>
        </section>

        {/* Forensic Report Export */}
        <section className="col-span-4 bg-panel border border-line p-3.5 flex flex-col justify-between">
          <div>
            <div className="text-2xs font-mono uppercase text-accent">FORENSIC REPORTING (13 SECTIONS)</div>
            <h2 className="text-sm font-semibold text-ink-bright mb-1">Generate Evidence-Backed Report</h2>
            <p className="text-2xs text-muted mb-3">
              Includes Executive Summary, Scope, Endpoint Identity, Methodology, Inventory, SHA-256 Integrity,
              Detections, Graph Summary, Timeline, MITRE ATT&CK, Notes, Conclusions & Limitations.
            </p>
            <div className="grid grid-cols-2 gap-2">
              <button
                disabled={!invId || reportBusy}
                onClick={() => handleGenerateReport('pdf')}
                className="py-2 px-3 bg-accent text-bg font-mono font-semibold text-xs uppercase hover:bg-accent/90 disabled:opacity-40"
              >
                Export PDF Report
              </button>
              <button
                disabled={!invId || reportBusy}
                onClick={() => handleGenerateReport('json')}
                className="py-2 px-3 border border-accent text-accent font-mono text-xs uppercase hover:bg-accent/10 disabled:opacity-40"
              >
                Export JSON
              </button>
            </div>
          </div>

          <div className="mt-3 pt-2.5 border-t border-line-soft font-mono text-2xs space-y-1 max-h-32 overflow-y-auto">
            <div className="text-muted uppercase">GENERATED REPORTS ({(reportsQuery.data ?? []).length})</div>
            {(reportsQuery.data ?? []).map((r) => (
              <div key={r.id} className="flex items-center justify-between bg-bg-2 px-2 py-1 border border-line-soft">
                <span>
                  {r.format.toUpperCase()} — {formatIso(r.created_at)}
                </span>
                <button
                  onClick={() =>
                    downloadAuthenticated(
                      r.download_url,
                      `TraceVault_Report_${r.id.slice(0, 8)}.${r.format}`,
                    )
                  }
                  className="text-accent hover:underline"
                >
                  Download
                </button>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Row 2: Incident Hypotheses & Analyst Notes */}
      <div className="grid grid-cols-12 gap-4">
        <section className="col-span-7 bg-panel border border-line p-3.5 space-y-3">
          <div>
            <div className="text-2xs font-mono uppercase text-accent">INCIDENT RECONSTRUCTION</div>
            <h3 className="text-xs font-semibold text-ink-bright">Analyst Hypotheses & Case Conclusions</h3>
          </div>

          <form onSubmit={handleCreateIncident} className="bg-bg-2 border border-line p-3 space-y-2 font-mono text-xs">
            <div className="grid grid-cols-3 gap-2">
              <input
                type="text"
                placeholder="Hypothesis / Incident title..."
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                className="col-span-1 bg-bg border border-line px-2 py-1 text-ink-bright"
                required
              />
              <input
                type="text"
                placeholder="Affected user (optional)"
                value={newUser}
                onChange={(e) => setNewUser(e.target.value)}
                className="bg-bg border border-line px-2 py-1 text-ink-bright"
              />
              <input
                type="text"
                placeholder="Affected process (optional)"
                value={newProc}
                onChange={(e) => setNewProc(e.target.value)}
                className="bg-bg border border-line px-2 py-1 text-ink-bright"
              />
            </div>
            <div className="flex space-x-2">
              <input
                type="text"
                placeholder="Describe hypothesis supported by forensic artifacts..."
                value={newHypothesis}
                onChange={(e) => setNewHypothesis(e.target.value)}
                className="flex-1 bg-bg border border-line px-2 py-1 text-ink-bright"
              />
              <button
                type="submit"
                className="px-3 py-1 bg-panel-2 border border-accent text-accent uppercase text-2xs"
              >
                + Record Hypothesis
              </button>
            </div>
          </form>

          <div className="space-y-2 max-h-64 overflow-y-auto">
            {(incidentsQuery.data ?? []).map((ic) => (
              <div key={ic.id} className="bg-bg-2 border border-line p-3">
                <div className="flex items-center justify-between">
                  <div className="font-semibold text-xs text-ink-bright">{ic.title}</div>
                  <select
                    value={ic.status}
                    onChange={(e) => handleUpdateIncidentStatus(ic, e.target.value as IncidentStatus)}
                    className="bg-bg border border-line px-2 py-0.5 font-mono text-2xs uppercase text-accent"
                  >
                    {INCIDENT_STATUSES.map((st) => (
                      <option key={st} value={st}>
                        {st}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="text-2xs font-mono text-muted mt-1">
                  User: {ic.affected_user ?? '—'} | Process: {ic.affected_process ?? '—'}
                </div>
                {ic.hypothesis && <div className="text-xs text-ink mt-1.5">{ic.hypothesis}</div>}
                {ic.conclusion && (
                  <div className="text-2xs font-mono text-verified mt-1">Conclusion: {ic.conclusion}</div>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* Analyst Notes */}
        <section className="col-span-5 bg-panel border border-line p-3.5 flex flex-col justify-between">
          <div>
            <div className="text-2xs font-mono uppercase text-accent">INVESTIGATION LOGBOOK</div>
            <h3 className="text-xs font-semibold text-ink-bright mb-2">Timestamped Analyst Notes</h3>

            <form onSubmit={handleAddNote} className="flex space-x-2 mb-3">
              <input
                type="text"
                placeholder="Add investigative observation..."
                value={noteBody}
                onChange={(e) => setNoteBody(e.target.value)}
                className="flex-1 bg-bg border border-line px-2.5 py-1.5 text-xs font-mono text-ink-bright"
              />
              <button
                type="submit"
                className="px-3 py-1.5 border border-accent text-accent font-mono text-2xs uppercase"
              >
                Add Note
              </button>
            </form>

            <div className="space-y-2 max-h-60 overflow-y-auto font-mono text-2xs">
              {(notesQuery.data ?? []).map((n) => (
                <div key={n.id} className="bg-bg-2 border border-line-soft p-2">
                  <div className="text-muted">
                    {formatIso(n.created_at)} — <strong className="text-accent">{n.author}</strong>
                  </div>
                  <div className="text-ink-bright mt-0.5 font-sans text-xs">{n.body}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>

      {/* Row 3: Full Findings List & Immutable Chain of Custody */}
      <div className="grid grid-cols-12 gap-4">
        <section className="col-span-6 bg-panel border border-line p-3.5">
          <div className="text-2xs font-mono uppercase text-accent">DETECTION LEDGER</div>
          <h3 className="text-xs font-semibold text-ink-bright mb-2">
            All Triggered Forensic Rules ({(findingsQuery.data ?? []).length})
          </h3>
          <div className="space-y-2 max-h-72 overflow-y-auto">
            {(findingsQuery.data ?? []).map((f) => (
              <div key={f.id} className="bg-bg-2 border border-line p-2.5 text-xs">
                <div className="flex items-center justify-between font-mono text-2xs">
                  <span style={{ color: SEVERITY_COLORS[f.severity] }} className="font-bold uppercase">
                    [{f.severity}] {f.rule_id} — {f.name}
                  </span>
                  {f.mitre && <span className="text-secondary">{f.mitre.technique_id}</span>}
                </div>
                <div className="text-ink mt-1">{f.description}</div>
                <div className="font-mono text-2xs text-muted mt-1">Logic: {f.detection_logic}</div>
                <div className="font-mono text-2xs text-muted mt-1 italic">{f.disclaimer}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="col-span-6 bg-panel border border-line p-3.5">
          <div className="text-2xs font-mono uppercase text-accent">CHAIN OF CUSTODY</div>
          <h3 className="text-xs font-semibold text-ink-bright mb-2">
            Immutable Acquisition & Verification Log ({(custodyQuery.data ?? []).length})
          </h3>
          <div className="max-h-72 overflow-y-auto border border-line-soft">
            <table className="w-full text-left border-collapse font-mono text-2xs">
              <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                <tr>
                  <th className="p-2 border-b border-line">Timestamp (UTC)</th>
                  <th className="p-2 border-b border-line">Action</th>
                  <th className="p-2 border-b border-line">Actor</th>
                  <th className="p-2 border-b border-line">Verification</th>
                  <th className="p-2 border-b border-line">SHA-256</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-soft">
                {(custodyQuery.data ?? []).map((c) => (
                  <tr key={c.id}>
                    <td className="p-2 whitespace-nowrap">{formatIso(c.timestamp)}</td>
                    <td className="p-2 text-ink-bright">{c.action}</td>
                    <td className="p-2 text-accent">{c.actor}</td>
                    <td className="p-2">
                      <span
                        className={
                          c.verification_status === 'verified'
                            ? 'text-verified'
                            : c.verification_status === 'mismatch'
                              ? 'text-critical'
                              : 'text-muted'
                        }
                      >
                        {c.verification_status ?? '—'}
                      </span>
                    </td>
                    <td className="p-2 text-muted">{c.sha256 ? `${c.sha256.slice(0, 16)}...` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
};
