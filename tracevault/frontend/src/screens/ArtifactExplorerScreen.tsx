import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import {
  ARTIFACT_SOURCES,
  type AmcacheRecord,
  type ArtifactRow,
  type ArtifactSource,
  type BrowserRecord,
  type EvtxRecord,
  type FilesystemRecord,
  type PrefetchRecord,
  type RegistryRecord,
} from '../api/types';
import { useWorkstation } from '../components/WorkstationContext';
import { formatBytes, formatIso, SOURCE_COLORS, SOURCE_LABELS } from '../theme/tokens';

export const ArtifactExplorerScreen: React.FC = () => {
  const { activeInvestigation } = useWorkstation();
  const [activeTab, setActiveTab] = useState<ArtifactSource>('evtx');
  const [searchQ, setSearchQ] = useState('');
  const [page, setPage] = useState(1);
  const [selectedRow, setSelectedRow] = useState<ArtifactRow<Record<string, unknown>> | null>(null);

  const invId = activeInvestigation?.id ?? null;

  const summaryQuery = useQuery({
    queryKey: ['summary', invId],
    queryFn: () => api.summary(invId!),
    enabled: Boolean(invId),
  });

  const latestScanId = summaryQuery.data?.latest_scan?.id ?? null;

  const scanArtifactsQuery = useQuery({
    queryKey: ['scanArtifacts', latestScanId],
    queryFn: () => api.scanArtifacts(latestScanId!),
    enabled: Boolean(latestScanId),
  });

  const recordsQuery = useQuery({
    queryKey: ['artifactRecords', invId, activeTab, searchQ, page],
    queryFn: () =>
      api.artifacts<Record<string, unknown>>(invId!, activeTab, {
        q: searchQ || undefined,
        page,
        page_size: 50,
      }),
    enabled: Boolean(invId),
  });

  const sourceArtifacts = (scanArtifactsQuery.data ?? []).filter((a) => a.source === activeTab);
  const rows = recordsQuery.data?.items ?? [];

  return (
    <div className="h-full flex flex-col overflow-hidden p-4 space-y-3">
      {/* Top Artifact Source Tabs & Search */}
      <div className="bg-panel border border-line p-3 flex items-center justify-between shrink-0">
        <div className="flex items-center space-x-2">
          {ARTIFACT_SOURCES.map((src) => (
            <button
              key={src}
              onClick={() => {
                setActiveTab(src);
                setPage(1);
                setSelectedRow(null);
              }}
              className={`px-3 py-1.5 border font-mono text-xs uppercase transition-colors ${
                activeTab === src
                  ? 'border-accent bg-panel-2 text-ink-bright'
                  : 'border-line bg-bg-2 text-muted hover:text-ink'
              }`}
            >
              <span
                className="inline-block w-2 h-2 mr-2"
                style={{ backgroundColor: SOURCE_COLORS[src] }}
              />
              {SOURCE_LABELS[src]}
            </button>
          ))}
        </div>

        <div className="flex items-center space-x-2">
          <input
            type="text"
            placeholder={`Search ${activeTab.toUpperCase()} records...`}
            value={searchQ}
            onChange={(e) => {
              setSearchQ(e.target.value);
              setPage(1);
            }}
            className="bg-bg border border-line px-3 py-1 text-xs font-mono text-ink-bright w-64 focus:outline-none focus:border-accent"
          />
        </div>
      </div>

      {/* Source Acquisition & Integrity Banner */}
      <div className="bg-panel border border-line px-3.5 py-2 flex items-center justify-between font-mono text-2xs shrink-0">
        <div className="flex items-center space-x-4 overflow-x-auto">
          <span className="text-accent uppercase font-semibold">ACQUISITION STATUS:</span>
          {sourceArtifacts.map((sa) => (
            <span key={sa.id} className="border-l border-line pl-3">
              <strong className="text-ink-bright">{sa.artifact_key}</strong>:{' '}
              <span
                className={
                  sa.status === 'collected'
                    ? 'text-verified'
                    : sa.status === 'permission_denied'
                      ? 'text-suspicious'
                      : 'text-muted'
                }
              >
                {sa.status.toUpperCase()}
              </span>{' '}
              ({sa.record_count} recs, parser={sa.parser}, integrity={sa.verification_status})
              {sa.error ? ` — ${sa.error}` : ''}
            </span>
          ))}
          {sourceArtifacts.length === 0 && (
            <span className="text-muted">No collection metadata recorded for this artifact source yet.</span>
          )}
        </div>

        {activeTab === 'amcache' && (
          <span className="px-2 py-0.5 border border-suspicious text-suspicious shrink-0">
            NOTE: Amcache records represent application inventory, NOT proof of execution.
          </span>
        )}
      </div>

      {/* Main Split: Purpose-Built Artifact Table + Raw Provenance & XML/Decoded Inspector */}
      <div className="flex-1 grid grid-cols-12 gap-4 overflow-hidden">
        <section className="col-span-8 bg-panel border border-line flex flex-col overflow-hidden">
          <div className="flex-1 overflow-auto">
            {activeTab === 'evtx' && (
              <table className="w-full text-left border-collapse font-mono text-2xs">
                <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                  <tr>
                    <th className="p-2 border-b border-line">Time Created (UTC)</th>
                    <th className="p-2 border-b border-line">Channel</th>
                    <th className="p-2 border-b border-line">Event ID</th>
                    <th className="p-2 border-b border-line">Record #</th>
                    <th className="p-2 border-b border-line">Provider</th>
                    <th className="p-2 border-b border-line">Key EventData Fields</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {rows.map((r) => {
                    const d = r.data as unknown as EvtxRecord;
                    return (
                      <tr
                        key={r.id}
                        onClick={() => setSelectedRow(r)}
                        className={`cursor-pointer hover:bg-panel-2 ${selectedRow?.id === r.id ? 'bg-panel-2' : ''}`}
                      >
                        <td className="p-2 whitespace-nowrap">{formatIso(d.time_created)}</td>
                        <td className="p-2 text-accent">{d.channel}</td>
                        <td className="p-2 font-bold text-ink-bright">{d.event_id}</td>
                        <td className="p-2 text-muted">{d.record_number}</td>
                        <td className="p-2 truncate max-w-[140px]">{d.provider}</td>
                        <td className="p-2 text-muted truncate max-w-[260px]">
                          {JSON.stringify(d.event_data ?? {})}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {activeTab === 'registry' && (
              <table className="w-full text-left border-collapse font-mono text-2xs">
                <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                  <tr>
                    <th className="p-2 border-b border-line">Category</th>
                    <th className="p-2 border-b border-line">Hive & Key Path</th>
                    <th className="p-2 border-b border-line">Value Name</th>
                    <th className="p-2 border-b border-line">Value Data / Decoded</th>
                    <th className="p-2 border-b border-line">Key Last-Write</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {rows.map((r) => {
                    const d = r.data as unknown as RegistryRecord;
                    return (
                      <tr
                        key={r.id}
                        onClick={() => setSelectedRow(r)}
                        className={`cursor-pointer hover:bg-panel-2 ${selectedRow?.id === r.id ? 'bg-panel-2' : ''}`}
                      >
                        <td className="p-2 uppercase text-accent">{d.category}</td>
                        <td className="p-2 truncate max-w-[220px]" title={d.key_path}>
                          {d.key_path}
                        </td>
                        <td className="p-2 text-ink-bright">{d.value_name ?? '—'}</td>
                        <td className="p-2 truncate max-w-[240px]">
                          {d.decoded ? JSON.stringify(d.decoded) : String(d.value_data ?? '')}
                        </td>
                        <td className="p-2 whitespace-nowrap text-muted">{formatIso(d.last_write)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {activeTab === 'prefetch' && (
              <table className="w-full text-left border-collapse font-mono text-2xs">
                <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                  <tr>
                    <th className="p-2 border-b border-line">Executable</th>
                    <th className="p-2 border-b border-line">Prefetch Hash</th>
                    <th className="p-2 border-b border-line">Run Count</th>
                    <th className="p-2 border-b border-line">Last Run / Modified</th>
                    <th className="p-2 border-b border-line">Referenced Files</th>
                    <th className="p-2 border-b border-line">Parser</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {rows.map((r) => {
                    const d = r.data as unknown as PrefetchRecord;
                    return (
                      <tr
                        key={r.id}
                        onClick={() => setSelectedRow(r)}
                        className={`cursor-pointer hover:bg-panel-2 ${selectedRow?.id === r.id ? 'bg-panel-2' : ''}`}
                      >
                        <td className="p-2 font-bold text-ink-bright">{d.executable}</td>
                        <td className="p-2 text-accent">{d.prefetch_hash ?? '—'}</td>
                        <td className="p-2">{d.run_count ?? 'N/A (metadata)'}</td>
                        <td className="p-2 whitespace-nowrap">
                          {formatIso(d.last_run_times?.[0] ?? d.pf_modified)}
                        </td>
                        <td className="p-2 text-muted">{(d.referenced_files ?? []).length} files</td>
                        <td className="p-2 text-muted">{d.parser}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {activeTab === 'amcache' && (
              <table className="w-full text-left border-collapse font-mono text-2xs">
                <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                  <tr>
                    <th className="p-2 border-b border-line">Program Path (Inventory)</th>
                    <th className="p-2 border-b border-line">SHA-1</th>
                    <th className="p-2 border-b border-line">Publisher</th>
                    <th className="p-2 border-b border-line">Size</th>
                    <th className="p-2 border-b border-line">Key Last-Write</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {rows.map((r) => {
                    const d = r.data as unknown as AmcacheRecord;
                    return (
                      <tr
                        key={r.id}
                        onClick={() => setSelectedRow(r)}
                        className={`cursor-pointer hover:bg-panel-2 ${selectedRow?.id === r.id ? 'bg-panel-2' : ''}`}
                      >
                        <td className="p-2 text-ink-bright truncate max-w-[260px]" title={d.program_path ?? ''}>
                          {d.program_path ?? d.name}
                        </td>
                        <td className="p-2 text-accent">{d.sha1 ?? '—'}</td>
                        <td className="p-2">{d.publisher ?? '—'}</td>
                        <td className="p-2">{formatBytes(d.size)}</td>
                        <td className="p-2 whitespace-nowrap text-muted">{formatIso(d.key_last_write)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {activeTab === 'browser' && (
              <table className="w-full text-left border-collapse font-mono text-2xs">
                <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                  <tr>
                    <th className="p-2 border-b border-line">Browser / Profile</th>
                    <th className="p-2 border-b border-line">Kind</th>
                    <th className="p-2 border-b border-line">Timestamp (UTC)</th>
                    <th className="p-2 border-b border-line">URL</th>
                    <th className="p-2 border-b border-line">Target Path / Title</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {rows.map((r) => {
                    const d = r.data as unknown as BrowserRecord;
                    return (
                      <tr
                        key={r.id}
                        onClick={() => setSelectedRow(r)}
                        className={`cursor-pointer hover:bg-panel-2 ${selectedRow?.id === r.id ? 'bg-panel-2' : ''}`}
                      >
                        <td className="p-2 uppercase">
                          {d.browser} / {d.profile}
                        </td>
                        <td className="p-2">
                          <span
                            className={`px-1.5 py-0.5 border uppercase ${
                              d.kind === 'download'
                                ? 'border-suspicious text-suspicious'
                                : 'border-line text-accent'
                            }`}
                          >
                            {d.kind}
                          </span>
                        </td>
                        <td className="p-2 whitespace-nowrap">
                          {formatIso(d.start_time ?? d.visit_time)}
                        </td>
                        <td className="p-2 text-ink-bright truncate max-w-[240px]" title={d.url}>
                          {d.url}
                        </td>
                        <td className="p-2 text-muted truncate max-w-[220px]" title={d.target_path ?? d.title ?? ''}>
                          {d.target_path ?? d.title ?? '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {activeTab === 'filesystem' && (
              <table className="w-full text-left border-collapse font-mono text-2xs">
                <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                  <tr>
                    <th className="p-2 border-b border-line">Kind</th>
                    <th className="p-2 border-b border-line">Path / Original Deleted Path</th>
                    <th className="p-2 border-b border-line">Size</th>
                    <th className="p-2 border-b border-line">Created / Deleted (UTC)</th>
                    <th className="p-2 border-b border-line">Modified (UTC)</th>
                    <th className="p-2 border-b border-line">SHA-256</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {rows.map((r) => {
                    const d = r.data as unknown as FilesystemRecord;
                    return (
                      <tr
                        key={r.id}
                        onClick={() => setSelectedRow(r)}
                        className={`cursor-pointer hover:bg-panel-2 ${selectedRow?.id === r.id ? 'bg-panel-2' : ''}`}
                      >
                        <td className="p-2 uppercase text-accent">{d.kind}</td>
                        <td className="p-2 text-ink-bright truncate max-w-[260px]" title={d.original_path ?? d.path}>
                          {d.original_path ? `${d.original_path} (from ${d.path})` : d.path}
                        </td>
                        <td className="p-2">{formatBytes(d.size)}</td>
                        <td className="p-2 whitespace-nowrap">{formatIso(d.deleted_time ?? d.created)}</td>
                        <td className="p-2 whitespace-nowrap text-muted">{formatIso(d.modified)}</td>
                        <td className="p-2 text-muted">{d.sha256 ? `${d.sha256.slice(0, 14)}...` : '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {rows.length === 0 && (
              <div className="p-6 text-center font-mono text-xs text-muted">
                No {activeTab.toUpperCase()} records collected or matching current filter.
                {sourceArtifacts.some((a) => a.status === 'permission_denied') && (
                  <div className="text-suspicious mt-1">
                    Source reported PERMISSION_DENIED during non-elevated collection. Run collector as Administrator to
                    acquire this source.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Pagination Footer */}
          <div className="h-9 bg-bg-2 border-t border-line px-3 flex items-center justify-between font-mono text-2xs shrink-0">
            <span>
              Total {activeTab.toUpperCase()} Records: <strong>{recordsQuery.data?.total ?? 0}</strong>
            </span>
            <div className="flex items-center space-x-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="px-2 py-0.5 border border-line bg-panel disabled:opacity-40"
              >
                Prev
              </button>
              <span>Page {page}</span>
              <button
                disabled={page * 50 >= (recordsQuery.data?.total ?? 0)}
                onClick={() => setPage((p) => p + 1)}
                className="px-2 py-0.5 border border-line bg-panel disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        </section>

        {/* Right: Raw Record & Chain-of-Custody Provenance Viewer */}
        <section className="col-span-4 bg-panel border border-line p-3.5 overflow-y-auto">
          <div className="text-2xs font-mono uppercase text-accent">RAW ARTIFACT PROVENANCE</div>
          <h3 className="text-xs font-semibold text-ink-bright border-b border-line-soft pb-2 mb-3">
            Source Traceability & Payload
          </h3>

          {selectedRow ? (
            <div className="space-y-3 font-mono text-2xs">
              <div className="bg-bg-2 border border-line p-2.5 space-y-1">
                <div>
                  <span className="text-muted">Artifact Key:</span>{' '}
                  <span className="text-ink-bright">{selectedRow.artifact_key}</span>
                </div>
                <div>
                  <span className="text-muted">Record ID:</span>{' '}
                  <span className="text-accent break-all">{selectedRow.record_id}</span>
                </div>
                <div>
                  <span className="text-muted">Original Path:</span>{' '}
                  <span className="text-ink break-all">{selectedRow.original_path ?? '—'}</span>
                </div>
                <div>
                  <span className="text-muted">Artifact SHA-256:</span>{' '}
                  <span className="text-verified break-all">{selectedRow.sha256 ?? '—'}</span>
                </div>
              </div>

              <div>
                <div className="text-muted uppercase mb-1">STRUCTURED RECORD PAYLOAD</div>
                <pre className="bg-bg border border-line-soft p-2.5 overflow-x-auto text-ink max-h-96 whitespace-pre-wrap">
                  {JSON.stringify(selectedRow.data, null, 2)}
                </pre>
              </div>
            </div>
          ) : (
            <div className="bg-bg-2 border border-line-soft p-3 font-mono text-2xs text-muted">
              Select any artifact record row on the left to inspect its raw JSON/XML fields, source path, and SHA-256
              integrity digest.
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
