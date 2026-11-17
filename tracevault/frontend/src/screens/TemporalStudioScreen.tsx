import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import * as d3 from 'd3';
import { api } from '../api/client';
import {
  ARTIFACT_SOURCES,
  TIMELINE_GROUPS,
  type ArtifactSource,
  type TimelineEvent,
  type TimelineGroup,
} from '../api/types';
import { useWorkstation } from '../components/WorkstationContext';
import { formatIso, SEVERITY_COLORS, SOURCE_COLORS } from '../theme/tokens';

export const TemporalStudioScreen: React.FC = () => {
  const nav = useNavigate();
  const {
    activeInvestigation,
    setFocusedEntityId,
    timeTravelCursor,
    setTimeTravelCursor,
  } = useWorkstation();

  const [selectedGroups, setSelectedGroups] = useState<TimelineGroup[]>([...TIMELINE_GROUPS]);
  const [selectedSources, setSelectedSources] = useState<ArtifactSource[]>([...ARTIFACT_SOURCES]);
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);

  const invId = activeInvestigation?.id ?? null;

  const timelineQuery = useQuery({
    queryKey: ['timeline', invId, selectedGroups, selectedSources, suspiciousOnly],
    queryFn: () =>
      api.timeline(invId!, {
        groups: selectedGroups,
        sources: selectedSources,
        suspicious_only: suspiciousOnly,
        limit: 2000,
      }),
    enabled: Boolean(invId),
  });

  const timeTravelGraphQuery = useQuery({
    queryKey: ['timeTravelGraph', invId, timeTravelCursor],
    queryFn: () => api.graph(invId!, { at: timeTravelCursor }),
    enabled: Boolean(invId),
  });

  const events = timelineQuery.data?.events ?? [];
  const timedEvents = useMemo(
    () =>
      events
        .filter((e) => Boolean(e.timestamp))
        .map((e) => ({
          ev: e,
          ms: new Date(e.timestamp!).getTime(),
        }))
        .filter((x) => !Number.isNaN(x.ms))
        .sort((a, b) => a.ms - b.ms),
    [events],
  );

  // D3 scale for swimlane positions
  const { xScale, minMs, maxMs } = useMemo(() => {
    if (timedEvents.length === 0) {
      const now = Date.now();
      return {
        xScale: d3.scaleTime().domain([new Date(now - 3600000), new Date(now)]).range([110, 920]),
        minMs: now - 3600000,
        maxMs: now,
      };
    }
    const lo = d3.min(timedEvents, (d) => d.ms)!;
    const hi = Math.max(lo + 1000, d3.max(timedEvents, (d) => d.ms)!);
    return {
      xScale: d3.scaleTime().domain([new Date(lo), new Date(hi)]).range([110, 920]),
      minMs: lo,
      maxMs: hi,
    };
  }, [timedEvents]);

  const cursorMs = timeTravelCursor ? new Date(timeTravelCursor).getTime() : maxMs;

  const toggleGroup = (g: TimelineGroup) =>
    setSelectedGroups((prev) => (prev.includes(g) ? prev.filter((x) => x !== g) : [...prev, g]));

  const toggleSource = (s: ArtifactSource) =>
    setSelectedSources((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4">
      {/* Header & Controls */}
      <section className="bg-panel border border-line p-3.5 flex items-center justify-between">
        <div>
          <div className="text-2xs font-mono uppercase text-accent">TEMPORAL RECONSTRUCTION STUDIO</div>
          <h2 className="text-sm font-semibold text-ink-bright">
            Chronological Swimlanes & Time Travel Investigation
          </h2>
          <div className="text-2xs font-mono text-muted mt-0.5">
            Event Bounds: {formatIso(timelineQuery.data?.bounds.start)} → {formatIso(timelineQuery.data?.bounds.end)} |{' '}
            <span className="text-accent">
              Artifact Collection Marker: {formatIso(timelineQuery.data?.collection_time)}
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-3 font-mono text-2xs">
          <label className="flex items-center space-x-1.5 cursor-pointer text-suspicious">
            <input
              type="checkbox"
              checked={suspiciousOnly}
              onChange={(e) => setSuspiciousOnly(e.target.checked)}
            />
            <span>SUSPICIOUS ONLY</span>
          </label>
          <div className="flex space-x-1 border-l border-line pl-3">
            {TIMELINE_GROUPS.map((g) => (
              <button
                key={g}
                onClick={() => toggleGroup(g)}
                className={`px-2 py-1 border uppercase ${
                  selectedGroups.includes(g)
                    ? 'border-accent bg-panel-2 text-ink-bright'
                    : 'border-line bg-bg text-muted opacity-50'
                }`}
              >
                {g}
              </button>
            ))}
          </div>
          <div className="flex space-x-1 border-l border-line pl-3">
            {ARTIFACT_SOURCES.map((s) => (
              <button
                key={s}
                onClick={() => toggleSource(s)}
                className={`px-2 py-1 border uppercase ${
                  selectedSources.includes(s)
                    ? 'border-line bg-bg-2 text-ink'
                    : 'border-transparent bg-bg text-muted opacity-40'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* D3 Multi-Lane Swimlane Canvas & Time Travel Slider */}
      <section className="bg-panel border border-line p-3.5">
        <div className="flex items-center justify-between mb-2 font-mono text-xs">
          <div className="flex items-center space-x-3">
            <span className="text-relation font-semibold uppercase">TIME TRAVEL CURSOR:</span>
            <span className="text-ink-bright">
              {timeTravelCursor ? formatIso(timeTravelCursor) : 'Present (All Observed Events)'}
            </span>
          </div>
          <div className="flex items-center space-x-3 text-2xs">
            <span className="text-muted">
              Supported Graph Relationships ≤ Cursor:{' '}
              <strong className="text-accent">{timeTravelGraphQuery.data?.stats.edge_count ?? 0}</strong> edges /{' '}
              <strong className="text-ink-bright">{timeTravelGraphQuery.data?.stats.node_count ?? 0}</strong> nodes
            </span>
            <button
              onClick={() => nav('/universe')}
              className="px-2 py-0.5 border border-accent text-accent hover:bg-accent hover:text-bg"
            >
              View in Evidence Universe →
            </button>
          </div>
        </div>

        {timedEvents.length > 0 && (
          <div className="flex items-center space-x-3 mb-3">
            <span className="text-2xs font-mono text-muted">SCRUB TIME:</span>
            <input
              type="range"
              min={minMs}
              max={maxMs}
              value={cursorMs}
              onChange={(e) => {
                const v = Number(e.target.value);
                if (v >= maxMs) setTimeTravelCursor(null);
                else setTimeTravelCursor(new Date(v).toISOString());
              }}
              className="flex-1 accent-relation cursor-pointer"
            />
            {timeTravelCursor && (
              <button
                onClick={() => setTimeTravelCursor(null)}
                className="px-2 py-0.5 border border-line bg-bg-2 text-2xs font-mono text-ink"
              >
                Reset
              </button>
            )}
          </div>
        )}

        <div className="bg-bg border border-line-soft overflow-x-auto">
          <svg viewBox="0 0 960 220" className="w-full h-56">
            {/* Swimlane rows */}
            {TIMELINE_GROUPS.map((grp, idx) => {
              const y = 28 + idx * 30;
              return (
                <g key={grp}>
                  <line x1={105} y1={y} x2={935} y2={y} stroke="#252D38" strokeWidth={1} />
                  <text
                    x={12}
                    y={y + 4}
                    fill="#929EAC"
                    fontFamily="JetBrains Mono, monospace"
                    fontSize={10}
                  >
                    {grp.toUpperCase()}
                  </text>
                </g>
              );
            })}

            {/* Event ticks (capped at 600 SVG nodes for instant switching on 5k-event scans) */}
            {timedEvents.slice(0, 600).map(({ ev, ms }) => {
              const laneIdx = Math.max(0, TIMELINE_GROUPS.indexOf(ev.group));
              const cy = 28 + laneIdx * 30;
              const cx = xScale(new Date(ms));
              const afterCursor = timeTravelCursor ? ms > cursorMs : false;
              const fill = ev.suspicious
                ? SEVERITY_COLORS[ev.severity]
                : SOURCE_COLORS[ev.artifact_source] || '#67C8D8';
              return (
                <circle
                  key={ev.id}
                  cx={cx}
                  cy={cy}
                  r={ev.suspicious ? 5.5 : 3.5}
                  fill={fill}
                  opacity={afterCursor ? 0.18 : 0.9}
                  stroke={selectedEvent?.id === ev.id ? '#EEF2F6' : '#101318'}
                  strokeWidth={selectedEvent?.id === ev.id ? 2 : 0.8}
                  className="cursor-pointer"
                  onClick={() => setSelectedEvent(ev)}
                >
                  <title>{`${ev.timestamp} — ${ev.summary}`}</title>
                </circle>
              );
            })}

            {/* Time Travel Cursor vertical line */}
            {timedEvents.length > 0 && (
              <line
                x1={xScale(new Date(cursorMs))}
                y1={10}
                x2={xScale(new Date(cursorMs))}
                y2={205}
                stroke="#B08CFF"
                strokeWidth={1.8}
                strokeDasharray="4 3"
              />
            )}
          </svg>
        </div>
      </section>

      {/* Bottom Split: Chronological Event Stream + Selected Event Provenance */}
      <div className="grid grid-cols-12 gap-4">
        <section className="col-span-8 bg-panel border border-line p-3.5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold text-ink-bright font-mono uppercase">
              CHRONOLOGICAL EVENT LEDGER ({events.length} shown / {timelineQuery.data?.total ?? 0} total)
            </h3>
            <span className="text-2xs font-mono text-muted">
              Distinguishes Observed Event Time (UTC) vs Artifact Collection Time
            </span>
          </div>

          <div className="max-h-96 overflow-y-auto border border-line-soft">
            <table className="w-full text-left border-collapse font-mono text-2xs">
              <thead className="bg-bg-2 text-muted uppercase sticky top-0">
                <tr>
                  <th className="p-2 border-b border-line">Event Timestamp (UTC)</th>
                  <th className="p-2 border-b border-line">Precision</th>
                  <th className="p-2 border-b border-line">Group</th>
                  <th className="p-2 border-b border-line">Source</th>
                  <th className="p-2 border-b border-line">Forensic Event Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-soft">
                {events.slice(0, 400).map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => setSelectedEvent(ev)}
                    className={`cursor-pointer hover:bg-panel-2 ${
                      selectedEvent?.id === ev.id ? 'bg-panel-2' : ''
                    } ${ev.suspicious ? 'text-suspicious' : 'text-ink'}`}
                  >
                    <td className="p-2 whitespace-nowrap">{formatIso(ev.timestamp)}</td>
                    <td className="p-2 text-muted">{ev.timestamp_precision ?? '—'}</td>
                    <td className="p-2 uppercase">{ev.group}</td>
                    <td className="p-2 uppercase" style={{ color: SOURCE_COLORS[ev.artifact_source] }}>
                      {ev.artifact_source}
                    </td>
                    <td className="p-2 text-ink-bright truncate max-w-md" title={ev.summary}>
                      {ev.summary}
                    </td>
                  </tr>
                ))}
                {events.length === 0 && (
                  <tr>
                    <td colSpan={5} className="p-4 text-center text-muted">
                      No timeline events match current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="col-span-4 bg-panel border border-line p-3.5">
          <div className="text-2xs font-mono uppercase text-accent">SELECTED EVENT CONTEXT</div>
          <h3 className="text-xs font-semibold text-ink-bright border-b border-line-soft pb-2 mb-3">
            Event Provenance & Graph Sync
          </h3>

          {selectedEvent ? (
            <div className="space-y-2.5 font-mono text-2xs">
              <div className="bg-bg-2 border border-line p-2.5">
                <div className="text-muted">EVENT TYPE // SEVERITY</div>
                <div className="text-xs font-semibold text-ink-bright mt-0.5">
                  {selectedEvent.event_type} ({selectedEvent.severity.toUpperCase()})
                </div>
              </div>
              <div>
                <span className="text-muted">Event Time:</span>{' '}
                <span className="text-ink-bright">{formatIso(selectedEvent.timestamp)}</span> (
                {selectedEvent.timestamp_precision ?? 'unknown'})
              </div>
              <div>
                <span className="text-muted">Source Record ID:</span>{' '}
                <span className="text-accent break-all">{selectedEvent.source_record_id ?? '—'}</span>
              </div>
              <div>
                <span className="text-muted">Summary:</span>
                <div className="bg-bg-2 border border-line-soft p-2 mt-1 text-ink break-words">
                  {selectedEvent.summary}
                </div>
              </div>

              <div className="pt-2 space-y-1.5">
                {selectedEvent.timestamp && (
                  <button
                    onClick={() => setTimeTravelCursor(selectedEvent.timestamp)}
                    className="w-full py-1.5 px-2 border border-relation text-relation uppercase hover:bg-relation/10"
                  >
                    Set Time Travel Cursor to This Event
                  </button>
                )}
                {selectedEvent.entity_ids.length > 0 && (
                  <button
                    onClick={() => {
                      setFocusedEntityId(selectedEvent.entity_ids[0]);
                      nav('/universe');
                    }}
                    className="w-full py-1.5 px-2 border border-accent text-accent uppercase hover:bg-accent hover:text-bg"
                  >
                    Focus Entity in Evidence Universe →
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-bg-2 border border-line-soft p-3 font-mono text-2xs text-muted">
              Click any event in the swimlane chart or chronological ledger to inspect its timestamp precision, source
              record ID, and synchronize with the Evidence Universe graph.
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
