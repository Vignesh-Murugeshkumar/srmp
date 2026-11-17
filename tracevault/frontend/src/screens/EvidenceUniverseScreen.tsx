import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import cytoscape, { type Core } from 'cytoscape';
import dagre from 'cytoscape-dagre';
import fcose from 'cytoscape-fcose';
import { api } from '../api/client';
import {
  ARTIFACT_SOURCES,
  EVIDENCE_CLASSES,
  RELATIONSHIP_TYPES,
  type ArtifactSource,
  type EvidenceClass,
  type Relationship,
  type RelationshipType,
} from '../api/types';
import { useWorkstation } from '../components/WorkstationContext';
import { buildCytoscapeElements, findSuspiciousPathSet, type GraphViewMode } from '../graph/graphHelpers';
import {
  ENTITY_COLORS,
  EVIDENCE_CLASS_META,
  formatIso,
  SEVERITY_COLORS,
  SOURCE_COLORS,
} from '../theme/tokens';

try {
  cytoscape.use(dagre);
  cytoscape.use(fcose);
} catch {
  /* already registered */
}

export const EvidenceUniverseScreen: React.FC = () => {
  const {
    activeInvestigation,
    focusedEntityId,
    setFocusedEntityId,
    timeTravelCursor,
    setTimeTravelCursor,
  } = useWorkstation();

  const [viewMode, setViewMode] = useState<GraphViewMode>('relationship');
  const [selectedSources, setSelectedSources] = useState<ArtifactSource[]>([...ARTIFACT_SOURCES]);
  const [selectedClasses, setSelectedClasses] = useState<EvidenceClass[]>([...EVIDENCE_CLASSES]);
  const [selectedRelTypes, setSelectedRelTypes] = useState<RelationshipType[]>([...RELATIONSHIP_TYPES]);
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [highlightSuspiciousPaths, setHighlightSuspiciousPaths] = useState(false);
  const [searchText, setSearchText] = useState('');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<Relationship | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  const invId = activeInvestigation?.id ?? null;

  const graphQuery = useQuery({
    queryKey: [
      'evidenceGraph',
      invId,
      timeTravelCursor,
      selectedSources,
      selectedClasses,
      selectedRelTypes,
      focusedEntityId,
      suspiciousOnly,
    ],
    queryFn: () =>
      api.graph(invId!, {
        at: timeTravelCursor,
        sources: selectedSources,
        evidence_classes: selectedClasses,
        relationship_types: selectedRelTypes,
        focus: focusedEntityId,
        depth: 2,
        suspicious_only: suspiciousOnly,
      }),
    enabled: Boolean(invId),
  });

  const entityDetailQuery = useQuery({
    queryKey: ['evidenceDetail', invId, selectedNodeId],
    queryFn: () => api.evidenceDetail(invId!, selectedNodeId!),
    enabled: Boolean(invId && selectedNodeId),
  });

  const timelineRangeQuery = useQuery({
    queryKey: ['timelineRange', invId],
    queryFn: () => api.timelineRange(invId!, 100),
    enabled: Boolean(invId),
  });

  const suspiciousPathSet = useMemo(() => {
    if (!highlightSuspiciousPaths || !graphQuery.data) return new Set<string>();
    return findSuspiciousPathSet(graphQuery.data);
  }, [highlightSuspiciousPaths, graphQuery.data]);

  const filteredGraph = useMemo(() => {
    if (!graphQuery.data) return null;
    if (!searchText.trim()) return graphQuery.data;
    const q = searchText.toLowerCase();
    const matchedIds = new Set(
      graphQuery.data.nodes
        .filter((n) => n.label.toLowerCase().includes(q) || n.key.toLowerCase().includes(q))
        .map((n) => n.id),
    );
    // Keep neighbors of matched nodes so relationships remain visible
    const edges = graphQuery.data.edges.filter(
      (e) => matchedIds.has(e.source) || matchedIds.has(e.target),
    );
    edges.forEach((e) => {
      matchedIds.add(e.source);
      matchedIds.add(e.target);
    });
    const nodes = graphQuery.data.nodes.filter((n) => matchedIds.has(n.id));
    return {
      nodes,
      edges,
      stats: {
        node_count: nodes.length,
        edge_count: edges.length,
        truncated: graphQuery.data.stats.truncated,
      },
    };
  }, [graphQuery.data, searchText]);

  // Destroy Cytoscape instance cleanly on component unmount
  useEffect(() => {
    return () => {
      try {
        cyRef.current?.destroy();
      } catch {
        /* ignore */
      }
      cyRef.current = null;
    };
  }, []);

  // Mount & update Cytoscape instance
  useEffect(() => {
    if (!containerRef.current || !filteredGraph) return;

    const elements = buildCytoscapeElements(filteredGraph, viewMode, suspiciousPathSet);

    if (!cyRef.current) {
      cyRef.current = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              shape: 'data(shape)' as never,
              'background-color': 'data(color)',
              'border-width': 2,
              'border-color': 'data(borderColor)',
              label: 'data(label)',
              color: '#D7DEE6',
              'font-family': 'Inter, sans-serif',
              'font-size': 10,
              'text-valign': 'bottom',
              'text-margin-y': 5,
              'text-max-width': '130px',
              'text-wrap': 'ellipsis',
              width: 26,
              height: 26,
            },
          },
          {
            selector: 'node.suspicious-node',
            style: {
              'border-width': 3,
              'border-color': '#E6AA55',
              width: 32,
              height: 32,
            },
          },
          {
            selector: 'node.critical-node',
            style: {
              'border-width': 3.5,
              'border-color': '#E56B72',
              width: 34,
              height: 34,
            },
          },
          {
            selector: 'node.cluster-node',
            style: {
              'background-color': '#151A21',
              'background-opacity': 0.7,
              'border-color': '#303A47',
              'border-width': 1,
              'text-valign': 'top',
              'font-family': 'JetBrains Mono, monospace',
              'font-size': 10,
              color: '#929EAC',
              padding: '16px',
            },
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 4,
              'border-color': '#67C8D8',
              color: '#EEF2F6',
            },
          },
          {
            selector: 'edge',
            style: {
              width: 1.8,
              'line-color': 'data(color)',
              'line-style': 'data(lineStyle)' as never,
              'target-arrow-color': 'data(color)',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              label: 'data(label)',
              'font-family': 'JetBrains Mono, monospace',
              'font-size': 8.5,
              color: '#929EAC',
              'text-background-color': '#101318',
              'text-background-opacity': 0.85,
              'text-background-padding': '2px',
            },
          },
          {
            selector: 'edge:selected',
            style: {
              width: 3,
              'line-color': '#B08CFF',
              'target-arrow-color': '#B08CFF',
              color: '#EEF2F6',
            },
          },
          {
            selector: '.highlighted-path',
            style: {
              'border-color': '#E56B72',
              'line-color': '#E56B72',
              'target-arrow-color': '#E56B72',
              width: 3,
            },
          },
        ],
      });

      cyRef.current.on('tap', 'node', (evt) => {
        const node = evt.target;
        if (node.data('isCluster')) return;
        setSelectedEdge(null);
        setSelectedNodeId(node.id());
      });

      cyRef.current.on('tap', 'edge', (evt) => {
        const edge = evt.target;
        const raw = edge.data('raw') as Relationship | undefined;
        if (raw) {
          setSelectedNodeId(null);
          setSelectedEdge(raw);
        }
      });
    } else {
      cyRef.current.elements().remove();
      cyRef.current.add(elements);
    }

    const nodeCount = filteredGraph.nodes.length;
    const layoutConfig =
      viewMode === 'process_tree'
        ? { name: 'dagre', rankDir: 'LR', nodeSep: 45, rankSep: 90, animate: false }
        : nodeCount > 120
          ? { name: 'concentric', minNodeSpacing: 28, animate: false }
          : { name: 'cose', idealEdgeLength: 90, nodeOverlap: 20, numIter: 250, animate: false };

    try {
      cyRef.current.layout(layoutConfig as never).run();
    } catch {
      cyRef.current.layout({ name: 'grid' }).run();
    }
  }, [filteredGraph, viewMode, suspiciousPathSet]);

  const handleExportGraphJson = () => {
    if (!filteredGraph) return;
    const blob = new Blob([JSON.stringify(filteredGraph, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `tracevault_graph_${invId?.slice(0, 8) ?? 'case'}.json`;
    a.click();
  };

  const handleExportGraphPng = () => {
    if (!cyRef.current) return;
    const png64 = cyRef.current.png({ bg: '#101318', full: true, scale: 2 });
    const a = document.createElement('a');
    a.href = png64;
    a.download = `tracevault_graph_${invId?.slice(0, 8) ?? 'case'}.png`;
    a.click();
  };

  const toggleSource = (s: ArtifactSource) =>
    setSelectedSources((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));

  const toggleClass = (c: EvidenceClass) =>
    setSelectedClasses((prev) => (prev.includes(c) ? prev.filter((x) => x !== c) : [...prev, c]));

  const toggleRelType = (r: RelationshipType) =>
    setSelectedRelTypes((prev) => (prev.includes(r) ? prev.filter((x) => x !== r) : [...prev, r]));

  const detail = entityDetailQuery.data;
  const buckets = timelineRangeQuery.data?.buckets ?? [];

  return (
    <div className="h-full w-full flex flex-col overflow-hidden">
      {/* Main 3-Pane Graph Workspace */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Evidence Source & Relationship Navigator */}
        <aside className="w-64 bg-panel border-r border-line p-3 overflow-y-auto space-y-4 shrink-0">
          <div>
            <div className="text-2xs font-mono uppercase text-accent">EVIDENCE UNIVERSE</div>
            <h2 className="text-xs font-semibold text-ink-bright">Graph Filters & Provenance</h2>
          </div>

          <div>
            <input
              type="text"
              placeholder="Search entity label, path, PID..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              className="w-full bg-bg border border-line px-2.5 py-1.5 text-xs font-mono text-ink-bright focus:outline-none focus:border-accent"
            />
          </div>

          {/* Graph Mode Switcher */}
          <div>
            <div className="text-2xs font-mono uppercase text-muted mb-1.5">RECONSTRUCTION VIEW</div>
            <div className="grid grid-cols-2 gap-1.5 font-mono text-2xs">
              {(
                [
                  ['relationship', 'Relationship Graph'],
                  ['process_tree', 'Process Tree'],
                  ['clusters', 'Artifact Clusters'],
                  ['dependency', 'Dependency View'],
                ] as [GraphViewMode, string][]
              ).map(([m, label]) => (
                <button
                  key={m}
                  onClick={() => setViewMode(m)}
                  className={`px-2 py-1.5 border text-left ${
                    viewMode === m
                      ? 'border-accent bg-accent/15 text-ink-bright'
                      : 'border-line bg-bg-2 text-muted hover:text-ink'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Toggles for Suspicious Paths & Focus */}
          <div className="space-y-1.5 border-t border-line-soft pt-3 text-xs font-mono">
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={suspiciousOnly}
                onChange={(e) => setSuspiciousOnly(e.target.checked)}
              />
              <span className="text-suspicious text-2xs uppercase">Suspicious Entities Only</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={highlightSuspiciousPaths}
                onChange={(e) => setHighlightSuspiciousPaths(e.target.checked)}
              />
              <span className="text-critical text-2xs uppercase">Highlight Suspicious Paths</span>
            </label>
            {focusedEntityId && (
              <button
                onClick={() => setFocusedEntityId(null)}
                className="w-full mt-1 py-1 px-2 border border-accent text-accent text-2xs uppercase"
              >
                Clear Entity Focus Filter
              </button>
            )}
          </div>

          {/* Evidence Classes */}
          <div className="border-t border-line-soft pt-3">
            <div className="text-2xs font-mono uppercase text-muted mb-1.5">EVIDENCE CLASS</div>
            <div className="space-y-1">
              {EVIDENCE_CLASSES.map((cls) => {
                const meta = EVIDENCE_CLASS_META[cls];
                return (
                  <button
                    key={cls}
                    onClick={() => toggleClass(cls)}
                    className={`w-full flex items-center justify-between px-2 py-1 border text-2xs font-mono ${
                      selectedClasses.includes(cls)
                        ? 'border-line bg-bg-2 text-ink-bright'
                        : 'border-transparent bg-bg text-muted opacity-50'
                    }`}
                  >
                    <span>{meta.label}</span>
                    <span className="w-3 h-0.5" style={{ backgroundColor: meta.color }} />
                  </button>
                );
              })}
            </div>
          </div>

          {/* Artifact Sources */}
          <div className="border-t border-line-soft pt-3">
            <div className="text-2xs font-mono uppercase text-muted mb-1.5">ARTIFACT SOURCES</div>
            <div className="grid grid-cols-2 gap-1">
              {ARTIFACT_SOURCES.map((src) => (
                <button
                  key={src}
                  onClick={() => toggleSource(src)}
                  className={`px-2 py-1 border text-2xs font-mono uppercase text-left ${
                    selectedSources.includes(src)
                      ? 'border-line bg-bg-2 text-ink-bright'
                      : 'border-transparent bg-bg text-muted opacity-40'
                  }`}
                >
                  <span
                    className="inline-block w-2 h-2 mr-1.5"
                    style={{ backgroundColor: SOURCE_COLORS[src] }}
                  />
                  {src}
                </button>
              ))}
            </div>
          </div>

          {/* Relationship Categories */}
          <div className="border-t border-line-soft pt-3">
            <div className="text-2xs font-mono uppercase text-muted mb-1.5">RELATIONSHIP TYPES</div>
            <div className="flex flex-wrap gap-1">
              {RELATIONSHIP_TYPES.map((rt) => (
                <button
                  key={rt}
                  onClick={() => toggleRelType(rt)}
                  className={`px-1.5 py-0.5 text-2xs font-mono border ${
                    selectedRelTypes.includes(rt)
                      ? 'border-line bg-bg-2 text-ink'
                      : 'border-transparent bg-bg text-muted opacity-40'
                  }`}
                >
                  {rt}
                </button>
              ))}
            </div>
          </div>
        </aside>

        {/* Center: Interactive Cytoscape Canvas */}
        <section className="flex-1 flex flex-col bg-bg relative overflow-hidden">
          {/* Top Canvas Toolbar */}
          <div className="h-9 bg-bg-2 border-b border-line px-3 flex items-center justify-between text-2xs font-mono z-10">
            <div className="flex items-center space-x-4">
              <span>
                NODES: <strong className="text-ink-bright">{filteredGraph?.stats.node_count ?? 0}</strong>
              </span>
              <span>
                RELATIONSHIPS: <strong className="text-accent">{filteredGraph?.stats.edge_count ?? 0}</strong>
              </span>
              {timeTravelCursor && (
                <span className="px-2 py-0.5 bg-relation/20 border border-relation text-relation">
                  TIME TRAVEL ≤ {formatIso(timeTravelCursor)}
                </span>
              )}
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => cyRef.current?.fit(undefined, 36)}
                className="px-2 py-0.5 border border-line bg-panel hover:border-accent"
              >
                Fit View
              </button>
              <button
                onClick={handleExportGraphPng}
                className="px-2 py-0.5 border border-line bg-panel hover:border-accent"
              >
                Export PNG
              </button>
              <button
                onClick={handleExportGraphJson}
                className="px-2 py-0.5 border border-line bg-panel hover:border-accent"
              >
                Export JSON
              </button>
            </div>
          </div>

          <div ref={containerRef} className="flex-1 w-full h-full" />

          {(filteredGraph?.stats.node_count ?? 0) === 0 && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="bg-panel border border-line p-5 text-center font-mono text-xs text-muted max-w-md">
                <div className="text-ink-bright font-semibold mb-1">No Evidence Nodes Match Active Filters</div>
                <div>
                  Initiate a Quick or Full Forensic Scan in the Command Center or clear active time-travel / source
                  filters.
                </div>
              </div>
            </div>
          )}
        </section>

        {/* Right: Dedicated Forensic Evidence Inspector Panel */}
        <aside className="w-80 bg-panel border-l border-line p-3.5 overflow-y-auto shrink-0">
          <div className="text-2xs font-mono uppercase text-accent">EVIDENCE INSPECTOR</div>
          <h2 className="text-xs font-semibold text-ink-bright border-b border-line-soft pb-2 mb-3">
            Provenance & Correlation Details
          </h2>

          {selectedEdge ? (
            <div className="space-y-3 font-mono text-xs">
              <div className="bg-bg-2 border border-relation p-2.5">
                <div className="text-2xs text-relation uppercase">SELECTED RELATIONSHIP EDGE</div>
                <div className="text-sm font-bold text-ink-bright mt-0.5">{selectedEdge.type}</div>
                <div className="text-2xs text-muted mt-1">
                  Class: <strong className="text-ink">{selectedEdge.evidence_class.toUpperCase()}</strong> | Confidence:{' '}
                  <strong className="text-verified">{Math.round(selectedEdge.confidence * 100)}%</strong>
                </div>
              </div>

              <div>
                <div className="text-2xs text-muted uppercase">CORRELATION METHOD</div>
                <div className="text-ink-bright bg-bg-2 border border-line-soft p-2 mt-0.5">
                  {selectedEdge.correlation_method}
                </div>
              </div>

              <div>
                <div className="text-2xs text-muted uppercase">DETERMINISTIC EXPLANATION</div>
                <div className="text-ink bg-bg-2 border border-line-soft p-2 mt-0.5 font-sans text-xs">
                  {selectedEdge.explanation}
                </div>
              </div>

              <div>
                <div className="text-2xs text-muted uppercase">OBSERVED TIMESTAMP</div>
                <div className="text-ink-bright mt-0.5">{formatIso(selectedEdge.timestamp)}</div>
              </div>

              <div>
                <div className="text-2xs text-muted uppercase">
                  SUPPORTING NORMALIZED EVENTS ({selectedEdge.supporting_event_ids.length})
                </div>
                <div className="mt-1 space-y-1 max-h-40 overflow-y-auto">
                  {selectedEdge.supporting_event_ids.map((eid) => (
                    <div key={eid} className="bg-bg-2 border border-line-soft px-2 py-1 text-2xs text-accent">
                      Event ID: {eid}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : detail ? (
            <div className="space-y-3 text-xs">
              <div className="bg-bg-2 border border-line p-2.5">
                <div className="flex items-center justify-between font-mono text-2xs">
                  <span
                    className="uppercase font-bold"
                    style={{ color: ENTITY_COLORS[detail.entity.type] }}
                  >
                    {detail.entity.type}
                  </span>
                  {detail.entity.suspicious && (
                    <span className="px-1.5 py-0.5 border border-suspicious text-suspicious">SUSPICIOUS</span>
                  )}
                </div>
                <div className="font-mono font-semibold text-ink-bright mt-1 break-all">{detail.entity.label}</div>
                <div className="text-2xs font-mono text-muted mt-1">
                  Sources: {detail.entity.sources.join(', ').toUpperCase()}
                </div>
                <div className="mt-2 flex space-x-2">
                  <button
                    onClick={() => setFocusedEntityId(detail.entity.id)}
                    className="px-2 py-1 border border-accent text-accent font-mono text-2xs uppercase hover:bg-accent hover:text-bg"
                  >
                    Focus 2-Hop Neighborhood
                  </button>
                </div>
              </div>

              {/* Technical Properties (PID, PPID, User, Path, SHA-256) */}
              <div>
                <div className="text-2xs font-mono uppercase text-muted mb-1">TECHNICAL METADATA</div>
                <div className="bg-bg-2 border border-line-soft p-2 font-mono text-2xs space-y-1">
                  <div>
                    <span className="text-muted">First Seen:</span> {formatIso(detail.entity.first_seen)}
                  </div>
                  <div>
                    <span className="text-muted">Last Seen:</span> {formatIso(detail.entity.last_seen)}
                  </div>
                  {Object.entries(detail.entity.properties ?? {}).map(([k, v]) => (
                    <div key={k} className="break-all">
                      <span className="text-muted">{k}:</span>{' '}
                      <span className="text-ink-bright">{typeof v === 'object' ? JSON.stringify(v) : String(v ?? '—')}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Connected Relationships */}
              <div>
                <div className="text-2xs font-mono uppercase text-muted mb-1">
                  CORRELATED RELATIONSHIPS ({detail.relationships.length})
                </div>
                <div className="space-y-1.5 max-h-44 overflow-y-auto">
                  {detail.relationships.map((r) => (
                    <button
                      key={r.id}
                      onClick={() => setSelectedEdge(r)}
                      className="w-full text-left bg-bg-2 border border-line-soft p-2 hover:border-relation"
                    >
                      <div className="flex items-center justify-between font-mono text-2xs">
                        <span className="text-relation font-semibold">{r.type}</span>
                        <span className="text-verified">{Math.round(r.confidence * 100)}%</span>
                      </div>
                      <div className="text-2xs text-muted mt-0.5">{r.explanation}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Related Findings */}
              {detail.findings.length > 0 && (
                <div>
                  <div className="text-2xs font-mono uppercase text-suspicious mb-1">
                    ASSOCIATED DETECTIONS ({detail.findings.length})
                  </div>
                  <div className="space-y-1.5">
                    {detail.findings.map((f) => (
                      <div key={f.id} className="bg-bg-2 border border-suspicious/50 p-2">
                        <div
                          className="font-mono text-2xs font-bold uppercase"
                          style={{ color: SEVERITY_COLORS[f.severity] }}
                        >
                          {f.rule_id} — {f.name}
                        </div>
                        <div className="text-2xs text-muted mt-0.5">{f.description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Related Timeline Events */}
              <div>
                <div className="text-2xs font-mono uppercase text-muted mb-1">
                  SUPPORTING TIMELINE EVENTS ({detail.events.length})
                </div>
                <div className="space-y-1 max-h-48 overflow-y-auto font-mono text-2xs">
                  {detail.events.map((ev) => (
                    <div key={ev.id} className="bg-bg-2 border border-line-soft p-1.5">
                      <div className="text-muted">{formatIso(ev.timestamp)}</div>
                      <div className="text-ink-bright truncate" title={ev.summary}>
                        {ev.summary}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-bg-2 border border-line-soft p-4 font-mono text-2xs text-muted space-y-2">
              <div className="text-ink-bright">Select any Node or Relationship Edge</div>
              <div>
                Clicking a process, executable, user, registry key, browser URL, or file node loads its complete
                forensic provenance, hashes, and correlated timeline events.
              </div>
              <div>
                Clicking a relationship edge displays its deterministic correlation rule, confidence score, and
                supporting event IDs.
              </div>
            </div>
          )}
        </aside>
      </div>

      {/* Bottom: Synchronized Time Travel Scrubber Bar */}
      <footer className="h-12 bg-panel border-t border-line px-4 flex items-center justify-between font-mono text-xs shrink-0">
        <div className="flex items-center space-x-3">
          <span className="text-2xs uppercase text-accent">TIME TRAVEL RECONSTRUCTION:</span>
          <span className="text-2xs text-muted">
            {timeTravelCursor ? `Showing evidence ≤ ${formatIso(timeTravelCursor)}` : 'Full Investigation Window'}
          </span>
        </div>

        {buckets.length > 0 && (
          <div className="flex items-center space-x-3 flex-1 max-w-xl mx-4">
            <input
              type="range"
              min={0}
              max={buckets.length - 1}
              value={
                timeTravelCursor
                  ? Math.max(
                      0,
                      buckets.findIndex((b) => b.t >= timeTravelCursor),
                    )
                  : buckets.length - 1
              }
              onChange={(e) => {
                const idx = Number(e.target.value);
                if (idx >= buckets.length - 1) setTimeTravelCursor(null);
                else setTimeTravelCursor(buckets[idx].t);
              }}
              className="flex-1 accent-accent cursor-pointer"
            />
            {timeTravelCursor && (
              <button
                onClick={() => setTimeTravelCursor(null)}
                className="px-2 py-0.5 border border-line bg-bg-2 text-2xs text-ink hover:border-accent"
              >
                Reset to Present
              </button>
            )}
          </div>
        )}

        <div className="text-2xs text-muted">
          Legend: <span className="text-accent">─── Direct</span>{' '}
          <span className="text-verified ml-2">- - - Strong</span>{' '}
          <span className="text-suspicious ml-2">● Suspicious</span>
        </div>
      </footer>
    </div>
  );
};
