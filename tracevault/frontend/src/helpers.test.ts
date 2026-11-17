import { describe, expect, it } from 'vitest';
import { buildQuery } from './api/client';
import type { EvidenceGraph } from './api/types';
import { buildCytoscapeElements, findSuspiciousPathSet } from './graph/graphHelpers';
import { formatBytes, formatIso } from './theme/tokens';

describe('TraceVault Frontend Helpers', () => {
  it('formats ISO timestamps and byte sizes deterministically', () => {
    expect(formatIso('2026-11-16T14:02:05+00:00')).toBe('2026-11-16 14:02:05 UTC');
    expect(formatIso(null)).toBe('—');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
  });

  it('builds URL query strings correctly for arrays and scalars', () => {
    expect(buildQuery({ sources: ['evtx', 'registry'], suspicious_only: true, empty: '' })).toBe(
      '?sources=evtx%2Cregistry&suspicious_only=true',
    );
  });

  it('maps EvidenceGraph into Cytoscape elements and computes shortest paths between suspicious nodes', () => {
    const sampleGraph: EvidenceGraph = {
      nodes: [
        {
          id: 'n1',
          type: 'url',
          key: 'https://phish.example.org/drop.exe',
          label: 'drop.exe URL',
          properties: {},
          sources: ['browser'],
          first_seen: '2026-11-16T14:00:00+00:00',
          last_seen: '2026-11-16T14:00:00+00:00',
          suspicious: true,
          risk_score: 50,
        },
        {
          id: 'n2',
          type: 'file',
          key: 'c:\\downloads\\drop.exe',
          label: 'drop.exe',
          properties: {},
          sources: ['browser', 'filesystem'],
          first_seen: '2026-11-16T14:00:02+00:00',
          last_seen: '2026-11-16T14:00:02+00:00',
          suspicious: false,
          risk_score: 10,
        },
        {
          id: 'n3',
          type: 'process',
          key: 'drop.exe:4880',
          label: 'drop.exe (PID 4880)',
          properties: {},
          sources: ['evtx'],
          first_seen: '2026-11-16T14:01:00+00:00',
          last_seen: '2026-11-16T14:01:00+00:00',
          suspicious: true,
          risk_score: 80,
        },
      ],
      edges: [
        {
          id: 'e1',
          source: 'n1',
          target: 'n2',
          type: 'DOWNLOADED',
          evidence_class: 'direct',
          correlation_method: 'Browser download target_path',
          confidence: 0.99,
          explanation: 'Downloaded file',
          timestamp: '2026-11-16T14:00:02+00:00',
          supporting_event_ids: ['ev1'],
          supporting_artifact_ids: ['a1'],
        },
        {
          id: 'e2',
          source: 'n2',
          target: 'n3',
          type: 'EXECUTED',
          evidence_class: 'strong',
          correlation_method: 'Target path == NewProcessName',
          confidence: 0.94,
          explanation: 'Executed downloaded binary',
          timestamp: '2026-11-16T14:01:00+00:00',
          supporting_event_ids: ['ev1', 'ev2'],
          supporting_artifact_ids: ['a1', 'a2'],
        },
      ],
      stats: { node_count: 3, edge_count: 2, truncated: false },
    };

    const pathSet = findSuspiciousPathSet(sampleGraph);
    expect(pathSet.has('n1')).toBe(true);
    expect(pathSet.has('n2')).toBe(true);
    expect(pathSet.has('n3')).toBe(true);
    expect(pathSet.has('e1')).toBe(true);
    expect(pathSet.has('e2')).toBe(true);

    const elements = buildCytoscapeElements(sampleGraph, 'relationship', pathSet);
    expect(elements.filter((x) => x.group === 'nodes')).toHaveLength(3);
    expect(elements.filter((x) => x.group === 'edges')).toHaveLength(2);
  });
});
