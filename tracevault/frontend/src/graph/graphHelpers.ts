import type { EvidenceGraph, GraphNode, Relationship } from '../api/types';
import { ENTITY_COLORS, ENTITY_SHAPES, EVIDENCE_CLASS_META, SOURCE_COLORS } from '../theme/tokens';

export type GraphViewMode = 'relationship' | 'process_tree' | 'clusters' | 'dependency';

export interface CyElement {
  group: 'nodes' | 'edges';
  data: Record<string, unknown>;
  classes?: string;
}

export function buildCytoscapeElements(
  graph: EvidenceGraph,
  mode: GraphViewMode,
  highlightedPathIds: Set<string>,
): CyElement[] {
  const elements: CyElement[] = [];

  let nodes: GraphNode[] = graph.nodes;
  let edges: Relationship[] = graph.edges;

  if (mode === 'process_tree') {
    const procTypes = new Set(['user', 'process', 'executable', 'scheduled_task', 'service']);
    const treeRels = new Set(['SPAWNED', 'EXECUTED', 'CREATED', 'PERSISTENCE_MODIFIED']);
    edges = graph.edges.filter((e) => treeRels.has(e.type));
    const touched = new Set<string>();
    edges.forEach((e) => {
      touched.add(e.source);
      touched.add(e.target);
    });
    nodes = graph.nodes.filter((n) => procTypes.has(n.type) || touched.has(n.id));
  }

  const nodeIds = new Set(nodes.map((n) => n.id));

  if (mode === 'clusters') {
    const sourcesUsed = new Set<string>();
    nodes.forEach((n) => {
      const primarySrc = n.sources?.[0] || 'evtx';
      sourcesUsed.add(primarySrc);
    });
    sourcesUsed.forEach((src) => {
      elements.push({
        group: 'nodes',
        data: {
          id: `cluster:${src}`,
          label: `SOURCE: ${src.toUpperCase()}`,
          isCluster: true,
          color: SOURCE_COLORS[src as keyof typeof SOURCE_COLORS] || '#303A47',
        },
        classes: 'cluster-node',
      });
    });
  }

  for (const n of nodes) {
    const primarySrc = n.sources?.[0] || 'evtx';
    const isSusp = Boolean(n.suspicious);
    const isCrit = (n.risk_score ?? 0) >= 60;
    const classes: string[] = [];
    if (isCrit) classes.push('critical-node');
    else if (isSusp) classes.push('suspicious-node');
    if (highlightedPathIds.has(n.id)) classes.push('highlighted-path');

    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        label: n.label,
        entityType: n.type,
        shape: ENTITY_SHAPES[n.type] || 'ellipse',
        color: ENTITY_COLORS[n.type] || '#67C8D8',
        borderColor: isCrit ? '#E56B72' : isSusp ? '#E6AA55' : '#303A47',
        parent: mode === 'clusters' ? `cluster:${primarySrc}` : undefined,
        suspicious: isSusp,
        riskScore: n.risk_score ?? 0,
        raw: n,
      },
      classes: classes.join(' '),
    });
  }

  for (const e of edges) {
    if (!nodeIds.has(e.source) || !nodeIds.has(e.target)) continue;
    const meta = EVIDENCE_CLASS_META[e.evidence_class] || EVIDENCE_CLASS_META.direct;
    const classes: string[] = [`edge-${e.evidence_class}`];
    if (highlightedPathIds.has(e.id)) classes.push('highlighted-path');

    elements.push({
      group: 'edges',
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.type,
        relType: e.type,
        evidenceClass: e.evidence_class,
        lineStyle: meta.lineStyle,
        color: meta.color,
        confidence: e.confidence,
        raw: e,
      },
      classes: classes.join(' '),
    });
  }

  return elements;
}

/** Find nodes & edges lying on shortest paths between suspicious nodes. */
export function findSuspiciousPathSet(graph: EvidenceGraph): Set<string> {
  const result = new Set<string>();
  const suspNodes = graph.nodes.filter((n) => n.suspicious).map((n) => n.id);
  if (suspNodes.length === 0) return result;
  suspNodes.forEach((id) => result.add(id));

  const adj = new Map<string, { neighbor: string; edgeId: string }[]>();
  for (const e of graph.edges) {
    if (!adj.has(e.source)) adj.set(e.source, []);
    if (!adj.has(e.target)) adj.set(e.target, []);
    adj.get(e.source)!.push({ neighbor: e.target, edgeId: e.id });
    adj.get(e.target)!.push({ neighbor: e.source, edgeId: e.id });
  }

  const suspSet = new Set(suspNodes);
  for (const startId of suspNodes) {
    const visited = new Set<string>([startId]);
    const parent = new Map<string, { prev: string; edgeId: string }>();
    const queue: string[] = [startId];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      if (curr !== startId && suspSet.has(curr)) {
        let trace = curr;
        while (parent.has(trace)) {
          const step = parent.get(trace)!;
          result.add(trace);
          result.add(step.edgeId);
          result.add(step.prev);
          trace = step.prev;
        }
      }
      for (const nxt of adj.get(curr) ?? []) {
        if (!visited.has(nxt.neighbor)) {
          visited.add(nxt.neighbor);
          parent.set(nxt.neighbor, { prev: curr, edgeId: nxt.edgeId });
          queue.push(nxt.neighbor);
        }
      }
    }
  }

  return result;
}
