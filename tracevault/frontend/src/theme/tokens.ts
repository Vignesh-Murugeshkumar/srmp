import type { ArtifactSource, EntityType, EvidenceClass, Severity } from '../api/types';

export const SOURCE_COLORS: Record<ArtifactSource, string> = {
  evtx: '#6FA8DC',
  registry: '#C89B6D',
  prefetch: '#7FC6A4',
  amcache: '#A3B86C',
  browser: '#D58FB8',
  filesystem: '#9AA7B8',
};

export const SOURCE_LABELS: Record<ArtifactSource, string> = {
  evtx: 'EVTX Event Logs',
  registry: 'Registry Hives',
  prefetch: 'Windows Prefetch',
  amcache: 'Amcache Inventory',
  browser: 'Browser SQLite',
  filesystem: 'NTFS / Filesystem',
};

export const ENTITY_SHAPES: Record<EntityType, string> = {
  user: 'octagon',
  process: 'round-rectangle',
  executable: 'hexagon',
  file: 'rectangle',
  registry_key: 'diamond',
  url: 'tag',
  event: 'ellipse',
  network: 'pentagon',
  service: 'vee',
  scheduled_task: 'triangle',
};

export const ENTITY_COLORS: Record<EntityType, string> = {
  user: '#67C8D8',
  process: '#8C9CFF',
  executable: '#7FC6A4',
  file: '#9AA7B8',
  registry_key: '#C89B6D',
  url: '#D58FB8',
  event: '#6FA8DC',
  network: '#E6AA55',
  service: '#A3B86C',
  scheduled_task: '#B08CFF',
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#E56B72',
  high: '#E6AA55',
  medium: '#8C9CFF',
  low: '#67C8D8',
  info: '#929EAC',
};

export const EVIDENCE_CLASS_META: Record<
  EvidenceClass,
  { label: string; lineStyle: 'solid' | 'dashed' | 'dotted'; color: string }
> = {
  direct: { label: 'Directly Observed', lineStyle: 'solid', color: '#67C8D8' },
  strong: { label: 'Strongly Correlated', lineStyle: 'dashed', color: '#70B99B' },
  weak: { label: 'Weak Contextual', lineStyle: 'dotted', color: '#929EAC' },
  hypothesis: { label: 'Analyst Hypothesis', lineStyle: 'dashed', color: '#B08CFF' },
};

export function formatIso(iso: string | null | undefined): string {
  if (!iso) return '—';
  return iso.replace('T', ' ').replace(/\+00:00$/, ' UTC');
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}
