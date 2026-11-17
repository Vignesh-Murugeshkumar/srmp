// Typed models mirroring docs/CONTRACT.md (v1). Do not invent fields.

export type ISO = string;
export type UUID = string;

export type Role = 'admin' | 'investigator' | 'viewer';
export interface User {
  id: UUID;
  username: string;
  role: Role;
  created_at: ISO;
}
export interface LoginResponse {
  access_token: string;
  token_type: 'bearer';
  user: User;
}

export const ARTIFACT_SOURCES = ['evtx', 'registry', 'prefetch', 'amcache', 'browser', 'filesystem'] as const;
export type ArtifactSource = (typeof ARTIFACT_SOURCES)[number];

export interface StorageInfo {
  drive: string;
  filesystem: string;
  total_bytes: number;
  free_bytes: number;
}

export type AgentStatus = 'online' | 'stale' | 'offline';

export interface Endpoint {
  id: UUID;
  hostname: string;
  machine_id: string;
  os_name: string;
  os_version: string;
  os_build: string;
  architecture: string;
  agent_version: string;
  collection_user: string;
  is_elevated: boolean;
  storage: StorageInfo[];
  registered_at: ISO;
  last_seen: ISO | null;
  agent_status: AgentStatus;
}

export type Availability =
  | 'available'
  | 'collected'
  | 'partially_accessible'
  | 'permission_denied'
  | 'not_found'
  | 'unsupported';

export interface DiscoveryItem {
  source: ArtifactSource;
  artifact_key: string;
  name: string;
  location: string;
  availability: Availability;
  last_modified: ISO | null;
  size_bytes: number | null;
  access_note: string | null;
}

export interface EndpointStatus {
  endpoint_id: UUID;
  agent_status: AgentStatus;
  last_seen: ISO | null;
  last_scan: ScanJob | null;
  discovery: DiscoveryItem[];
}

export type ScanType = 'quick' | 'full';
export type ScanStatus = 'queued' | 'collecting' | 'processing' | 'completed' | 'partial' | 'failed' | 'cancelled';

export interface ScanJob {
  id: UUID;
  investigation_id: UUID;
  endpoint_id: UUID;
  scan_type: ScanType;
  status: ScanStatus;
  time_window_hours: number | null;
  sources: ArtifactSource[];
  created_at: ISO;
  started_at: ISO | null;
  finished_at: ISO | null;
  cancel_requested: boolean;
  limitations: string[];
  side_effects: string[];
}

export type StageStatus = 'pending' | 'running' | 'completed' | 'partial' | 'failed' | 'skipped' | 'cancelled';
export type StageName = ArtifactSource | 'processing';

export interface StageProgress {
  stage: StageName;
  status: StageStatus;
  records: number;
  progress: number;
  duration_ms: number | null;
  errors: string[];
  message: string | null;
}

export interface ScanProgress {
  scan: ScanJob;
  stages: StageProgress[];
}

export type ArtifactStatus = 'collected' | 'partial' | 'permission_denied' | 'not_found' | 'unsupported' | 'error';

export interface CollectedArtifact {
  id: UUID;
  artifact_key: string;
  source: ArtifactSource;
  name: string;
  original_path: string;
  status: ArtifactStatus;
  acquisition_method: string;
  sha256: string | null;
  records_sha256: string | null;
  size_bytes: number | null;
  last_modified: ISO | null;
  collected_at: ISO;
  collector_version: string;
  record_count: number;
  parser: string;
  side_effects: string[];
  error: string | null;
  time_window: { start: ISO | null; end: ISO | null } | null;
  verified: boolean;
  verification_status: string;
  storage_ref: string | null;
}

export type InvestigationStatus = 'open' | 'in_review' | 'closed';
export interface Investigation {
  id: UUID;
  title: string;
  description: string | null;
  endpoint_id: UUID;
  endpoint_hostname: string;
  status: InvestigationStatus;
  is_demo: boolean;
  created_by: string;
  created_at: ISO;
  updated_at: ISO;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface InvestigationSummary {
  evidence_collected: number;
  records_total: number;
  events_total: number;
  suspicious_findings: number;
  correlated_events: number;
  high_confidence_relationships: number;
  integrity: { verified: number; mismatched: number; unverified: number };
  sources: { source: ArtifactSource; status: string; records: number }[];
  latest_scan: ScanJob | null;
}

export const ENTITY_TYPES = [
  'user',
  'process',
  'executable',
  'file',
  'registry_key',
  'url',
  'event',
  'network',
  'service',
  'scheduled_task',
] as const;
export type EntityType = (typeof ENTITY_TYPES)[number];

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface EvidenceEntity {
  id: UUID;
  type: EntityType;
  key: string;
  label: string;
  properties: Record<string, unknown>;
  sources: ArtifactSource[];
  first_seen: ISO | null;
  last_seen: ISO | null;
  suspicious: boolean;
  risk_score: number | null;
}

export const RELATIONSHIP_TYPES = [
  'EXECUTED',
  'CREATED',
  'MODIFIED',
  'ACCESSED',
  'AUTHENTICATED',
  'DOWNLOADED',
  'CONNECTED_TO',
  'PERSISTENCE_MODIFIED',
  'SPAWNED',
  'ASSOCIATED_WITH',
] as const;
export type RelationshipType = (typeof RELATIONSHIP_TYPES)[number];

export const EVIDENCE_CLASSES = ['direct', 'strong', 'weak', 'hypothesis'] as const;
export type EvidenceClass = (typeof EVIDENCE_CLASSES)[number];

export interface Relationship {
  id: UUID;
  source: UUID;
  target: UUID;
  type: RelationshipType;
  evidence_class: EvidenceClass;
  correlation_method: string;
  confidence: number;
  explanation: string;
  timestamp: ISO | null;
  supporting_event_ids: UUID[];
  supporting_artifact_ids: UUID[];
}

export type GraphNode = Omit<EvidenceEntity, 'properties'> & { properties: Record<string, unknown> };

export interface EvidenceGraph {
  nodes: GraphNode[];
  edges: Relationship[];
  stats: { node_count: number; edge_count: number; truncated: boolean };
}

export type TimelineGroup = 'user' | 'process' | 'registry' | 'browser' | 'file' | 'security';
export const TIMELINE_GROUPS: TimelineGroup[] = ['security', 'user', 'process', 'registry', 'browser', 'file'];

export interface TimelineEvent {
  id: UUID;
  timestamp: ISO | null;
  timestamp_precision: string | null;
  group: TimelineGroup;
  event_type: string;
  artifact_source: ArtifactSource;
  summary: string;
  suspicious: boolean;
  severity: Severity;
  entity_ids: UUID[];
  source_record_id: string | null;
  source_artifact_id: UUID | null;
}

export interface Timeline {
  events: TimelineEvent[];
  bounds: { start: ISO | null; end: ISO | null };
  collection_time: ISO | null;
  total: number;
  truncated: boolean;
}

export interface TimelineRange {
  start: ISO | null;
  end: ISO | null;
  buckets: { t: ISO; count: number; suspicious: number }[];
}

export interface EvidenceDetail {
  entity: EvidenceEntity;
  relationships: Relationship[];
  events: TimelineEvent[];
  findings: Finding[];
}

export interface Finding {
  id: UUID;
  rule_id: string;
  name: string;
  severity: Severity;
  description: string;
  affected_entity_id: UUID | null;
  affected_entity_label: string | null;
  detection_logic: string;
  supporting_event_ids: UUID[];
  timestamp: ISO | null;
  confidence: number;
  mitre: { technique_id: string; technique_name: string; tactic: string } | null;
  recommendations: string[];
  disclaimer: string;
}

export interface RiskAssessment {
  score: number;
  level: string;
  factors: { finding_id: UUID; name: string; contribution: number; explanation: string }[];
  explanation: string;
}

export interface ArtifactRow<T = Record<string, unknown>> {
  id: UUID;
  artifact_id: UUID;
  artifact_key: string;
  record_id: string;
  original_path: string | null;
  sha256: string | null;
  data: T;
  related_event_ids: UUID[];
}

// §4 record shapes (fields are nullable per contract)
export interface EvtxRecord {
  channel: string;
  provider: string;
  event_id: number;
  record_number: number;
  level: number | null;
  time_created: ISO | null;
  computer: string | null;
  user_sid: string | null;
  process_id: number | null;
  thread_id: number | null;
  event_data: Record<string, unknown> | null;
  xml: string | null;
}
export interface RegistryRecord {
  category: string;
  hive: string;
  key_path: string;
  value_name: string | null;
  value_type: string | null;
  value_data: unknown;
  last_write: ISO | null;
  user_sid: string | null;
  decoded: Record<string, unknown> | null;
}
export interface PrefetchRecord {
  executable: string;
  prefetch_hash: string | null;
  pf_path: string | null;
  pf_created: ISO | null;
  pf_modified: ISO | null;
  run_count: number | null;
  last_run_times: ISO[] | null;
  referenced_files: string[] | null;
  referenced_dirs: string[] | null;
  volume_serials: string[] | null;
  parser: string | null;
}
export interface AmcacheRecord {
  record_type: string;
  program_path: string | null;
  name: string | null;
  sha1: string | null;
  publisher: string | null;
  version: string | null;
  size: number | null;
  link_date: ISO | null;
  key_last_write: ISO | null;
  program_id: string | null;
}
export interface BrowserRecord {
  browser: 'chrome' | 'edge' | 'firefox';
  profile: string;
  kind: 'visit' | 'download';
  url: string;
  title: string | null;
  visit_time: ISO | null;
  visit_count: number | null;
  transition: string | null;
  target_path: string | null;
  start_time: ISO | null;
  end_time: ISO | null;
  received_bytes: number | null;
  total_bytes: number | null;
  mime_type: string | null;
  referrer: string | null;
  danger_type: string | null;
  state: string | null;
}
export interface FilesystemRecord {
  kind: 'recycle_bin' | 'file_metadata' | 'mft' | 'usn';
  path: string;
  size: number | null;
  created: ISO | null;
  modified: ISO | null;
  accessed: ISO | null;
  mft_changed: ISO | null;
  deleted_time: ISO | null;
  original_path: string | null;
  usn_reason: string | null;
  usn: number | null;
  mft_entry: number | null;
  mft_sequence: number | null;
  sha256: string | null;
  attributes: string | null;
}

export type IncidentStatus = 'hypothesis' | 'investigating' | 'supported' | 'refuted' | 'closed';
export const INCIDENT_STATUSES: IncidentStatus[] = ['hypothesis', 'investigating', 'supported', 'refuted', 'closed'];

export interface IncidentCase {
  id: UUID;
  investigation_id: UUID;
  title: string;
  status: IncidentStatus;
  hypothesis: string | null;
  affected_user: string | null;
  affected_process: string | null;
  attached_entity_ids: UUID[];
  attached_event_ids: UUID[];
  attached_finding_ids: UUID[];
  conclusion: string | null;
  created_at: ISO;
  updated_at: ISO;
}

export interface Note {
  id: UUID;
  body: string;
  incident_id: UUID | null;
  author: string;
  created_at: ISO;
}

export interface Report {
  id: UUID;
  format: 'pdf' | 'json';
  status: string;
  sha256: string | null;
  created_at: ISO;
  download_url: string;
}

export interface CustodyEntry {
  id: UUID;
  artifact_id: UUID | null;
  action: string;
  actor: string;
  timestamp: ISO;
  sha256: string | null;
  verification_status: string | null;
  details: unknown;
}
