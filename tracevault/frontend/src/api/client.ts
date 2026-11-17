import { auth } from './auth';
import type * as T from './types';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

type Query = Record<string, string | number | boolean | null | undefined | string[]>;

export function buildQuery(params?: Query): string {
  if (!params) return '';
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      if (v.length) usp.set(k, v.join(','));
    } else usp.set(k, String(v));
  }
  const s = usp.toString();
  return s ? `?${s}` : '';
}

async function request<R>(method: string, path: string, body?: unknown, query?: Query): Promise<R> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (auth.token) headers.Authorization = `Bearer ${auth.token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`/api${path}${buildQuery(query)}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && path !== '/auth/login') {
    auth.set(null);
    throw new ApiError(401, 'Session expired — sign in again');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const j = (await res.json()) as { detail?: unknown };
      if (typeof j.detail === 'string') detail = j.detail;
      else if (j.detail) detail = JSON.stringify(j.detail);
    } catch {
      /* not json */
    }
    throw new ApiError(res.status, detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as R;
  return (await res.json()) as R;
}

const get = <R>(p: string, q?: Query) => request<R>('GET', p, undefined, q);
const post = <R>(p: string, b?: unknown) => request<R>('POST', p, b ?? {});
const patch = <R>(p: string, b: unknown) => request<R>('PATCH', p, b);

export interface GraphQuery {
  at?: string | null;
  sources?: string[];
  relationship_types?: string[];
  evidence_classes?: string[];
  focus?: string | null;
  depth?: number;
  suspicious_only?: boolean;
}

export interface TimelineQuery {
  start?: string | null;
  end?: string | null;
  groups?: string[];
  sources?: string[];
  suspicious_only?: boolean;
  limit?: number;
}

export type ArtifactKind = T.ArtifactSource;

export const api = {
  login: (username: string, password: string) =>
    request<T.LoginResponse>('POST', '/auth/login', { username, password }),
  me: () => get<T.User>('/auth/me'),

  endpoints: () => get<T.Endpoint[]>('/endpoints'),
  endpoint: (id: string) => get<T.Endpoint>(`/endpoints/${id}`),
  endpointStatus: (id: string) => get<T.EndpointStatus>(`/endpoints/${id}/status`),

  investigations: (page = 1, page_size = 100) =>
    get<T.Paged<T.Investigation>>('/investigations', { page, page_size }),
  investigation: (id: string) => get<T.Investigation>(`/investigations/${id}`),
  createInvestigation: (b: { title: string; description?: string; endpoint_id: string }) =>
    post<T.Investigation>('/investigations', b),
  summary: (id: string) => get<T.InvestigationSummary>(`/investigations/${id}/summary`),

  startScan: (
    endpointId: string,
    b: { investigation_id: string; scan_type: T.ScanType; time_window_hours?: number | null; sources?: string[] },
  ) => post<T.ScanJob>(`/endpoints/${endpointId}/scans`, b),
  scan: (id: string) => get<T.ScanJob>(`/scans/${id}`),
  scanProgress: (id: string) => get<T.ScanProgress>(`/scans/${id}/progress`),
  cancelScan: (id: string) => post<T.ScanJob>(`/scans/${id}/cancel`),
  scanArtifacts: (id: string) => get<T.CollectedArtifact[]>(`/scans/${id}/artifacts`),

  evidence: (inv: string, q: { type?: string; q?: string; page?: number; page_size?: number }) =>
    get<T.Paged<T.EvidenceEntity>>(`/investigations/${inv}/evidence`, q),
  evidenceDetail: (inv: string, id: string) => get<T.EvidenceDetail>(`/investigations/${inv}/evidence/${id}`),
  graph: (inv: string, q: GraphQuery) => get<T.EvidenceGraph>(`/investigations/${inv}/evidence-graph`, { ...q }),
  relationships: (inv: string, page = 1, page_size = 200) =>
    get<T.Paged<T.Relationship>>(`/investigations/${inv}/relationships`, { page, page_size }),

  timeline: (inv: string, q: TimelineQuery) => get<T.Timeline>(`/investigations/${inv}/timeline`, { ...q }),
  timelineRange: (inv: string, buckets = 200) =>
    get<T.TimelineRange>(`/investigations/${inv}/timeline/range`, { buckets }),

  artifacts: <R>(inv: string, kind: ArtifactKind, q: Query) =>
    get<T.Paged<T.ArtifactRow<R>>>(`/investigations/${inv}/artifacts/${kind}`, q),

  findings: (inv: string) => get<T.Finding[]>(`/investigations/${inv}/findings`),
  risk: (inv: string) => get<T.RiskAssessment>(`/investigations/${inv}/risk`),

  incidents: (inv: string) => get<T.IncidentCase[]>(`/investigations/${inv}/incidents`),
  createIncident: (inv: string, b: Partial<T.IncidentCase> & { title: string }) =>
    post<T.IncidentCase>(`/investigations/${inv}/incidents`, b),
  incident: (id: string) => get<T.IncidentCase>(`/incidents/${id}`),
  updateIncident: (id: string, b: Partial<T.IncidentCase>) => patch<T.IncidentCase>(`/incidents/${id}`, b),

  notes: (inv: string) => get<T.Note[]>(`/investigations/${inv}/notes`),
  addNote: (inv: string, b: { body: string; incident_id?: string | null }) =>
    post<T.Note>(`/investigations/${inv}/notes`, b),

  reports: (inv: string) => get<T.Report[]>(`/investigations/${inv}/reports`),
  createReport: (inv: string, b: { format: 'pdf' | 'json'; incident_id?: string }) =>
    post<T.Report>(`/investigations/${inv}/reports`, b),

  custody: (inv: string) => get<T.CustodyEntry[]>(`/investigations/${inv}/custody`),
  seedDemo: () => post<T.Investigation>('/demo/seed'),
};

/** Download an authenticated binary (reports) and trigger a browser save. */
export async function downloadAuthenticated(url: string, filename: string) {
  const path = url.startsWith('/api') ? url : `/api/reports/${url}/download`;
  const res = await fetch(path, { headers: auth.token ? { Authorization: `Bearer ${auth.token}` } : {} });
  if (!res.ok) throw new ApiError(res.status, `Download failed (${res.status})`);
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

export function wsUrl(path: string): string {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}${path}?token=${encodeURIComponent(auth.token ?? '')}`;
}
