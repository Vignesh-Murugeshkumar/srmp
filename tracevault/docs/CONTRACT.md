# TraceVault — Shared Interface Contract (v1)

This document is the single source of truth binding the three components:

| Component | Path | Runtime |
|---|---|---|
| Windows Endpoint Collector | `tracevault/collector/` | Python 3.12 on Windows (pywin32) |
| Backend API + processing | `tracevault/backend/` | Python 3.12, FastAPI, SQLAlchemy 2, PostgreSQL (SQLite allowed for tests/dev), Celery+Redis (inline mode allowed for dev) |
| Investigation UI | `tracevault/frontend/` | React 18 + TS + Vite + Tailwind + Cytoscape + D3 + Recharts + TanStack Query + React Router + Framer Motion |

Ports: backend `8000`, frontend dev `5173` (Vite proxies `/api` and `/ws` to `8000`), postgres `5432`, redis `6379`.

**Golden rules:** never fabricate evidence; every relationship carries an explanation and supporting event ids; every finding links to supporting events; unavailable artifacts are reported with an explicit status, never substituted. Demo data exists only in investigations flagged `is_demo=true` and must be visibly labelled in the UI.

---

## 1. Authentication

### 1.1 Analyst (human) auth
- `POST /api/auth/login` body `{ "username": str, "password": str }` → `{ "access_token": str, "token_type": "bearer", "user": User }`
- `GET /api/auth/me` → `User`
- `User = { id: str(uuid), username: str, role: "admin"|"investigator"|"viewer", created_at: iso }`
- JWT (HS256, secret from env `TRACEVAULT_SECRET_KEY`), header `Authorization: Bearer <token>`.
- Bootstrap admin created at startup from env `TRACEVAULT_ADMIN_USERNAME` / `TRACEVAULT_ADMIN_PASSWORD` (defaults for dev: `admin` / `tracevault-admin` — logged as a warning).
- Investigation isolation: admins see everything; investigators see investigations they created or are assigned to; viewers read-only on assigned.

### 1.2 Agent auth
- Enrollment: agent presents header `X-Enrollment-Key: <key>` (env `TRACEVAULT_ENROLLMENT_KEY`, dev default `dev-enrollment-key`) to `POST /api/endpoints/register`.
- Response returns a per-agent secret token **once**; backend stores only its SHA-256 hash.
- Subsequent agent calls: `Authorization: Agent <agent_id>:<agent_token>`.
- mTLS is a deployment option (documented, reverse-proxy terminated); token auth is always enforced.

---

## 2. Endpoint registration

`POST /api/endpoints/register` (enrollment key)
```json
{
  "machine_id": "string (MachineGuid from HKLM\\SOFTWARE\\Microsoft\\Cryptography)",
  "hostname": "string",
  "os_name": "Windows 11 Pro",
  "os_version": "10.0",
  "os_build": "22631",
  "architecture": "AMD64",
  "collection_user": "DOMAIN\\user",
  "is_elevated": false,
  "agent_version": "0.1.0",
  "storage": [{"drive": "C:\\", "filesystem": "NTFS", "total_bytes": 0, "free_bytes": 0}],
  "collected_at": "2026-11-17T02:44:50.123456+00:00"
}
```
→ `{ "endpoint_id": uuid, "agent_id": uuid, "agent_token": str }`
Re-registering the same `machine_id` reuses the endpoint and rotates the agent token.

Analyst endpoints:
- `GET /api/endpoints` → `Endpoint[]`
- `GET /api/endpoints/{id}` → `Endpoint`
- `GET /api/endpoints/{id}/status` → `{ endpoint_id, agent_status: "online"|"stale"|"offline", last_seen, last_scan: ScanJob|null, discovery: DiscoveryItem[] }`
- `Endpoint = { id, hostname, machine_id, os_name, os_version, os_build, architecture, agent_version, collection_user, is_elevated, storage, registered_at, last_seen, agent_status }`
- `agent_status`: online if last heartbeat < 2 min, stale < 30 min, else offline.

---

## 3. Agent ↔ backend protocol (pull model — agent never accepts inbound connections)

| Call | Purpose |
|---|---|
| `POST /api/agent/heartbeat` body `{ discovery?: DiscoveryItem[] }` → `{ ok: true }` | liveness + latest artifact discovery |
| `GET /api/agent/jobs/next` → `200 Job` or `204` | claim the next queued scan for this endpoint (status → `collecting`) |
| `POST /api/agent/scans/{scan_id}/progress` body `StageProgress` → `{ cancel_requested: bool }` | stage progress; agent must stop gracefully when `cancel_requested` |
| `POST /api/agent/scans/{scan_id}/artifacts` multipart (see 3.3) → `{ artifact_id, verified: bool, record_count }` | upload one artifact |
| `POST /api/agent/scans/{scan_id}/complete` body `{ status: "completed"|"partial"|"failed"|"cancelled", limitations: str[], side_effects: str[] }` → `{ ok: true }` | finishes collection, backend enqueues processing |

### 3.1 Job
```json
{ "scan_id": "uuid", "investigation_id": "uuid", "scan_type": "quick"|"full",
  "time_window_hours": 72, "sources": ["evtx","registry","prefetch","amcache","browser","filesystem"],
  "options": { "max_records_per_source": 50000 } }
```
`time_window_hours` applies to quick scans (null = unlimited for full).

### 3.2 StageProgress
```json
{ "stage": "evtx", "status": "pending"|"running"|"completed"|"partial"|"failed"|"skipped"|"cancelled",
  "records": 1234, "progress": 0.45, "duration_ms": 5200, "errors": ["Security: Access is denied (requires elevation)"],
  "message": "Reading Microsoft-Windows-PowerShell/Operational" }
```

### 3.3 Artifact upload (multipart/form-data)
- `meta` (application/json) — `ArtifactMeta`
- `records` (application/x-ndjson, optional) — one parsed record per line (schemas §4)
- `original` (application/octet-stream, optional) — faithful copy of the source artifact (e.g. exported `.evtx`, copied browser SQLite, `.pf` file). Backend recomputes SHA-256 and compares to `meta.sha256`; mismatch → `verified=false` and a chain-of-custody entry with `verification_status="mismatch"`.
- Backend also verifies `meta.records_sha256` (SHA-256 of the exact NDJSON bytes).

```json
ArtifactMeta = {
  "artifact_key": "evtx:Security",            // unique within a scan
  "source": "evtx"|"registry"|"prefetch"|"amcache"|"browser"|"filesystem",
  "name": "Security event log",
  "original_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
  "status": "collected"|"partial"|"permission_denied"|"not_found"|"unsupported"|"error",
  "acquisition_method": "EvtQuery live channel query (pywin32)" ,
  "sha256": "hex|null",            // of `original` if uploaded
  "records_sha256": "hex|null",
  "size_bytes": 0,
  "last_modified": "iso|null",
  "collected_at": "iso",
  "collector_version": "0.1.0",
  "record_count": 0,
  "parser": "pywin32-evtquery|winreg|PECmd|prefetch-metadata|AmcacheParser|sqlite3|recyclebin-$I|fs-stat",
  "side_effects": ["Read-only API query; no evidence modified"],
  "error": "string|null",
  "time_window": {"start": "iso|null", "end": "iso|null"}
}
```
Artifacts with status `permission_denied` / `not_found` / `unsupported` / `error` are still uploaded (meta only) so limitations are recorded.

### 3.4 DiscoveryItem
```json
{ "source": "evtx", "artifact_key": "evtx:Security", "name": "Security event log",
  "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
  "availability": "available"|"collected"|"partially_accessible"|"permission_denied"|"not_found"|"unsupported",
  "last_modified": "iso|null", "size_bytes": 0, "access_note": "Requires elevation" }
```

---

## 4. Parsed record schemas (NDJSON lines)

Every line has: `record_id` (stable, unique within artifact, e.g. `Security:84123`), `source`, plus source-specific fields. All timestamps ISO-8601 **with offset**; add `"timestamp_precision": "100ns"|"microsecond"|"millisecond"|"second"|"day"|"unknown"` where known. Never invent values — use `null`.

**evtx**: `{ channel, provider, event_id:int, record_number:int, level:int|null, time_created, computer, user_sid|null, process_id|null, thread_id|null, event_data:{name:value}, xml }`

**registry**: `{ category: "run"|"runonce"|"userassist"|"usb"|"installed_software"|"services"|"profile"|"shell"|"scheduled_task", hive: "HKLM"|"HKCU"|"HKU\\<sid>", key_path, value_name|null, value_type|null, value_data|null, last_write|null, user_sid|null, decoded:{...} }`
- userassist `decoded`: `{ name (ROT13-decoded), run_count|null, focus_count|null, focus_time_ms|null, last_executed|null }`
- usb `decoded`: `{ device_class, vendor, product, revision, serial, friendly_name }`
- installed_software `decoded`: `{ display_name, publisher, version, install_date, install_location }`
- services `decoded`: `{ image_path, start_type, service_type, display_name, object_name }`

**prefetch**: `{ executable, prefetch_hash, pf_path, pf_created, pf_modified, run_count|null, last_run_times:[iso], referenced_files:[str], referenced_dirs:[str], volume_serials:[str], parser }`  (metadata-only parser leaves run_count/last_run_times null/empty)

**amcache**: `{ record_type: "InventoryApplicationFile"|"InventoryApplication"|"File"|..., program_path|null, name|null, sha1|null, publisher|null, version|null, size|null, link_date|null, key_last_write|null, program_id|null }`  — inventory, **not proof of execution**.

**browser**: `{ browser: "chrome"|"edge"|"firefox", profile, kind: "visit"|"download", url, title|null, visit_time|null, visit_count|null, transition|null, target_path|null, start_time|null, end_time|null, received_bytes|null, total_bytes|null, mime_type|null, referrer|null, danger_type|null, state|null }`

**filesystem**: `{ kind: "recycle_bin"|"file_metadata"|"mft"|"usn", path, size|null, created|null, modified|null, accessed|null, mft_changed|null, deleted_time|null, original_path|null, usn_reason|null, usn|null, mft_entry|null, mft_sequence|null, sha256|null, attributes|null }`

---

## 5. Normalized event schema (backend table `normalized_events`)
`event_id, investigation_id, endpoint_id, artifact_source, event_type, timestamp (nullable), timestamp_precision, timezone, user_identifier, process_identifier, process_name, file_path, registry_path, network_indicator, source_artifact_id, source_record_id, evidence_reference, confidence, raw_metadata (JSONB), summary, suspicious(bool), severity("info"|"low"|"medium"|"high"|"critical")`

`event_type` vocabulary: `logon_success, logon_failure, logoff, explicit_credentials, special_privileges, process_created, service_installed, scheduled_task_created, user_created, group_member_added, audit_log_cleared, powershell_script_block, powershell_activity, defender_detection, sysmon_event, generic_event, registry_persistence, registry_value, userassist_execution, usb_device, software_installed, service_config, prefetch_execution, prefetch_present, amcache_inventory, browser_visit, browser_download, file_created, file_modified, file_deleted, recycle_bin_entry, file_metadata`

---

## 6. Analyst API (all require analyst JWT)

Pagination: `?page=1&page_size=50` → `{ items: [...], total, page, page_size }` on list endpoints marked **(paged)**.

- `POST /api/investigations` `{ title, description?, endpoint_id, assigned_user_ids?: [] }` → `Investigation`
- `GET /api/investigations` **(paged)** ; `GET /api/investigations/{id}`
- `Investigation = { id, title, description, endpoint_id, endpoint_hostname, status: "open"|"in_review"|"closed", is_demo, created_by, created_at, updated_at }`
- `GET /api/investigations/{id}/summary` → `{ evidence_collected (artifact count), records_total, events_total, suspicious_findings, correlated_events, high_confidence_relationships, integrity: { verified, mismatched, unverified }, sources: [{ source, status, records }], latest_scan: ScanJob|null }`
- `POST /api/endpoints/{id}/scans` `{ investigation_id, scan_type, time_window_hours?, sources? }` → `ScanJob` (status `queued`)
- `GET /api/scans/{id}` → `ScanJob = { id, investigation_id, endpoint_id, scan_type, status: "queued"|"collecting"|"processing"|"completed"|"partial"|"failed"|"cancelled", time_window_hours, sources, created_at, started_at, finished_at, cancel_requested, limitations, side_effects }`
- `GET /api/scans/{id}/progress` → `{ scan: ScanJob, stages: StageProgress[] (+ "processing" pseudo-stage) }`
- `POST /api/scans/{id}/cancel` → `ScanJob`
- `GET /api/scans/{id}/artifacts` → `CollectedArtifact[]` (= ArtifactMeta + `id, verified, verification_status, storage_ref`)
- WebSocket `GET /ws/scans/{id}?token=<jwt>` pushes `{ type: "progress", data: <progress payload> }` on every change, and `{ type: "status", data: ScanJob }`.

Evidence:
- `GET /api/investigations/{id}/evidence` **(paged)** `?type=&q=` → `EvidenceEntity[]`
- `GET /api/investigations/{id}/evidence/{evidence_id}` → `{ entity, relationships: Relationship[], events: TimelineEvent[], findings: Finding[] }`
- `EvidenceEntity = { id, type: "user"|"process"|"executable"|"file"|"registry_key"|"url"|"event"|"network"|"service"|"scheduled_task", key, label, properties, sources: [artifact_source], first_seen, last_seen, suspicious, risk_score }`
- `GET /api/investigations/{id}/evidence-graph?at=&sources=evtx,registry&relationship_types=EXECUTED,...&evidence_classes=direct,strong,weak,hypothesis&focus=<entity_id>&depth=2&suspicious_only=false` →
  `{ nodes: [{ id, type, label, key, suspicious, risk_score, sources, first_seen, last_seen, properties }], edges: Relationship[], stats: { node_count, edge_count, truncated: bool } }`
  `at` = Time Travel: include only relationships whose `timestamp <= at` (relationships with null timestamp excluded when `at` set) and nodes they touch.
- `GET /api/investigations/{id}/relationships` **(paged)** → `Relationship[]`
- `Relationship = { id, source, target, type: "EXECUTED"|"CREATED"|"MODIFIED"|"ACCESSED"|"AUTHENTICATED"|"DOWNLOADED"|"CONNECTED_TO"|"PERSISTENCE_MODIFIED"|"SPAWNED"|"ASSOCIATED_WITH", evidence_class: "direct"|"strong"|"weak"|"hypothesis", correlation_method, confidence: 0..1, explanation, timestamp|null, supporting_event_ids: [], supporting_artifact_ids: [] }`

Timeline:
- `GET /api/investigations/{id}/timeline` `?start=&end=&groups=&sources=&suspicious_only=&limit=5000` → `{ events: TimelineEvent[], bounds: {start, end}, collection_time, total, truncated }`
- `GET /api/investigations/{id}/timeline/range` → `{ start, end, buckets: [{ t, count, suspicious }] }` (`?buckets=200`)
- `TimelineEvent = { id, timestamp, timestamp_precision, group: "user"|"process"|"registry"|"browser"|"file"|"security", event_type, artifact_source, summary, suspicious, severity, entity_ids, source_record_id, source_artifact_id }`

Artifact explorers **(paged)**, `?q=` free text:
- `/api/investigations/{id}/artifacts/{evtx|registry|prefetch|amcache|browser|filesystem}` → items `{ id, artifact_id, artifact_key, record_id, original_path, sha256, data: <record §4>, related_event_ids }`
  extra filters: evtx `event_id, channel`; registry `category`; browser `kind, browser`; filesystem `kind`.

Findings:
- `GET /api/investigations/{id}/findings` → `Finding[]`
- `Finding = { id, rule_id, name, severity, description, affected_entity_id|null, affected_entity_label, detection_logic, supporting_event_ids, timestamp, confidence, mitre: { technique_id, technique_name, tactic }|null, recommendations: [], disclaimer: "A detection indicates activity worth review, not proof of malicious intent." }`
- `GET /api/investigations/{id}/risk` → `{ score: 0..100, level, factors: [{ finding_id, name, contribution, explanation }], explanation }`

Incidents / notes / reports / custody:
- `GET|POST /api/investigations/{id}/incidents` ; `GET|PATCH /api/incidents/{id}` — `IncidentCase = { id, investigation_id, title, status: "hypothesis"|"investigating"|"supported"|"refuted"|"closed", hypothesis, affected_user, affected_process, attached_entity_ids, attached_event_ids, attached_finding_ids, conclusion, created_at, updated_at }`
- `GET|POST /api/investigations/{id}/notes` — `{ id, body, incident_id|null, author, created_at }`
- `POST /api/investigations/{id}/reports` `{ format: "pdf"|"json", incident_id? }` → `Report = { id, format, status, sha256, created_at, download_url }` ; `GET /api/investigations/{id}/reports` ; `GET /api/reports/{id}/download`
- `GET /api/investigations/{id}/custody` → chain_of_custody entries `{ id, artifact_id, action, actor, timestamp, sha256, verification_status, details }`
- `POST /api/demo/seed` (admin only) → creates a clearly flagged demo investigation from a synthetic dataset (`is_demo=true`).

Errors: `{ "detail": str }` with proper HTTP codes (401/403/404/409/413/422/429).
