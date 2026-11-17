"""Deterministic, explainable Evidence Correlation Engine (CONTRACT §6 & Spec §7).

Golden rule: Time proximity alone NEVER creates a relationship.
Every relationship requires a shared forensic identifier (PID, executable path, file path, hash,
user identifier, registry target, or URL download target) and records its correlation rule,
rule version, confidence, evidence class, explanation, and supporting event/artifact IDs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import CORRELATION_RULES_VERSION
from ..config import settings
from ..models import (
    CorrelationModel,
    EvidenceEntityModel,
    EvidenceRelationshipModel,
    NormalizedEventModel,
    TimelineEventModel,
    new_uuid,
)
from .normalization import win_basename


def _norm_path_key(path: str | None) -> str | None:
    if not path:
        return None
    s = path.strip().strip("\"'").replace("/", "\\").lower()
    return s if s else None


def _parse_dt(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _within_window(ts1: str | None, ts2: str | None, seconds: int) -> bool:
    d1 = _parse_dt(ts1)
    d2 = _parse_dt(ts2)
    if not d1 or not d2:
        return False
    try:
        return abs((d1 - d2).total_seconds()) <= seconds
    except TypeError:
        return False


def _event_timeline_group(ev: NormalizedEventModel) -> str:
    if ev.artifact_source == "browser":
        return "browser"
    if ev.artifact_source == "registry":
        return "registry"
    if ev.artifact_source == "filesystem":
        return "file"
    if ev.artifact_source in ("prefetch", "amcache"):
        return "process"
    if ev.event_type in ("process_created", "powershell_script_block", "powershell_activity"):
        return "process"
    if ev.event_type in ("logoff",):
        return "user"
    return "security"


def build_entities_and_correlations(db: Session, investigation_id: str) -> dict[str, int]:
    """Extract evidence entities, construct deterministic relationships, and populate timeline_events."""
    events = db.scalars(
        select(NormalizedEventModel).where(NormalizedEventModel.investigation_id == investigation_id)
    ).all()

    entities_by_key: dict[tuple[str, str], EvidenceEntityModel] = {}
    event_entity_map: dict[str, set[str]] = {ev.event_id: set() for ev in events}

    def get_or_create_entity(
        ent_type: str,
        key: str,
        label: str,
        ev: NormalizedEventModel,
        extra_props: dict[str, Any] | None = None,
    ) -> EvidenceEntityModel:
        norm_k = key.strip().lower()
        map_key = (ent_type, norm_k)
        ent = entities_by_key.get(map_key)
        if ent is None:
            ent = EvidenceEntityModel(
                id=new_uuid(),
                investigation_id=investigation_id,
                type=ent_type,
                key=norm_k,
                label=label or key,
                properties=dict(extra_props or {}),
                sources=[ev.artifact_source],
                first_seen=ev.timestamp,
                last_seen=ev.timestamp,
                suspicious=ev.suspicious,
                risk_score=25.0 if ev.suspicious else 0.0,
            )
            entities_by_key[map_key] = ent
        else:
            if ev.artifact_source not in ent.sources:
                ent.sources = [*ent.sources, ev.artifact_source]
            if ev.timestamp:
                if not ent.first_seen or ev.timestamp < ent.first_seen:
                    ent.first_seen = ev.timestamp
                if not ent.last_seen or ev.timestamp > ent.last_seen:
                    ent.last_seen = ev.timestamp
            if ev.suspicious and not ent.suspicious:
                ent.suspicious = True
                ent.risk_score = max(ent.risk_score or 0.0, 25.0)
            if extra_props:
                merged = dict(ent.properties or {})
                for k, v in extra_props.items():
                    if v is not None and k not in merged:
                        merged[k] = v
                ent.properties = merged
        event_entity_map[ev.event_id].add(ent.id)
        return ent

    relationships_by_sig: dict[tuple[str, str, str, str], EvidenceRelationshipModel] = {}
    correlations_to_add: list[CorrelationModel] = []

    def add_relationship(
        src: EvidenceEntityModel,
        dst: EvidenceEntityModel,
        rel_type: str,
        evidence_class: str,
        rule_id: str,
        method: str,
        confidence: float,
        explanation: str,
        ev_list: list[NormalizedEventModel],
    ) -> None:
        if src.id == dst.id:
            return
        sig = (src.id, dst.id, rel_type, method)
        ev_ids = sorted({e.event_id for e in ev_list if e.event_id})
        art_ids = sorted({e.source_artifact_id for e in ev_list if e.source_artifact_id})
        timestamps = [e.timestamp for e in ev_list if e.timestamp]
        rel_ts = min(timestamps) if timestamps else None

        existing = relationships_by_sig.get(sig)
        if existing is None:
            rel = EvidenceRelationshipModel(
                id=new_uuid(),
                investigation_id=investigation_id,
                source_id=src.id,
                target_id=dst.id,
                type=rel_type,
                evidence_class=evidence_class,
                correlation_method=method,
                confidence=round(min(1.0, max(0.1, confidence)), 2),
                explanation=explanation,
                timestamp=rel_ts,
                supporting_event_ids=ev_ids,
                supporting_artifact_ids=art_ids,
            )
            relationships_by_sig[sig] = rel
            correlations_to_add.append(
                CorrelationModel(
                    id=new_uuid(),
                    investigation_id=investigation_id,
                    relationship_id=rel.id,
                    rule_id=rule_id,
                    rule_version=CORRELATION_RULES_VERSION,
                    confidence=rel.confidence,
                    explanation=explanation,
                    supporting_event_ids=ev_ids,
                )
            )
        else:
            existing.supporting_event_ids = sorted(set(existing.supporting_event_ids) | set(ev_ids))
            existing.supporting_artifact_ids = sorted(set(existing.supporting_artifact_ids) | set(art_ids))
            if confidence > existing.confidence:
                existing.confidence = round(min(1.0, confidence), 2)
            if rel_ts and (not existing.timestamp or rel_ts < existing.timestamp):
                existing.timestamp = rel_ts

    # Indexes for cross-artifact correlation
    executables_by_path: dict[str, tuple[EvidenceEntityModel, list[NormalizedEventModel]]] = {}
    executables_by_basename: dict[str, list[tuple[EvidenceEntityModel, NormalizedEventModel]]] = {}
    files_by_path: dict[str, tuple[EvidenceEntityModel, list[NormalizedEventModel]]] = {}
    processes_by_exe_path: dict[str, list[tuple[EvidenceEntityModel, NormalizedEventModel]]] = {}
    browser_downloads_by_path: dict[str, list[tuple[EvidenceEntityModel, EvidenceEntityModel, NormalizedEventModel]]] = {}

    # Pass 1: Extract primary entities & direct intra-record relationships
    for ev in events:
        raw = ev.raw_metadata or {}
        ed = raw.get("event_data") if isinstance(raw.get("event_data"), dict) else {}

        user_ent: EvidenceEntityModel | None = None
        if ev.user_identifier and str(ev.user_identifier).lower() not in ("none", "-", "n/a"):
            user_ent = get_or_create_entity(
                "user",
                ev.user_identifier,
                ev.user_identifier,
                ev,
                {"user_identifier": ev.user_identifier},
            )

        # EVTX specific direct relationships
        if ev.artifact_source == "evtx":
            ev_id_num = int(raw.get("event_id") or 0)
            if ev.event_type in ("logon_success", "logon_failure", "explicit_credentials") and user_ent:
                ev_node = get_or_create_entity(
                    "event",
                    f"evtx:{ev.source_record_id}",
                    f"Event {ev_id_num} ({ev.event_type})",
                    ev,
                    {"event_id": ev_id_num, "channel": raw.get("channel")},
                )
                add_relationship(
                    user_ent,
                    ev_node,
                    "AUTHENTICATED",
                    "direct",
                    "CORR-EVTX-AUTH",
                    "EVTX Logon Subject/Target User SID/Name",
                    1.0,
                    f"User '{user_ent.label}' recorded in Windows Security event #{ev_id_num} ({ev.source_record_id}).",
                    [ev],
                )
                if ev.network_indicator:
                    net_ent = get_or_create_entity(
                        "network",
                        ev.network_indicator,
                        ev.network_indicator,
                        ev,
                        {"ip": ev.network_indicator},
                    )
                    add_relationship(
                        user_ent,
                        net_ent,
                        "CONNECTED_TO",
                        "direct",
                        "CORR-EVTX-NET",
                        "EVTX Logon Source Network Address",
                        0.98,
                        f"Logon event {ev.source_record_id} recorded source network address {ev.network_indicator} for user {user_ent.label}.",
                        [ev],
                    )

            if ev.event_type in ("process_created", "powershell_script_block", "powershell_activity") and (
                ev.file_path or ev.process_name
            ):
                exe_path = ev.file_path or ev.process_name or "unknown.exe"
                exe_name = win_basename(exe_path) or exe_path
                pid = ev.process_identifier or "0"
                cmd_line = ed.get("CommandLine") or ed.get("ScriptBlockText")
                parent_path = ed.get("ParentProcessName") or ed.get("ParentImage")
                parent_pid = ed.get("ProcessId") or ed.get("ParentProcessId")

                proc_key = f"{exe_name.lower()}:{pid}" if pid != "0" else exe_path.lower()
                proc_ent = get_or_create_entity(
                    "process",
                    proc_key,
                    f"{exe_name} (PID {pid})" if pid != "0" else exe_name,
                    ev,
                    {
                        "process_name": exe_name,
                        "pid": pid,
                        "ppid": str(parent_pid) if parent_pid else None,
                        "executable_path": exe_path,
                        "command_line": cmd_line,
                        "user": ev.user_identifier,
                    },
                )
                exe_ent = get_or_create_entity(
                    "executable",
                    exe_path,
                    exe_name,
                    ev,
                    {"path": exe_path, "name": exe_name},
                )
                p_norm = _norm_path_key(exe_path)
                if p_norm:
                    executables_by_path.setdefault(p_norm, (exe_ent, []))[1].append(ev)
                    processes_by_exe_path.setdefault(p_norm, []).append((proc_ent, ev))
                executables_by_basename.setdefault(exe_name.lower(), []).append((exe_ent, ev))

                add_relationship(
                    proc_ent,
                    exe_ent,
                    "EXECUTED",
                    "direct",
                    "CORR-PROC-EXE",
                    "EVTX Process Creation Image Path",
                    1.0,
                    f"Process {proc_ent.label} directly executed image '{exe_path}' ({ev.source_record_id}).",
                    [ev],
                )
                if user_ent:
                    add_relationship(
                        user_ent,
                        proc_ent,
                        "EXECUTED",
                        "direct",
                        "CORR-USER-PROC",
                        "EVTX Process Creation SubjectUserName",
                        1.0,
                        f"User '{user_ent.label}' spawned process {proc_ent.label} ({ev.source_record_id}).",
                        [ev],
                    )
                if parent_path:
                    p_name = win_basename(str(parent_path)) or str(parent_path)
                    p_key = f"{p_name.lower()}:{parent_pid}" if parent_pid else str(parent_path).lower()
                    parent_ent = get_or_create_entity(
                        "process",
                        p_key,
                        f"{p_name} (PID {parent_pid})" if parent_pid else p_name,
                        ev,
                        {"process_name": p_name, "pid": str(parent_pid) if parent_pid else None, "executable_path": str(parent_path)},
                    )
                    add_relationship(
                        parent_ent,
                        proc_ent,
                        "SPAWNED",
                        "direct",
                        "CORR-PARENT-CHILD",
                        "EVTX ParentProcessName / ParentProcessId",
                        1.0,
                        f"Parent process '{parent_ent.label}' spawned child '{proc_ent.label}' in event {ev.source_record_id}.",
                        [ev],
                    )

            if ev.event_type == "service_installed":
                svc_name = ed.get("ServiceName") or "Service"
                svc_file = ed.get("ServiceFileName") or ed.get("ImagePath") or ev.file_path
                svc_ent = get_or_create_entity(
                    "service",
                    str(svc_name),
                    f"Service: {svc_name}",
                    ev,
                    {"service_name": svc_name, "image_path": svc_file},
                )
                if svc_file:
                    exe_ent = get_or_create_entity(
                        "executable",
                        str(svc_file),
                        win_basename(str(svc_file)) or str(svc_file),
                        ev,
                        {"path": str(svc_file)},
                    )
                    add_relationship(
                        svc_ent,
                        exe_ent,
                        "ASSOCIATED_WITH",
                        "direct",
                        "CORR-SVC-IMAGE",
                        "EVTX Service Installation ServiceFileName",
                        0.98,
                        f"Service '{svc_name}' configured to run binary '{svc_file}' ({ev.source_record_id}).",
                        [ev],
                    )
                if user_ent:
                    add_relationship(
                        user_ent,
                        svc_ent,
                        "CREATED",
                        "direct",
                        "CORR-USER-SVC",
                        "EVTX Service Installation Account",
                        0.95,
                        f"User '{user_ent.label}' installed service '{svc_name}' ({ev.source_record_id}).",
                        [ev],
                    )

            if ev.event_type == "scheduled_task_created":
                t_name = ed.get("TaskName") or "ScheduledTask"
                t_cmd = ed.get("Command") or ed.get("TaskContent")
                task_ent = get_or_create_entity(
                    "scheduled_task",
                    str(t_name),
                    f"Task: {t_name}",
                    ev,
                    {"task_name": t_name, "command": t_cmd},
                )
                if user_ent:
                    add_relationship(
                        user_ent,
                        task_ent,
                        "CREATED",
                        "direct",
                        "CORR-USER-TASK",
                        "EVTX 4698 SubjectUserName",
                        0.98,
                        f"User '{user_ent.label}' registered scheduled task '{t_name}' ({ev.source_record_id}).",
                        [ev],
                    )
                if ev.file_path or t_cmd:
                    exe_p = ev.file_path or str(t_cmd)
                    exe_ent = get_or_create_entity(
                        "executable",
                        exe_p,
                        win_basename(exe_p) or exe_p,
                        ev,
                        {"path": exe_p},
                    )
                    add_relationship(
                        task_ent,
                        exe_ent,
                        "EXECUTED",
                        "direct",
                        "CORR-TASK-EXE",
                        "Scheduled Task Action Command",
                        0.95,
                        f"Scheduled task '{t_name}' configured to execute '{exe_p}'.",
                        [ev],
                    )

            if ev.event_type == "audit_log_cleared":
                ev_node = get_or_create_entity(
                    "event",
                    f"evtx:{ev.source_record_id}",
                    "Security Audit Log Cleared (1102)",
                    ev,
                    {"event_id": 1102},
                )
                if user_ent:
                    add_relationship(
                        user_ent,
                        ev_node,
                        "MODIFIED",
                        "direct",
                        "CORR-LOG-CLEAR",
                        "EVTX 1102 SubjectUserName",
                        1.0,
                        f"User '{user_ent.label}' cleared the Windows Security audit log ({ev.source_record_id}).",
                        [ev],
                    )

        # Registry relationships
        elif ev.artifact_source == "registry":
            cat = str(raw.get("category") or "")
            reg_path = ev.registry_path or str(raw.get("key_path") or "")
            decoded = raw.get("decoded") if isinstance(raw.get("decoded"), dict) else {}

            if cat in ("run", "runonce"):
                reg_ent = get_or_create_entity(
                    "registry_key",
                    reg_path,
                    f"{raw.get('hive', 'REG')}\\...\\Run\\{raw.get('value_name', '')}",
                    ev,
                    {
                        "key_path": raw.get("key_path"),
                        "value_name": raw.get("value_name"),
                        "value_data": raw.get("value_data"),
                        "last_write": raw.get("last_write"),
                    },
                )
                if ev.file_path:
                    exe_ent = get_or_create_entity(
                        "executable",
                        ev.file_path,
                        win_basename(ev.file_path) or ev.file_path,
                        ev,
                        {"path": ev.file_path},
                    )
                    p_norm = _norm_path_key(ev.file_path)
                    if p_norm:
                        executables_by_path.setdefault(p_norm, (exe_ent, []))[1].append(ev)
                    executables_by_basename.setdefault((win_basename(ev.file_path) or ev.file_path).lower(), []).append((exe_ent, ev))

                    add_relationship(
                        reg_ent,
                        exe_ent,
                        "PERSISTENCE_MODIFIED",
                        "direct",
                        "CORR-REG-RUN-EXE",
                        "Registry Run/RunOnce Value Data Path",
                        0.98,
                        f"Registry persistence key '{reg_path}' references executable '{ev.file_path}' (value='{raw.get('value_data')}').",
                        [ev],
                    )

            elif cat == "userassist" and ev.file_path:
                ua_exe_ent = get_or_create_entity(
                    "executable",
                    ev.file_path,
                    win_basename(ev.file_path) or ev.file_path,
                    ev,
                    {
                        "path": ev.file_path,
                        "userassist_run_count": decoded.get("run_count"),
                        "userassist_last_executed": decoded.get("last_executed"),
                    },
                )
                reg_ent = get_or_create_entity(
                    "registry_key",
                    reg_path,
                    f"UserAssist: {win_basename(ev.file_path) or ev.file_path}",
                    ev,
                    {"key_path": raw.get("key_path"), "decoded": decoded},
                )
                p_norm = _norm_path_key(ev.file_path)
                if p_norm:
                    executables_by_path.setdefault(p_norm, (ua_exe_ent, []))[1].append(ev)
                executables_by_basename.setdefault((win_basename(ev.file_path) or ev.file_path).lower(), []).append((ua_exe_ent, ev))

                add_relationship(
                    reg_ent,
                    ua_exe_ent,
                    "EXECUTED",
                    "direct",
                    "CORR-USERASSIST-EXE",
                    "UserAssist ROT13 Decoded Executable Path",
                    0.95,
                    f"UserAssist registry entry records GUI execution of '{ev.file_path}' (run_count={decoded.get('run_count')}).",
                    [ev],
                )

            elif cat == "services" and ev.file_path:
                svc_name = decoded.get("service_name") or win_basename(reg_path) or "Service"
                svc_ent = get_or_create_entity(
                    "service",
                    str(svc_name),
                    f"Service: {svc_name}",
                    ev,
                    {"service_name": svc_name, "image_path": ev.file_path, "start_type": decoded.get("start_type")},
                )
                exe_ent = get_or_create_entity(
                    "executable",
                    ev.file_path,
                    win_basename(ev.file_path) or ev.file_path,
                    ev,
                    {"path": ev.file_path},
                )
                add_relationship(
                    svc_ent,
                    exe_ent,
                    "ASSOCIATED_WITH",
                    "direct",
                    "CORR-REG-SVC-EXE",
                    "Services Registry ImagePath",
                    0.95,
                    f"Windows Service key '{reg_path}' specifies ImagePath '{ev.file_path}'.",
                    [ev],
                )

        # Browser relationships
        elif ev.artifact_source == "browser":
            kind = str(raw.get("kind") or "visit")
            url = str(raw.get("url") or "")
            if url:
                url_ent = get_or_create_entity(
                    "url",
                    url,
                    url[:80],
                    ev,
                    {"url": url, "browser": raw.get("browser"), "profile": raw.get("profile"), "title": raw.get("title")},
                )
                if kind == "download" and ev.file_path:
                    file_ent = get_or_create_entity(
                        "file",
                        ev.file_path,
                        win_basename(ev.file_path) or ev.file_path,
                        ev,
                        {
                            "path": ev.file_path,
                            "download_url": url,
                            "danger_type": raw.get("danger_type"),
                            "mime_type": raw.get("mime_type"),
                        },
                    )
                    p_norm = _norm_path_key(ev.file_path)
                    if p_norm:
                        files_by_path.setdefault(p_norm, (file_ent, []))[1].append(ev)
                        browser_downloads_by_path.setdefault(p_norm, []).append((url_ent, file_ent, ev))
                    add_relationship(
                        url_ent,
                        file_ent,
                        "DOWNLOADED",
                        "direct",
                        "CORR-BROWSER-DL",
                        "Browser SQLite downloads.target_path",
                        0.99,
                        f"Browser ({raw.get('browser')}) downloaded URL '{url}' to local file '{ev.file_path}'.",
                        [ev],
                    )

        # Filesystem relationships
        elif ev.artifact_source == "filesystem" and ev.file_path:
            f_ent = get_or_create_entity(
                "file",
                ev.file_path,
                win_basename(ev.file_path) or ev.file_path,
                ev,
                {
                    "path": ev.file_path,
                    "kind": raw.get("kind"),
                    "size": raw.get("size"),
                    "sha256": raw.get("sha256"),
                    "created": raw.get("created"),
                    "modified": raw.get("modified"),
                    "deleted_time": raw.get("deleted_time"),
                },
            )
            p_norm = _norm_path_key(ev.file_path)
            if p_norm:
                files_by_path.setdefault(p_norm, (f_ent, []))[1].append(ev)

    # Pass 2: Cross-Artifact Correlation (Prefetch, Amcache, Browser Downloads -> Execution, Process -> Registry Persistence)
    for ev in events:
        raw = ev.raw_metadata or {}
        if ev.artifact_source == "prefetch":
            exe_name = str(raw.get("executable") or ev.process_name or "").strip()
            ref_files = [str(x) for x in (raw.get("referenced_files") or []) if x]
            pf_ent = get_or_create_entity(
                "file",
                str(raw.get("pf_path") or f"prefetch:{exe_name}"),
                f"Prefetch: {exe_name}",
                ev,
                {
                    "executable": exe_name,
                    "prefetch_hash": raw.get("prefetch_hash"),
                    "run_count": raw.get("run_count"),
                    "last_run_times": raw.get("last_run_times"),
                },
            )
            # Match by full referenced path first (strong), or executable basename (strong/weak)
            matched = False
            for rf in ref_files:
                rf_norm = _norm_path_key(rf)
                if rf_norm and rf_norm in executables_by_path:
                    exe_ent, src_evs = executables_by_path[rf_norm]
                    prox_boost = 0.05 if any(_within_window(ev.timestamp, se.timestamp, settings.correlation_window_seconds) for se in src_evs) else 0.0
                    add_relationship(
                        pf_ent,
                        exe_ent,
                        "EXECUTED",
                        "strong",
                        "CORR-PREFETCH-FULLPATH",
                        "Prefetch Executable + Referenced File Full Path Match",
                        0.92 + prox_boost,
                        f"Prefetch artifact '{pf_ent.label}' references full binary path '{rf}' matching executable entity '{exe_ent.label}'.",
                        [ev, *src_evs],
                    )
                    matched = True
            if not matched and exe_name.lower() in executables_by_basename:
                for exe_ent, src_ev in executables_by_basename[exe_name.lower()]:
                    prox_boost = 0.07 if _within_window(ev.timestamp, src_ev.timestamp, settings.correlation_window_seconds) else 0.0
                    add_relationship(
                        pf_ent,
                        exe_ent,
                        "EXECUTED",
                        "strong",
                        "CORR-PREFETCH-BASENAME",
                        "Prefetch Executable Name Match",
                        0.85 + prox_boost,
                        f"Prefetch record for '{exe_name}' corroborates execution of '{exe_ent.label}'.",
                        [ev, src_ev],
                    )

        elif ev.artifact_source == "amcache" and ev.file_path:
            p_norm = _norm_path_key(ev.file_path)
            am_ent = get_or_create_entity(
                "executable",
                ev.file_path,
                win_basename(ev.file_path) or ev.file_path,
                ev,
                {"path": ev.file_path, "amcache_sha1": raw.get("sha1"), "inventory_only": True},
            )
            if p_norm and p_norm in processes_by_exe_path:
                for proc_ent, proc_ev in processes_by_exe_path[p_norm]:
                    add_relationship(
                        proc_ent,
                        am_ent,
                        "ASSOCIATED_WITH",
                        "strong",
                        "CORR-AMCACHE-PATH",
                        "Amcache Inventory ProgramPath Exact Match (inventory != execution)",
                        0.88,
                        f"Amcache application inventory entry for '{ev.file_path}' (SHA1={raw.get('sha1')}) matches executed process '{proc_ent.label}'.",
                        [ev, proc_ev],
                    )

    # Correlate Browser Downloads -> Filesystem Metadata & Process Execution
    for dl_path_norm, dl_tuples in browser_downloads_by_path.items():
        for url_ent, dl_file_ent, dl_ev in dl_tuples:
            # Link to filesystem metadata / Recycle Bin if present at same path
            if dl_path_norm in files_by_path:
                fs_ent, fs_evs = files_by_path[dl_path_norm]
                non_browser_evs = [e for e in fs_evs if e.artifact_source == "filesystem"]
                if non_browser_evs:
                    add_relationship(
                         url_ent,
                        fs_ent,
                        "DOWNLOADED",
                        "strong",
                        "CORR-DL-FILESYSTEM",
                        "Browser Download target_path == Filesystem Path",
                        0.95,
                        f"Downloaded file '{dl_file_ent.label}' from '{url_ent.label}' confirmed on disk / Recycle Bin by filesystem metadata.",
                        [dl_ev, *non_browser_evs],
                    )
            # Link downloaded file to subsequent process execution at the exact same path
            if dl_path_norm in executables_by_path:
                exe_ent, exe_evs = executables_by_path[dl_path_norm]
                prox_boost = 0.05 if any(_within_window(dl_ev.timestamp, ee.timestamp, settings.correlation_window_seconds) for ee in exe_evs) else 0.0
                add_relationship(
                    dl_file_ent,
                    exe_ent,
                    "EXECUTED",
                    "strong",
                    "CORR-DL-EXECUTED",
                    "Browser Download target_path == Executed Binary Path",
                    0.93 + prox_boost,
                    f"File downloaded to '{dl_ev.file_path}' from '{url_ent.label}' was subsequently executed as '{exe_ent.label}'.",
                    [dl_ev, *exe_evs],
                )

    # Populate TimelineEventModel rows with linked entity_ids in memory, then perform a single short SQLite write transaction
    timeline_rows: list[TimelineEventModel] = [
        TimelineEventModel(
            id=ev.event_id,
            investigation_id=investigation_id,
            normalized_event_id=ev.event_id,
            timestamp=ev.timestamp,
            timestamp_precision=ev.timestamp_precision,
            group=_event_timeline_group(ev),
            event_type=ev.event_type,
            artifact_source=ev.artifact_source,
            summary=ev.summary,
            suspicious=ev.suspicious,
            severity=ev.severity,
            entity_ids=sorted(event_entity_map.get(ev.event_id, set())),
            source_record_id=ev.source_record_id,
            source_artifact_id=ev.source_artifact_id,
        )
        for ev in events
    ]

    db.execute(delete(CorrelationModel).where(CorrelationModel.investigation_id == investigation_id))
    db.execute(delete(EvidenceRelationshipModel).where(EvidenceRelationshipModel.investigation_id == investigation_id))
    db.execute(delete(TimelineEventModel).where(TimelineEventModel.investigation_id == investigation_id))
    db.execute(delete(EvidenceEntityModel).where(EvidenceEntityModel.investigation_id == investigation_id))

    if entities_by_key:
        db.add_all(list(entities_by_key.values()))
        db.flush()
    if relationships_by_sig:
        db.add_all(list(relationships_by_sig.values()))
        db.flush()
    if correlations_to_add:
        db.add_all(correlations_to_add)
    if timeline_rows:
        db.add_all(timeline_rows)

    db.commit()
    return {
        "entities": len(entities_by_key),
        "relationships": len(relationships_by_sig),
        "correlations": len(correlations_to_add),
    }
