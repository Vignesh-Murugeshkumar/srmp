"""Forensic artifact normalization engine (CONTRACT §5 & Spec §6).

Preserves original timestamp strings and precision semantics without fabricating UTC conversions
when timestamps are uncertain or missing.
"""

from __future__ import annotations

import ntpath
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import (
    ArtifactRecordModel,
    CollectedArtifactModel,
    NormalizedEventModel,
    new_uuid,
)

EVTX_EVENT_TYPE_MAP: dict[int, tuple[str, str]] = {
    4624: ("logon_success", "security"),
    4625: ("logon_failure", "security"),
    4634: ("logoff", "user"),
    4648: ("explicit_credentials", "security"),
    4672: ("special_privileges", "security"),
    4688: ("process_created", "process"),
    4697: ("service_installed", "security"),
    4698: ("scheduled_task_created", "security"),
    4720: ("user_created", "security"),
    4728: ("group_member_added", "security"),
    4732: ("group_member_added", "security"),
    7045: ("service_installed", "security"),
    1102: ("audit_log_cleared", "security"),
    4104: ("powershell_script_block", "process"),
    4103: ("powershell_activity", "process"),
    1116: ("defender_detection", "security"),
    1117: ("defender_detection", "security"),
}


def normalize_timestamp(ts: str | None) -> tuple[str | None, str]:
    """Normalize an ISO timestamp to UTC ISO-8601 when reliable, or preserve None/original."""
    if not ts or not isinstance(ts, str):
        return None, "UTC"
    s = ts.strip()
    if not s:
        return None, "UTC"
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            utc_dt = dt.astimezone(timezone.utc)
            return utc_dt.isoformat(), "UTC"
        # Naive timestamp: preserve as-is and mark timezone as "local/unspecified"
        return s, "local/unspecified"
    except ValueError:
        return None, "unknown"


def extract_exe_from_command(cmd: str | None) -> str | None:
    """Extract executable path from a Windows command line or registry Run value."""
    if not cmd or not isinstance(cmd, str):
        return None
    s = cmd.strip()
    if not s:
        return None
    if s.startswith('"'):
        end_q = s.find('"', 1)
        if end_q > 1:
            return s[1:end_q].strip()
    # Match C:\...\.exe or %...\...\.exe
    m = re.search(r'([A-Za-z]:\\[^\s"\']+?\.(?:exe|bat|cmd|ps1|vbs|dll|sys|msi))', s, re.IGNORECASE)
    if m:
        return m.group(1)
    first_tok = s.split()[0].strip("\"'")
    return first_tok if ("\\" in first_tok or first_tok.lower().endswith(".exe")) else None


def win_basename(path: str | None) -> str | None:
    if not path:
        return None
    return ntpath.basename(path.rstrip("\\/")) or path


def _normalize_evtx_record(rec: ArtifactRecordModel, endpoint_id: str) -> NormalizedEventModel:
    d = rec.data or {}
    event_id_num = int(d.get("event_id") or 0)
    channel = str(d.get("channel") or "")
    ed = d.get("event_data") or {}
    if not isinstance(ed, dict):
        ed = {}

    ev_type, _ = EVTX_EVENT_TYPE_MAP.get(event_id_num, ("generic_event", "security"))
    if "sysmon" in channel.lower() and event_id_num == 1:
        ev_type = "process_created"
    elif "sysmon" in channel.lower() and ev_type == "generic_event":
        ev_type = "sysmon_event"
    elif "powershell" in channel.lower() and ev_type == "generic_event":
        ev_type = "powershell_activity"
    elif "defender" in channel.lower() and ev_type in ("generic_event", "defender_detection"):
        if event_id_num in (1116, 1117, 1006, 1007):
            ev_type = "defender_detection"

    ts, tz = normalize_timestamp(d.get("time_created"))
    precision = str(d.get("timestamp_precision") or "100ns")

    user_id = (
        ed.get("TargetUserName")
        or ed.get("SubjectUserName")
        or ed.get("User")
        or ed.get("AccountName")
        or d.get("user_sid")
    )
    if user_id and str(user_id) in ("-", "S-1-0-0"):
        user_id = ed.get("SubjectUserName") or None

    proc_path = (
        ed.get("NewProcessName")
        or ed.get("Image")
        or ed.get("ProcessName")
        or ed.get("Application")
        or ed.get("ServiceFileName")
        or ed.get(" ImagePath")
    )
    if not proc_path and ev_type in ("powershell_script_block", "powershell_activity"):
        proc_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    proc_name = win_basename(proc_path) if proc_path else None
    proc_id = str(ed.get("NewProcessId") or ed.get("ProcessId") or d.get("process_id") or "") or None
    net_ind = ed.get("IpAddress") or ed.get("SourceNetworkAddress") or ed.get("DestinationIp")
    if net_ind in ("-", "127.0.0.1", "::1", ""):
        net_ind = None

    cmd_line = ed.get("CommandLine") or ed.get("ScriptBlockText") or ed.get("Payload") or ""
    suspicious = False
    severity = "info"

    if event_id_num == 1102:
        suspicious = True
        severity = "critical"
    elif event_id_num in (4697, 7045, 4698, 4720, 4728, 4732):
        suspicious = True
        severity = "medium"
    elif event_id_num == 4625:
        severity = "low"
    elif ev_type == "defender_detection":
        suspicious = True
        severity = "high"

    cmd_low = str(cmd_line).lower()
    if any(tok in cmd_low for tok in ("-enc", "encodedcommand", "downloadstring", "invoke-webrequest", "frombase64string", "-w hidden", "bypass")):
        suspicious = True
        severity = "high"

    summary = f"[{channel} #{event_id_num}] {ev_type}"
    if proc_name:
        summary += f" — {proc_name}"
    if user_id:
        summary += f" (user: {user_id})"
    if cmd_line:
        summary += f" | {str(cmd_line)[:120]}"

    return NormalizedEventModel(
        event_id=new_uuid(),
        investigation_id=rec.investigation_id,
        endpoint_id=endpoint_id,
        artifact_source="evtx",
        event_type=ev_type,
        timestamp=ts,
        timestamp_precision=precision,
        timezone=tz,
        user_identifier=str(user_id) if user_id else None,
        process_identifier=proc_id,
        process_name=proc_name,
        file_path=str(proc_path) if proc_path else None,
        registry_path=None,
        network_indicator=str(net_ind) if net_ind else None,
        source_artifact_id=rec.artifact_id,
        source_record_id=rec.record_id,
        evidence_reference=f"evtx://{rec.record_id}",
        confidence=1.0,
        raw_metadata=d,
        summary=summary,
        suspicious=suspicious,
        severity=severity,
    )


def _normalize_registry_record(rec: ArtifactRecordModel, endpoint_id: str) -> NormalizedEventModel:
    d = rec.data or {}
    cat = str(d.get("category") or "registry_value")
    key_path = str(d.get("key_path") or "")
    val_name = d.get("value_name")
    val_data = d.get("value_data")
    decoded = d.get("decoded") or {}
    if not isinstance(decoded, dict):
        decoded = {}

    # Distinguish UserAssist execution timestamp vs Registry key last-write timestamp
    raw_ts = decoded.get("last_executed") if cat == "userassist" and decoded.get("last_executed") else d.get("last_write")
    ts, tz = normalize_timestamp(raw_ts)
    precision = str(d.get("timestamp_precision") or "100ns")

    ev_type_map = {
        "run": "registry_persistence",
        "runonce": "registry_persistence",
        "userassist": "userassist_execution",
        "usb": "usb_device",
        "installed_software": "software_installed",
        "services": "service_config",
    }
    ev_type = ev_type_map.get(cat, "registry_value")

    exe_path: str | None = None
    proc_name: str | None = None
    suspicious = False
    severity = "info"

    if cat in ("run", "runonce"):
        exe_path = extract_exe_from_command(str(val_data or ""))
        proc_name = win_basename(exe_path) if exe_path else None
        val_low = str(val_data or "").lower()
        if any(p in val_low for p in ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\", "powershell", "cmd.exe", "mshta", "wscript")):
            suspicious = True
            severity = "high"
    elif cat == "userassist":
        ua_name = str(decoded.get("name") or "")
        if ":\\" in ua_name or ua_name.lower().endswith(".exe"):
            exe_path = ua_name
            proc_name = win_basename(ua_name)
    elif cat == "services":
        exe_path = extract_exe_from_command(str(decoded.get("image_path") or val_data or ""))
        proc_name = win_basename(exe_path) if exe_path else None

    summary = f"[Registry {cat}] {key_path}"
    if val_name:
        summary += f" -> {val_name}"
    if exe_path:
        summary += f" ({exe_path})"

    return NormalizedEventModel(
        event_id=new_uuid(),
        investigation_id=rec.investigation_id,
        endpoint_id=endpoint_id,
        artifact_source="registry",
        event_type=ev_type,
        timestamp=ts,
        timestamp_precision=precision,
        timezone=tz,
        user_identifier=d.get("user_sid"),
        process_identifier=None,
        process_name=proc_name,
        file_path=exe_path,
        registry_path=f"{key_path}\\{val_name}" if val_name else key_path,
        network_indicator=None,
        source_artifact_id=rec.artifact_id,
        source_record_id=rec.record_id,
        evidence_reference=f"registry://{rec.record_id}",
        confidence=0.95,
        raw_metadata=d,
        summary=summary,
        suspicious=suspicious,
        severity=severity,
    )


def _normalize_prefetch_record(rec: ArtifactRecordModel, endpoint_id: str) -> NormalizedEventModel:
    d = rec.data or {}
    exe = str(d.get("executable") or "")
    last_runs = d.get("last_run_times") or []
    raw_ts = last_runs[0] if last_runs else (d.get("pf_modified") or d.get("pf_created"))
    ts, tz = normalize_timestamp(raw_ts)
    ev_type = "prefetch_execution" if d.get("run_count") is not None or last_runs else "prefetch_present"

    ref_files = d.get("referenced_files") or []
    matched_exe_path = next((f for f in ref_files if isinstance(f, str) and f.upper().endswith(f"\\{exe.upper()}")), None)

    return NormalizedEventModel(
        event_id=new_uuid(),
        investigation_id=rec.investigation_id,
        endpoint_id=endpoint_id,
        artifact_source="prefetch",
        event_type=ev_type,
        timestamp=ts,
        timestamp_precision=str(d.get("timestamp_precision") or "100ns"),
        timezone=tz,
        user_identifier=None,
        process_identifier=None,
        process_name=exe or None,
        file_path=matched_exe_path or d.get("pf_path"),
        registry_path=None,
        network_indicator=None,
        source_artifact_id=rec.artifact_id,
        source_record_id=rec.record_id,
        evidence_reference=f"prefetch://{rec.record_id}",
        confidence=0.95 if ev_type == "prefetch_execution" else 0.8,
        raw_metadata=d,
        summary=f"[Prefetch] {exe} (run_count={d.get('run_count')}, hash={d.get('prefetch_hash')})",
        suspicious=False,
        severity="info",
    )


def _normalize_amcache_record(rec: ArtifactRecordModel, endpoint_id: str) -> NormalizedEventModel:
    d = rec.data or {}
    prog_path = d.get("program_path")
    name = d.get("name") or win_basename(prog_path)
    ts, tz = normalize_timestamp(d.get("key_last_write") or d.get("link_date"))

    return NormalizedEventModel(
        event_id=new_uuid(),
        investigation_id=rec.investigation_id,
        endpoint_id=endpoint_id,
        artifact_source="amcache",
        event_type="amcache_inventory",
        timestamp=ts,
        timestamp_precision=str(d.get("timestamp_precision") or "100ns"),
        timezone=tz,
        user_identifier=None,
        process_identifier=None,
        process_name=name,
        file_path=prog_path,
        registry_path=None,
        network_indicator=None,
        source_artifact_id=rec.artifact_id,
        source_record_id=rec.record_id,
        evidence_reference=f"amcache://{rec.record_id}",
        confidence=0.85,
        raw_metadata=d,
        summary=f"[Amcache Inventory] {prog_path or name} (SHA1={d.get('sha1') or 'n/a'})",
        suspicious=False,
        severity="info",
    )


def _normalize_browser_record(rec: ArtifactRecordModel, endpoint_id: str) -> NormalizedEventModel:
    d = rec.data or {}
    kind = str(d.get("kind") or "visit")
    browser = str(d.get("browser") or "browser")
    url = str(d.get("url") or "")
    target_path = d.get("target_path")
    raw_ts = d.get("start_time") or d.get("visit_time")
    ts, tz = normalize_timestamp(raw_ts)

    ev_type = "browser_download" if kind == "download" else "browser_visit"
    suspicious = False
    severity = "info"
    if kind == "download" and target_path:
        tp_low = str(target_path).lower()
        if tp_low.endswith((".exe", ".msi", ".ps1", ".bat", ".vbs", ".scr", ".hta", ".dll", ".zip", ".iso")):
            suspicious = True
            severity = "medium"
        if d.get("danger_type") and d.get("danger_type") not in ("NOT_DANGEROUS", "0", None):
            suspicious = True
            severity = "high"

    summary = (
        f"[{browser.capitalize()} Download] {url} -> {target_path}"
        if kind == "download"
        else f"[{browser.capitalize()} Visit] {url}"
    )

    return NormalizedEventModel(
        event_id=new_uuid(),
        investigation_id=rec.investigation_id,
        endpoint_id=endpoint_id,
        artifact_source="browser",
        event_type=ev_type,
        timestamp=ts,
        timestamp_precision=str(d.get("timestamp_precision") or "microsecond"),
        timezone=tz,
        user_identifier=None,
        process_identifier=None,
        process_name=f"{browser}.exe",
        file_path=str(target_path) if target_path else None,
        registry_path=None,
        network_indicator=url or None,
        source_artifact_id=rec.artifact_id,
        source_record_id=rec.record_id,
        evidence_reference=f"browser://{rec.record_id}",
        confidence=0.95,
        raw_metadata=d,
        summary=summary[:400],
        suspicious=suspicious,
        severity=severity,
    )


def _normalize_filesystem_record(rec: ArtifactRecordModel, endpoint_id: str) -> NormalizedEventModel:
    d = rec.data or {}
    kind = str(d.get("kind") or "file_metadata")
    path = str(d.get("original_path") or d.get("path") or "")
    raw_ts = d.get("deleted_time") or d.get("created") or d.get("modified")
    ts, tz = normalize_timestamp(raw_ts)

    if kind == "recycle_bin":
        ev_type = "recycle_bin_entry"
    elif d.get("deleted_time"):
        ev_type = "file_deleted"
    elif d.get("created"):
        ev_type = "file_created"
    else:
        ev_type = "file_metadata"

    suspicious = False
    severity = "info"
    p_low = path.lower()
    if any(loc in p_low for loc in ("\\temp\\", "\\appdata\\local\\temp\\")) and p_low.endswith((".exe", ".ps1", ".bat", ".vbs", ".dll")):
        suspicious = True
        severity = "medium"

    summary = f"[Filesystem {kind}] {path}"
    if d.get("sha256"):
        summary += f" (sha256={str(d['sha256'])[:12]}...)"

    return NormalizedEventModel(
        event_id=new_uuid(),
        investigation_id=rec.investigation_id,
        endpoint_id=endpoint_id,
        artifact_source="filesystem",
        event_type=ev_type,
        timestamp=ts,
        timestamp_precision=str(d.get("timestamp_precision") or "100ns"),
        timezone=tz,
        user_identifier=None,
        process_identifier=None,
        process_name=win_basename(path) if p_low.endswith(".exe") else None,
        file_path=path or None,
        registry_path=None,
        network_indicator=None,
        source_artifact_id=rec.artifact_id,
        source_record_id=rec.record_id,
        evidence_reference=f"filesystem://{rec.record_id}",
        confidence=0.9,
        raw_metadata=d,
        summary=summary,
        suspicious=suspicious,
        severity=severity,
    )


def normalize_investigation_records(db: Session, investigation_id: str, endpoint_id: str) -> int:
    """Normalize all `artifact_records` for an investigation into `normalized_events`."""
    db.execute(delete(NormalizedEventModel).where(NormalizedEventModel.investigation_id == investigation_id))
    db.flush()

    records = db.scalars(
        select(ArtifactRecordModel).where(ArtifactRecordModel.investigation_id == investigation_id)
    ).all()

    events: list[NormalizedEventModel] = []
    for rec in records:
        if rec.source == "evtx":
            ev = _normalize_evtx_record(rec, endpoint_id)
        elif rec.source == "registry":
            ev = _normalize_registry_record(rec, endpoint_id)
        elif rec.source == "prefetch":
            ev = _normalize_prefetch_record(rec, endpoint_id)
        elif rec.source == "amcache":
            ev = _normalize_amcache_record(rec, endpoint_id)
        elif rec.source == "browser":
            ev = _normalize_browser_record(rec, endpoint_id)
        else:
            ev = _normalize_filesystem_record(rec, endpoint_id)

        rec.related_event_ids = [ev.event_id]
        events.append(ev)
        if len(events) >= 500:
            db.add_all(events)
            db.flush()
            events.clear()

    if events:
        db.add_all(events)
        db.flush()

    db.commit()
    return len(records)
