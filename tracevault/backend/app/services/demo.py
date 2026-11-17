"""Clearly labeled Demonstration Dataset Seeder (`is_demo=true`).

Flows through the exact same ingestion, SHA-256 verification, normalization,
correlation, and detection pipeline as real endpoint uploads.
"""

from __future__ import annotations

import hashlib
import io
import json
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    EndpointModel,
    IncidentCaseModel,
    InvestigationModel,
    InvestigationNoteModel,
    ScanJobModel,
    new_uuid,
    utc_now_str,
)
from .ingestion import ingest_uploaded_artifact
from .pipeline import execute_processing_pipeline


def _make_ndjson_stream(records: list[dict]) -> tuple[io.BytesIO, str, int]:
    buf = io.BytesIO()
    for r in records:
        line = (json.dumps(r, sort_keys=True) + "\n").encode("utf-8")
        buf.write(line)
    raw = buf.getvalue()
    digest = hashlib.sha256(raw).hexdigest()
    buf.seek(0)
    return buf, digest, len(raw)


def seed_demo_investigation(db: Session, created_by: str = "admin") -> InvestigationModel:
    """Create or refresh a clearly flagged (`is_demo=True`, `DEMO-WORKSTATION-07`) forensic investigation."""
    existing_ep = db.scalar(select(EndpointModel).where(EndpointModel.machine_id == "DEMO-MACHINE-GUID-0007"))
    if not existing_ep:
        existing_ep = EndpointModel(
            id=new_uuid(),
            machine_id="DEMO-MACHINE-GUID-0007",
            hostname="DEMO-WORKSTATION-07",
            os_name="Windows 11 Enterprise (Synthetic Demo)",
            os_version="10.0",
            os_build="22631",
            architecture="AMD64",
            agent_version="0.1.0-demo",
            collection_user="CORP\\j.miller",
            is_elevated=True,
            storage=[{"drive": "C:\\", "filesystem": "NTFS", "total_bytes": 512000000000, "free_bytes": 310000000000}],
            discovery=[
                {"source": s, "artifact_key": f"{s}:demo", "name": f"Demo {s.upper()}", "location": f"C:\\Demo\\{s}", "availability": "collected", "last_modified": "2026-11-16T14:25:00+00:00", "size_bytes": 4096, "access_note": "Demonstration dataset"}
                for s in ("evtx", "registry", "prefetch", "amcache", "browser", "filesystem")
            ],
            registered_at=utc_now_str(),
            last_seen=utc_now_str(),
        )
        db.add(existing_ep)
        db.flush()

    inv = InvestigationModel(
        id=new_uuid(),
        title="[DEMO] Spear-Phishing Download, PowerShell Staging & Persistence Reconstruction",
        description="Synthetic demonstration dataset illustrating multi-source correlation across Browser downloads, EVTX 4688/4104/7045/4698/1102, Prefetch, Amcache, Registry Run/UserAssist, and Recycle Bin.",
        endpoint_id=existing_ep.id,
        status="in_review",
        is_demo=True,
        created_by=created_by,
        assigned_user_ids=[],
        created_at=utc_now_str(),
        updated_at=utc_now_str(),
    )
    db.add(inv)
    db.flush()

    scan = ScanJobModel(
        id=new_uuid(),
        investigation_id=inv.id,
        endpoint_id=existing_ep.id,
        scan_type="full",
        status="processing",
        time_window_hours=None,
        sources=["evtx", "registry", "prefetch", "amcache", "browser", "filesystem"],
        stages=[
            {"stage": s, "status": "completed", "records": 5, "progress": 1.0, "duration_ms": 120, "errors": [], "message": "Demo stage completed"}
            for s in ("evtx", "registry", "prefetch", "amcache", "browser", "filesystem")
        ],
        cancel_requested=False,
        limitations=["SYNTHETIC DEMO INVESTIGATION: Generated via /api/demo/seed for analytical validation."],
        side_effects=["Synthetic dataset — no live endpoint modified."],
        created_at="2026-11-16T14:30:00+00:00",
        started_at="2026-11-16T14:30:01+00:00",
    )
    db.add(scan)
    db.flush()

    # 1. Browser records: Phishing visit + dropper download
    browser_recs = [
        {
            "record_id": "edge:Default:visit:101",
            "source": "browser",
            "browser": "edge",
            "profile": "Default",
            "kind": "visit",
            "url": "https://portal-invoice-verify.example.net/q4-statement",
            "title": "Q4 Vendor Statement Portal",
            "visit_time": "2026-11-16T14:01:10+00:00",
            "timestamp_precision": "microsecond",
            "visit_count": 1,
            "transition": "LINK",
            "target_path": None,
            "start_time": None,
            "end_time": None,
            "received_bytes": None,
            "total_bytes": None,
            "mime_type": None,
            "referrer": None,
            "danger_type": None,
            "state": None,
        },
        {
            "record_id": "edge:Default:download:202",
            "source": "browser",
            "browser": "edge",
            "profile": "Default",
            "kind": "download",
            "url": "https://cdn-invoice-verify.example.net/Q4_Invoice_Updater.exe",
            "title": "Q4_Invoice_Updater.exe",
            "visit_time": "2026-11-16T14:01:25+00:00",
            "timestamp_precision": "microsecond",
            "visit_count": None,
            "transition": None,
            "target_path": r"C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe",
            "start_time": "2026-11-16T14:01:25+00:00",
            "end_time": "2026-11-16T14:01:28+00:00",
            "received_bytes": 412672,
            "total_bytes": 412672,
            "mime_type": "application/x-msdownload",
            "referrer": "https://portal-invoice-verify.example.net/q4-statement",
            "danger_type": "UNCOMMON_CONTENT",
            "state": "COMPLETE",
        },
    ]

    # 2. EVTX records: Logon failures + logon success + process execution chain + PowerShell + Service + Task + Log clear
    evtx_recs = [
        {
            "record_id": "Security:9001",
            "source": "evtx",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4625,
            "record_number": 9001,
            "level": 0,
            "time_created": "2026-11-16T13:58:10+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-18",
            "process_id": 640,
            "thread_id": 712,
            "event_data": {"TargetUserName": "j.miller", "IpAddress": "10.24.8.99", "LogonType": "3"},
            "xml": "<Event><System><EventID>4625</EventID></System></Event>",
        },
        {
            "record_id": "Security:9002",
            "source": "evtx",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4625,
            "record_number": 9002,
            "level": 0,
            "time_created": "2026-11-16T13:58:14+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-18",
            "process_id": 640,
            "thread_id": 712,
            "event_data": {"TargetUserName": "j.miller", "IpAddress": "10.24.8.99", "LogonType": "3"},
            "xml": "<Event><System><EventID>4625</EventID></System></Event>",
        },
        {
            "record_id": "Security:9003",
            "source": "evtx",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4625,
            "record_number": 9003,
            "level": 0,
            "time_created": "2026-11-16T13:58:19+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-18",
            "process_id": 640,
            "thread_id": 712,
            "event_data": {"TargetUserName": "j.miller", "IpAddress": "10.24.8.99", "LogonType": "3"},
            "xml": "<Event><System><EventID>4625</EventID></System></Event>",
        },
        {
            "record_id": "Security:9004",
            "source": "evtx",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4624,
            "record_number": 9004,
            "level": 0,
            "time_created": "2026-11-16T14:00:02+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-21-998877-1104",
            "process_id": 640,
            "thread_id": 800,
            "event_data": {"TargetUserName": "j.miller", "IpAddress": "10.24.8.99", "LogonType": "2"},
            "xml": "<Event><System><EventID>4624</EventID></System></Event>",
        },
        {
            "record_id": "Security:9010",
            "source": "evtx",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4688,
            "record_number": 9010,
            "level": 0,
            "time_created": "2026-11-16T14:02:05+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-21-998877-1104",
            "process_id": 4120,
            "thread_id": 4124,
            "event_data": {
                "SubjectUserName": "j.miller",
                "ProcessId": "3200",
                "ParentProcessName": r"C:\Windows\explorer.exe",
                "NewProcessId": "4880",
                "NewProcessName": r"C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe",
                "CommandLine": r'"C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe" --silent',
            },
            "xml": "<Event><System><EventID>4688</EventID></System><EventData><Data Name='NewProcessName'>C:\\Users\\j.miller\\Downloads\\Q4_Invoice_Updater.exe</Data></EventData></Event>",
        },
        {
            "record_id": "Security:9011",
            "source": "evtx",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4688,
            "record_number": 9011,
            "level": 0,
            "time_created": "2026-11-16T14:02:11+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-21-998877-1104",
            "process_id": 4880,
            "thread_id": 4900,
            "event_data": {
                "SubjectUserName": "j.miller",
                "ProcessId": "4880",
                "ParentProcessName": r"C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe",
                "NewProcessId": "5312",
                "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": r"powershell.exe -nop -w hidden -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            },
            "xml": "<Event><System><EventID>4688</EventID></System><EventData><Data Name='CommandLine'>powershell.exe -nop -w hidden -ExecutionPolicy Bypass -enc ...</Data></EventData></Event>",
        },
        {
            "record_id": "Microsoft-Windows-PowerShell/Operational:401",
            "source": "evtx",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider": "Microsoft-Windows-PowerShell",
            "event_id": 4104,
            "record_number": 401,
            "level": 3,
            "time_created": "2026-11-16T14:02:13+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-21-998877-1104",
            "process_id": 5312,
            "thread_id": 5320,
            "event_data": {
                "SubjectUserName": "j.miller",
                "ProcessId": "5312",
                "ScriptBlockText": r"Copy-Item C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe; New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name 'CorpSyncHelper' -Value 'C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe' -Force",
            },
            "xml": "<Event><System><EventID>4104</EventID></System></Event>",
        },
        {
            "record_id": "Security:9015",
            "source": "evtx",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4698,
            "record_number": 9015,
            "level": 0,
            "time_created": "2026-11-16T14:03:05+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-21-998877-1104",
            "process_id": 5312,
            "thread_id": 5320,
            "event_data": {
                "SubjectUserName": "j.miller",
                "TaskName": r"\Microsoft\Windows\Telemetry\CorpTelemetrySync",
                "Command": r"C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe",
            },
            "xml": "<Event><System><EventID>4698</EventID></System></Event>",
        },
        {
            "record_id": "System:7712",
            "source": "evtx",
            "channel": "System",
            "provider": "Service Control Manager",
            "event_id": 7045,
            "record_number": 7712,
            "level": 4,
            "time_created": "2026-11-16T14:03:40+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-21-998877-1104",
            "process_id": 708,
            "thread_id": 912,
            "event_data": {
                "SubjectUserName": "j.miller",
                "ServiceName": "CorpSyncUpdaterSvc",
                "ServiceFileName": r"C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe --service",
                "ServiceType": "user mode service",
                "StartType": "auto start",
            },
            "xml": "<Event><System><EventID>7045</EventID></System></Event>",
        },
        {
            "record_id": "Security:9025",
            "source": "evtx",
            "channel": "Security",
            "provider": "Microsoft-Windows-Eventlog",
            "event_id": 1102,
            "record_number": 9025,
            "level": 4,
            "time_created": "2026-11-16T14:05:00+00:00",
            "timestamp_precision": "100ns",
            "computer": "DEMO-WORKSTATION-07",
            "user_sid": "S-1-5-21-998877-1104",
            "process_id": 1020,
            "thread_id": 1088,
            "event_data": {"SubjectUserName": "j.miller", "SubjectDomainName": "CORP"},
            "xml": "<Event><System><EventID>1102</EventID></System></Event>",
        },
    ]

    # 3. Registry records: Run key persistence + UserAssist GUI execution
    reg_recs = [
        {
            "record_id": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run:CorpSyncHelper",
            "source": "registry",
            "category": "run",
            "hive": "HKCU",
            "key_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "CorpSyncHelper",
            "value_type": "REG_SZ",
            "value_data": r"C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe",
            "last_write": "2026-11-16T14:02:14+00:00",
            "timestamp_precision": "100ns",
            "user_sid": "S-1-5-21-998877-1104",
            "decoded": {"command": r"C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe", "persistence_type": "run"},
        },
        {
            "record_id": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist:Q4_Invoice_Updater.exe",
            "source": "registry",
            "category": "userassist",
            "hive": "HKCU",
            "key_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
            "value_name": r"P:\Hfref\w.zvyyre\Qbjaybnqf\D4_Vaibvpr_Hcqngre.rkr",
            "value_type": "REG_BINARY",
            "value_data": "0000000001000000",
            "last_write": "2026-11-16T14:02:05+00:00",
            "timestamp_precision": "100ns",
            "user_sid": "S-1-5-21-998877-1104",
            "decoded": {
                "name": r"C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe",
                "run_count": 1,
                "focus_count": 2,
                "focus_time_ms": 4200,
                "last_executed": "2026-11-16T14:02:05+00:00",
            },
        },
    ]

    # 4. Prefetch records
    pf_recs = [
        {
            "record_id": "prefetch:Q4_INVOICE_UPDATER.EXE-8F912C1A.pf",
            "source": "prefetch",
            "executable": "Q4_INVOICE_UPDATER.EXE",
            "prefetch_hash": "8F912C1A",
            "pf_path": r"C:\Windows\Prefetch\Q4_INVOICE_UPDATER.EXE-8F912C1A.pf",
            "pf_created": "2026-11-16T14:02:06+00:00",
            "pf_modified": "2026-11-16T14:02:06+00:00",
            "timestamp_precision": "100ns",
            "run_count": 1,
            "last_run_times": ["2026-11-16T14:02:05+00:00"],
            "referenced_files": [
                r"C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe",
                r"C:\Windows\System32\ntdll.dll",
                r"C:\Windows\System32\kernel32.dll",
            ],
            "referenced_dirs": [r"C:\Users\j.miller\Downloads"],
            "volume_serials": ["D4B0-C7A3"],
            "parser": "PECmd",
        },
        {
            "record_id": "prefetch:POWERSHELL.EXE-3B77E102.pf",
            "source": "prefetch",
            "executable": "POWERSHELL.EXE",
            "prefetch_hash": "3B77E102",
            "pf_path": r"C:\Windows\Prefetch\POWERSHELL.EXE-3B77E102.pf",
            "pf_created": "2026-11-16T14:02:11+00:00",
            "pf_modified": "2026-11-16T14:02:12+00:00",
            "timestamp_precision": "100ns",
            "run_count": 4,
            "last_run_times": ["2026-11-16T14:02:11+00:00"],
            "referenced_files": [
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r"C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe",
            ],
            "referenced_dirs": [r"C:\Users\j.miller\AppData\Local\Temp"],
            "volume_serials": ["D4B0-C7A3"],
            "parser": "PECmd",
        },
    ]

    # 5. Amcache records
    amcache_recs = [
        {
            "record_id": r"amcache:C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe",
            "source": "amcache",
            "record_type": "InventoryApplicationFile",
            "program_path": r"C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe",
            "name": "Q4_Invoice_Updater.exe",
            "sha1": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1098",
            "publisher": "Unsigned",
            "version": "1.0.0.0",
            "size": 412672,
            "link_date": "2026-11-15T22:10:00+00:00",
            "key_last_write": "2026-11-16T14:01:29+00:00",
            "timestamp_precision": "100ns",
            "program_id": "0006f81a2c3d4e5f",
        }
    ]

    # 6. Filesystem records (Downloads file + Temp copy + Recycle Bin deletion of original dropper)
    fs_recs = [
        {
            "record_id": r"file:C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe",
            "source": "filesystem",
            "kind": "file_metadata",
            "path": r"C:\Users\j.miller\AppData\Local\Temp\svc_sync.exe",
            "size": 412672,
            "created": "2026-11-16T14:02:13+00:00",
            "modified": "2026-11-16T14:02:13+00:00",
            "accessed": "2026-11-16T14:03:40+00:00",
            "mft_changed": "2026-11-16T14:02:13+00:00",
            "deleted_time": None,
            "timestamp_precision": "100ns",
            "original_path": None,
            "usn_reason": None,
            "usn": None,
            "mft_entry": 88412,
            "mft_sequence": 2,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "attributes": "ext=.exe",
        },
        {
            "record_id": "recyclebin:$I4F912A.exe",
            "source": "filesystem",
            "kind": "recycle_bin",
            "path": r"C:\$Recycle.Bin\S-1-5-21-998877-1104\$I4F912A.exe",
            "size": 412672,
            "created": None,
            "modified": None,
            "accessed": None,
            "mft_changed": None,
            "deleted_time": "2026-11-16T14:04:30+00:00",
            "timestamp_precision": "100ns",
            "original_path": r"C:\Users\j.miller\Downloads\Q4_Invoice_Updater.exe",
            "usn_reason": "FILE_DELETE",
            "usn": 9912440,
            "mft_entry": 88210,
            "mft_sequence": 5,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "attributes": "RecycleBin_v2",
        },
    ]

    bundles = [
        ("browser:Edge", "browser", "Microsoft Edge History & Downloads", r"C:\Users\j.miller\AppData\Local\Microsoft\Edge\User Data", "sqlite3", browser_recs),
        ("evtx:Security", "evtx", "Security & Operational Event Logs", r"C:\Windows\System32\winevt\Logs\Security.evtx", "pywin32-evtquery", evtx_recs),
        ("registry:Persistence", "registry", "Registry Run & UserAssist Keys", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "winreg", reg_recs),
        ("prefetch:WindowsPrefetch", "prefetch", "Windows Prefetch (*.pf)", r"C:\Windows\Prefetch", "PECmd", pf_recs),
        ("amcache:AmcacheHve", "amcache", "Amcache Application Inventory", r"C:\Windows\appcompat\Programs\Amcache.hve", "AmcacheParser", amcache_recs),
        ("filesystem:UserFiles", "filesystem", "Filesystem & Recycle Bin ($I) Metadata", r"C:\Users\j.miller\Downloads", "recyclebin-$I", fs_recs),
    ]

    for a_key, src, name, orig_p, parser_name, recs in bundles:
        stream, digest, sz = _make_ndjson_stream(recs)
        meta = {
            "artifact_key": a_key,
            "source": src,
            "name": name,
            "original_path": orig_p,
            "status": "collected",
            "acquisition_method": "Synthetic Demo Seeder",
            "sha256": None,
            "records_sha256": digest,
            "size_bytes": sz,
            "last_modified": "2026-11-16T14:05:00+00:00",
            "collected_at": "2026-11-16T14:30:02+00:00",
            "collector_version": "0.1.0-demo",
            "record_count": len(recs),
            "parser": parser_name,
            "side_effects": ["Synthetic demonstration dataset"],
            "error": None,
            "time_window": None,
        }
        ingest_uploaded_artifact(db, scan, meta, stream, None, actor="demo-seeder")

    execute_processing_pipeline(db, scan.id)

    # Create a sample incident hypothesis and analyst note on the demo investigation
    inc = IncidentCaseModel(
        id=new_uuid(),
        investigation_id=inv.id,
        title="Hypothesis: Execution of Downloaded Dropper & Staging to Temp",
        status="investigating",
        hypothesis="User j.miller downloaded Q4_Invoice_Updater.exe from portal-invoice-verify.example.net, executed it from Downloads, which spawned encoded PowerShell to copy svc_sync.exe into Temp, establish Run key / Scheduled Task / Service persistence, and delete the original dropper.",
        affected_user="j.miller",
        affected_process="Q4_Invoice_Updater.exe",
        attached_entity_ids=[],
        attached_event_ids=[],
        attached_finding_ids=[],
        conclusion="Corroborated across Browser SQLite, EVTX 4688/4104/4698/7045/1102, UserAssist, Prefetch, Amcache, and Recycle Bin $I metadata.",
    )
    db.add(inc)
    db.add(
        InvestigationNoteModel(
            id=new_uuid(),
            investigation_id=inv.id,
            incident_id=inc.id,
            body="Verified SHA-256 parity between staged Temp binary and deleted Recycle Bin $I4F912A.exe record.",
            author=created_by,
        )
    )
    db.commit()
    db.refresh(inv)
    return inv
