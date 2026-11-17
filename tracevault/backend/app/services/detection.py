"""Rule-based Forensic Detection Engine (10 priority rules, MITRE ATT&CK mapping) and Explainable Risk Scoring (Spec §14)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import (
    AlertModel,
    DeviceRiskAssessmentModel,
    EvidenceEntityModel,
    NormalizedEventModel,
    new_uuid,
    utc_now_str,
)

DISCLAIMER = "A detection indicates activity worth review, not proof of malicious intent."

SEVERITY_WEIGHTS = {
    "critical": 28.0,
    "high": 18.0,
    "medium": 10.0,
    "low": 4.0,
    "info": 1.0,
}


def run_detections_and_risk(db: Session, investigation_id: str, endpoint_id: str) -> dict[str, Any]:
    """Evaluate the 10 forensic detection rules against normalized events and compute an explainable risk score."""
    db.execute(delete(AlertModel).where(AlertModel.investigation_id == investigation_id))
    db.execute(delete(DeviceRiskAssessmentModel).where(DeviceRiskAssessmentModel.investigation_id == investigation_id))
    db.flush()

    events = db.scalars(
        select(NormalizedEventModel).where(NormalizedEventModel.investigation_id == investigation_id)
    ).all()
    entities = db.scalars(
        select(EvidenceEntityModel).where(EvidenceEntityModel.investigation_id == investigation_id)
    ).all()

    entity_by_path: dict[str, EvidenceEntityModel] = {}
    entity_by_label: dict[str, EvidenceEntityModel] = {}
    for ent in entities:
        entity_by_label[ent.label.lower()] = ent
        p = ent.properties.get("path") or ent.properties.get("executable_path")
        if p and isinstance(p, str):
            entity_by_path[p.lower()] = ent

    findings: list[AlertModel] = []

    def add_finding(
        rule_id: str,
        name: str,
        severity: str,
        description: str,
        detection_logic: str,
        matched_events: list[NormalizedEventModel],
        confidence: float,
        mitre: dict[str, str] | None,
        recommendations: list[str],
        affected_label: str | None = None,
        affected_path: str | None = None,
    ) -> None:
        if not matched_events:
            return
        for me in matched_events:
            me.suspicious = True
            if SEVERITY_WEIGHTS.get(severity, 0) > SEVERITY_WEIGHTS.get(me.severity, 0):
                me.severity = severity

        aff_ent: EvidenceEntityModel | None = None
        if affected_path and affected_path.lower() in entity_by_path:
            aff_ent = entity_by_path[affected_path.lower()]
        elif affected_label and affected_label.lower() in entity_by_label:
            aff_ent = entity_by_label[affected_label.lower()]
        if aff_ent:
            aff_ent.suspicious = True
            aff_ent.risk_score = max(aff_ent.risk_score or 0.0, SEVERITY_WEIGHTS.get(severity, 10.0) * 2.5)

        timestamps = [e.timestamp for e in matched_events if e.timestamp]
        f_ts = min(timestamps) if timestamps else None
        findings.append(
            AlertModel(
                id=new_uuid(),
                investigation_id=investigation_id,
                rule_id=rule_id,
                name=name,
                severity=severity,
                description=description,
                affected_entity_id=aff_ent.id if aff_ent else None,
                affected_entity_label=aff_ent.label if aff_ent else (affected_label or affected_path),
                detection_logic=detection_logic,
                supporting_event_ids=[e.event_id for e in matched_events],
                timestamp=f_ts,
                confidence=confidence,
                mitre=mitre,
                recommendations=recommendations,
                disclaimer=DISCLAIMER,
            )
        )

    # Rule 1: Suspicious process execution from user-writable directories (Downloads / Temp / AppData / Public)
    r1_events = [
        ev
        for ev in events
        if ev.event_type in ("process_created", "userassist_execution", "prefetch_execution")
        and ev.file_path
        and any(p in ev.file_path.lower() for p in ("\\downloads\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\"))
    ]
    if r1_events:
        first_p = r1_events[0].file_path
        add_finding(
            rule_id="TV-RULE-001",
            name="Process Execution from User-Writable Staging Directory",
            severity="high",
            description=f"Observed {len(r1_events)} execution event(s) launched from Downloads, Temp, or Public user folders (e.g. '{first_p}').",
            detection_logic="event_type IN ('process_created','userassist_execution','prefetch_execution') AND file_path CONTAINS ('\\Downloads\\','\\Temp\\','\\Users\\Public\\')",
            matched_events=r1_events,
            confidence=0.88,
            mitre={"technique_id": "T1204.002", "technique_name": "User Execution: Malicious File", "tactic": "Execution"},
            recommendations=[
                "Verify the SHA-256 hash and digital signature of the binary in the Artifact Explorer.",
                "Inspect Evidence Universe to check whether the binary originated from a browser download.",
            ],
            affected_path=first_p,
        )

    # Rule 2: Unusual / Encoded or Hidden PowerShell Execution
    r2_events = []
    for ev in events:
        if ev.artifact_source == "evtx" and (
            ev.event_type in ("powershell_script_block", "powershell_activity", "process_created")
        ):
            raw_str = str(ev.raw_metadata).lower()
            if "powershell" in raw_str and any(
                ind in raw_str
                for ind in ("-enc", "encodedcommand", "-w hidden", "windowstyle hidden", "downloadstring", "invoke-webrequest", "frombase64string", "-nop", "bypass")
            ):
                r2_events.append(ev)
    if r2_events:
        add_finding(
            rule_id="TV-RULE-002",
            name="Suspicious PowerShell Command or Script Block Activity",
            severity="high",
            description=f"Detected {len(r2_events)} PowerShell event(s) using encoded commands, hidden windows, execution policy bypass, or web download cradles.",
            detection_logic="channel='PowerShell' OR process_name='powershell.exe' WITH ('-enc'|'-w hidden'|'DownloadString'|'FromBase64String'|'Bypass')",
            matched_events=r2_events,
            confidence=0.92,
            mitre={"technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
            recommendations=[
                "Decode any Base64 payload in the EVTX Explorer XML view.",
                "Trace parent and child processes of powershell.exe in the Evidence Universe process tree.",
            ],
            affected_label="powershell.exe",
        )

    # Rule 3: Persistence through Registry Run / RunOnce Keys pointing to non-standard locations or scripts
    r3_events = [
        ev
        for ev in events
        if ev.event_type == "registry_persistence"
        and (
            ev.suspicious
            or (
                ev.file_path
                and any(
                    loc in ev.file_path.lower()
                    for loc in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\", "powershell", "cmd.exe", "wscript", "mshta")
                )
            )
        )
    ]
    if r3_events:
        add_finding(
            rule_id="TV-RULE-003",
            name="Suspicious Registry Run / RunOnce Persistence Entry",
            severity="high",
            description=f"Identified {len(r3_events)} Registry Run/RunOnce persistence value(s) referencing user-writable paths or script interpreters.",
            detection_logic="artifact_source='registry' AND category IN ('run','runonce') AND value_data CONTAINS ('\\AppData\\'|'\\Temp\\'|'\\Downloads\\'|'powershell'|'cmd.exe')",
            matched_events=r3_events,
            confidence=0.90,
            mitre={"technique_id": "T1547.001", "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactic": "Persistence"},
            recommendations=[
                "Inspect the registry key last-write timestamp and compare against process creation events in Temporal Reconstruction Studio.",
                "Verify whether the referenced executable is legitimate vendor software.",
            ],
            affected_path=r3_events[0].file_path,
        )

    # Rule 4: Suspicious Scheduled Task Creation (Event ID 4698)
    r4_events = [ev for ev in events if ev.event_type == "scheduled_task_created"]
    if r4_events:
        add_finding(
            rule_id="TV-RULE-004",
            name="Scheduled Task Registration Observed",
            severity="medium",
            description=f"Detected {len(r4_events)} scheduled task creation event(s) (Event ID 4698).",
            detection_logic="artifact_source='evtx' AND event_id=4698",
            matched_events=r4_events,
            confidence=0.85,
            mitre={"technique_id": "T1053.005", "technique_name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence"},
            recommendations=[
                "Inspect the TaskName and Command payload in EVTX Explorer.",
                "Confirm whether the user account that registered the task was authorized.",
            ],
            affected_label=r4_events[0].user_identifier or "Scheduled Task",
        )

    # Rule 5: Suspicious Service Installation (Event ID 7045 / 4697)
    r5_events = [ev for ev in events if ev.event_type == "service_installed"]
    if r5_events:
        sev = "high" if any(
            ev.file_path and any(x in ev.file_path.lower() for x in ("\\temp\\", "\\appdata\\", "\\downloads\\", "cmd.exe", "powershell"))
            for ev in r5_events
        ) else "medium"
        add_finding(
            rule_id="TV-RULE-005",
            name="New Windows Service Installation",
            severity=sev,
            description=f"Observed {len(r5_events)} Windows service installation event(s) (Event ID 7045 / 4697).",
            detection_logic="artifact_source='evtx' AND event_id IN (7045, 4697)",
            matched_events=r5_events,
            confidence=0.90,
            mitre={"technique_id": "T1543.003", "technique_name": "Create or Modify System Process: Windows Service", "tactic": "Persistence"},
            recommendations=[
                "Review the ServiceFileName binary path and service account context.",
                "Correlate the service installation timestamp against file creation and user logon events.",
            ],
            affected_path=r5_events[0].file_path,
        )

    # Rule 6: Security Audit Log Cleared (Event ID 1102)
    r6_events = [ev for ev in events if ev.event_type == "audit_log_cleared"]
    if r6_events:
        add_finding(
            rule_id="TV-RULE-006",
            name="Windows Security Audit Log Cleared (Event ID 1102)",
            severity="critical",
            description=f"The Windows Security event log was explicitly cleared ({len(r6_events)} occurrence(s)), potentially destroying prior audit trail evidence.",
            detection_logic="artifact_source='evtx' AND channel='Security' AND event_id=1102",
            matched_events=r6_events,
            confidence=0.99,
            mitre={"technique_id": "T1070.001", "technique_name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion"},
            recommendations=[
                "Identify the SubjectUserName that cleared the log and inspect immediately preceding process and logon activity.",
                "Rely on surviving artifacts (Prefetch, Amcache, Registry last-write times, USN/Recycle Bin) for pre-clear reconstruction.",
            ],
            affected_label=r6_events[0].user_identifier or "Security Log",
        )

    # Rule 7: Failed Authentication Burst (Event ID 4625 >= 3 failures)
    r7_events = [ev for ev in events if ev.event_type == "logon_failure"]
    if len(r7_events) >= 3:
        add_finding(
            rule_id="TV-RULE-007",
            name="Repeated Failed Logon Attempts (Event ID 4625)",
            severity="medium",
            description=f"Observed {len(r7_events)} failed authentication attempt(s) on the endpoint.",
            detection_logic="COUNT(event_type='logon_failure' [EventID 4625]) >= 3",
            matched_events=r7_events,
            confidence=0.85,
            mitre={"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
            recommendations=[
                "Check whether a successful logon (4624) followed the failed attempts from the same source IP or user.",
                "Inspect LogonType and FailureReason codes in the EVTX Explorer.",
            ],
            affected_label=r7_events[0].user_identifier,
        )

    # Rule 8: Privileged Account or Group Membership Changes (4720, 4728, 4732)
    r8_events = [ev for ev in events if ev.event_type in ("user_created", "group_member_added")]
    if r8_events:
        add_finding(
            rule_id="TV-RULE-008",
            name="Local User Account Creation or Security Group Modification",
            severity="high",
            description=f"Observed {len(r8_events)} account creation or security group membership change event(s) (Event ID 4720 / 4728 / 4732).",
            detection_logic="artifact_source='evtx' AND event_id IN (4720, 4728, 4732)",
            matched_events=r8_events,
            confidence=0.93,
            mitre={"technique_id": "T1136.001", "technique_name": "Create Account: Local Account", "tactic": "Persistence"},
            recommendations=[
                "Verify whether the account creation or group elevation was part of an authorized administrative ticket.",
                "Check subsequent logons by the newly created or elevated account.",
            ],
            affected_label=r8_events[0].user_identifier,
        )

    # Rule 9: Executable or Script Downloaded via Browser
    r9_events = [
        ev
        for ev in events
        if ev.event_type == "browser_download"
        and ev.file_path
        and ev.file_path.lower().endswith((".exe", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".scr", ".dll"))
    ]
    if r9_events:
        add_finding(
            rule_id="TV-RULE-009",
            name="Executable or Script Downloaded via Web Browser",
            severity="medium",
            description=f"Browser download history recorded {len(r9_events)} executable/script file download(s) (e.g. '{r9_events[0].file_path}').",
            detection_logic="event_type='browser_download' AND target_path ENDSWITH ('.exe','.msi','.ps1','.bat','.vbs','.hta','.scr')",
            matched_events=r9_events,
            confidence=0.88,
            mitre={"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control"},
            recommendations=[
                "Inspect the source URL and referrer chain in the Browser Artifact Explorer.",
                "Check Evidence Universe to determine if the downloaded binary was executed.",
            ],
            affected_path=r9_events[0].file_path,
        )

    # Rule 10: Suspicious File Deletion / Recycle Bin Artifacts of Executables or Archives
    r10_events = [
        ev
        for ev in events
        if ev.event_type in ("recycle_bin_entry", "file_deleted")
        and ev.file_path
        and ev.file_path.lower().endswith((".exe", ".ps1", ".bat", ".vbs", ".zip", ".7z", ".rar", ".dll", ".docm", ".xlsm"))
    ]
    if r10_events:
        add_finding(
            rule_id="TV-RULE-010",
            name="Executable, Script, or Archive Moved to Recycle Bin",
            severity="low",
            description=f"Recycle Bin ($I) metadata contains {len(r10_events)} deleted executable, script, macro document, or archive item(s).",
            detection_logic="event_type IN ('recycle_bin_entry','file_deleted') AND original_path ENDSWITH ('.exe','.ps1','.bat','.zip','.7z','.docm')",
            matched_events=r10_events,
            confidence=0.80,
            mitre={"technique_id": "T1070.004", "technique_name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion"},
            recommendations=[
                "Compare the deletion timestamp ($I header) with execution timestamps in Temporal Reconstruction Studio.",
                "Check if the corresponding $R payload file remains in C:\\$Recycle.Bin for hash verification.",
            ],
            affected_path=r10_events[0].file_path,
        )

    if findings:
        db.add_all(findings)
        db.flush()

    # Calculate explainable endpoint risk score (0..100)
    factors: list[dict[str, Any]] = []
    raw_score = 0.0
    for f in findings:
        weight = SEVERITY_WEIGHTS.get(f.severity, 5.0)
        contrib = round(weight * f.confidence, 1)
        raw_score += contrib
        factors.append(
            {
                "finding_id": f.id,
                "name": f.name,
                "contribution": contrib,
                "explanation": f"{f.severity.upper()} severity finding ({f.rule_id}) with {int(f.confidence * 100)}% confidence supported by {len(f.supporting_event_ids)} event(s).",
            }
        )

    final_score = round(min(100.0, raw_score), 1)
    if final_score >= 75:
        level = "critical"
    elif final_score >= 50:
        level = "high"
    elif final_score >= 25:
        level = "medium"
    elif final_score > 0:
        level = "low"
    else:
        level = "minimal"

    explanation = (
        f"Composite risk score {final_score}/100 ({level}) derived deterministically from {len(findings)} rule-based forensic finding(s). "
        "Scores reflect observed indicator severity and evidence confidence; they do not automatically declare compromise."
        if findings
        else "No rule-based suspicious findings triggered across the collected forensic artifacts (score 0/100)."
    )

    risk_row = DeviceRiskAssessmentModel(
        id=new_uuid(),
        investigation_id=investigation_id,
        endpoint_id=endpoint_id,
        score=final_score,
        level=level,
        factors=factors,
        explanation=explanation,
        calculated_at=utc_now_str(),
    )
    db.add(risk_row)
    db.commit()

    return {"findings_count": len(findings), "risk_score": final_score, "risk_level": level}
