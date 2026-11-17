"""Forensic Investigation Report Generator (PDF via ReportLab & Machine-Readable JSON) (Spec §15).

Includes all 13 mandatory forensic report sections and computes SHA-256 of generated report files.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AlertModel,
    ChainOfCustodyModel,
    CollectedArtifactModel,
    DeviceRiskAssessmentModel,
    EndpointModel,
    EvidenceEntityModel,
    EvidenceRelationshipModel,
    IncidentCaseModel,
    InvestigationModel,
    InvestigationNoteModel,
    ReportModel,
    ScanJobModel,
    TimelineEventModel,
    new_uuid,
    utc_now_str,
)
from .graph import serialize_entity, serialize_relationship, serialize_timeline_event
from .storage import get_evidence_root


def build_report_payload(db: Session, inv: InvestigationModel, incident_id: str | None = None) -> dict[str, Any]:
    endpoint = db.get(EndpointModel, inv.endpoint_id)
    scans = db.scalars(select(ScanJobModel).where(ScanJobModel.investigation_id == inv.id)).all()
    artifacts = db.scalars(select(CollectedArtifactModel).where(CollectedArtifactModel.investigation_id == inv.id)).all()
    findings = db.scalars(select(AlertModel).where(AlertModel.investigation_id == inv.id)).all()
    risk = db.scalar(select(DeviceRiskAssessmentModel).where(DeviceRiskAssessmentModel.investigation_id == inv.id))
    entities = db.scalars(select(EvidenceEntityModel).where(EvidenceEntityModel.investigation_id == inv.id)).all()
    relationships = db.scalars(
        select(EvidenceRelationshipModel).where(EvidenceRelationshipModel.investigation_id == inv.id)
    ).all()
    timeline = db.scalars(
        select(TimelineEventModel)
        .where(TimelineEventModel.investigation_id == inv.id)
        .order_by(TimelineEventModel.timestamp.asc())
    ).all()
    notes = db.scalars(select(InvestigationNoteModel).where(InvestigationNoteModel.investigation_id == inv.id)).all()
    incidents = db.scalars(select(IncidentCaseModel).where(IncidentCaseModel.investigation_id == inv.id)).all()
    custody = db.scalars(select(ChainOfCustodyModel).where(ChainOfCustodyModel.investigation_id == inv.id)).all()

    entity_label_by_id = {e.id: e.label for e in entities}
    limitations: list[str] = []
    for s in scans:
        for lim in s.limitations or []:
            if lim not in limitations:
                limitations.append(lim)
    for a in artifacts:
        if a.error and a.error not in limitations:
            limitations.append(f"{a.artifact_key}: {a.error}")

    selected_incident = next((ic for ic in incidents if ic.id == incident_id), incidents[0] if incidents else None)

    return {
        "report_generated_at": utc_now_str(),
        "1_executive_summary": {
            "investigation_id": inv.id,
            "title": inv.title,
            "status": inv.status,
            "is_demo": inv.is_demo,
            "endpoint_hostname": endpoint.hostname if endpoint else "Unknown",
            "total_artifacts": len(artifacts),
            "total_timeline_events": len(timeline),
            "total_entities": len(entities),
            "total_relationships": len(relationships),
            "total_findings": len(findings),
            "risk_score": risk.score if risk else 0.0,
            "risk_level": risk.level if risk else "minimal",
            "risk_explanation": risk.explanation if risk else "",
        },
        "2_investigation_scope": {
            "description": inv.description,
            "created_by": inv.created_by,
            "created_at": inv.created_at,
            "scans_executed": len(scans),
            "reproducibility_versions": inv.reproducibility_versions or {},
        },
        "3_endpoint_information": {
            "id": endpoint.id if endpoint else None,
            "hostname": endpoint.hostname if endpoint else None,
            "machine_id": endpoint.machine_id if endpoint else None,
            "os_name": endpoint.os_name if endpoint else None,
            "os_version": endpoint.os_version if endpoint else None,
            "os_build": endpoint.os_build if endpoint else None,
            "architecture": endpoint.architecture if endpoint else None,
            "collection_user": endpoint.collection_user if endpoint else None,
            "is_elevated": endpoint.is_elevated if endpoint else False,
        },
        "4_acquisition_methodology": {
            "methods": sorted({a.acquisition_method for a in artifacts if a.acquisition_method}),
            "side_effects": sorted({se for s in scans for se in (s.side_effects or [])}),
        },
        "5_artifact_inventory": [
            {
                "artifact_key": a.artifact_key,
                "source": a.source,
                "name": a.name,
                "original_path": a.original_path,
                "status": a.status,
                "record_count": a.record_count,
                "parser": a.parser,
                "collected_at": a.collected_at,
            }
            for a in artifacts
        ],
        "6_evidence_integrity": {
            "verified_count": sum(1 for a in artifacts if a.verification_status == "verified"),
            "mismatched_count": sum(1 for a in artifacts if a.verification_status == "mismatch"),
            "unverified_count": sum(1 for a in artifacts if a.verification_status == "unverified"),
            "artifacts": [
                {
                    "artifact_key": a.artifact_key,
                    "sha256": a.sha256,
                    "records_sha256": a.records_sha256,
                    "verification_status": a.verification_status,
                    "storage_ref": a.storage_ref,
                }
                for a in artifacts
            ],
            "chain_of_custody_events": len(custody),
        },
        "7_suspicious_findings": [
            {
                "rule_id": f.rule_id,
                "name": f.name,
                "severity": f.severity,
                "confidence": f.confidence,
                "affected_entity": f.affected_entity_label,
                "description": f.description,
                "detection_logic": f.detection_logic,
                "supporting_event_ids": f.supporting_event_ids,
                "mitre": f.mitre,
                "disclaimer": f.disclaimer,
            }
            for f in findings
        ],
        "8_evidence_relationship_graph": {
            "entity_count": len(entities),
            "relationship_count": len(relationships),
            "entities": [serialize_entity(e) for e in entities[:200]],
            "relationships": [
                {
                    **serialize_relationship(r),
                    "source_label": entity_label_by_id.get(r.source_id, r.source_id),
                    "target_label": entity_label_by_id.get(r.target_id, r.target_id),
                }
                for r in relationships[:200]
            ],
        },
        "9_chronological_reconstruction": [
            serialize_timeline_event(t) for t in timeline[:250]
        ],
        "10_mitre_attack_mapping": [
            {
                "finding": f.name,
                "technique_id": f.mitre.get("technique_id"),
                "technique_name": f.mitre.get("technique_name"),
                "tactic": f.mitre.get("tactic"),
                "confidence": f.confidence,
            }
            for f in findings
            if f.mitre
        ],
        "11_analyst_notes": [
            {"author": n.author, "created_at": n.created_at, "body": n.body}
            for n in notes
        ],
        "12_conclusion": {
            "incident_title": selected_incident.title if selected_incident else "General Endpoint Forensic Reconstruction",
            "incident_status": selected_incident.status if selected_incident else inv.status,
            "hypothesis": selected_incident.hypothesis if selected_incident else None,
            "conclusion": (
                selected_incident.conclusion
                if (selected_incident and selected_incident.conclusion)
                else "All conclusions are bounded by the collected forensic artifacts and correlation provenance listed in this report."
            ),
        },
        "13_limitations": limitations or ["None recorded."],
    }


def _render_pdf_file(payload: dict[str, Any], out_path: Path) -> None:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TVTitle",
        parent=styles["Heading1"],
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#101318"),
        spaceAfter=8,
    )
    h2_style = ParagraphStyle(
        "TVH2",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#1A2029"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "TVBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
    )

    story: list[Any] = []
    exec_sum = payload["1_executive_summary"]
    ep = payload["3_endpoint_information"]

    story.append(Paragraph(f"TraceVault Forensic Investigation Report — {exec_sum['title']}", title_style))
    if exec_sum.get("is_demo"):
        story.append(Paragraph("<b>DEMONSTRATION DATASET:</b> Synthetic forensic dataset for analytical validation.", body_style))
    story.append(Paragraph(f"Generated (UTC): {payload['report_generated_at']} | Investigation ID: {exec_sum['investigation_id']}", body_style))
    story.append(Spacer(1, 4 * mm))

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    story.append(
        Paragraph(
            f"Endpoint <b>{exec_sum['endpoint_hostname']}</b> was examined. "
            f"Artifacts collected: {exec_sum['total_artifacts']} | Timeline events: {exec_sum['total_timeline_events']} | "
            f"Evidence entities: {exec_sum['total_entities']} | Correlated relationships: {exec_sum['total_relationships']} | "
            f"Suspicious findings: {exec_sum['total_findings']} | Risk Assessment: {exec_sum['risk_score']}/100 ({exec_sum['risk_level']}).",
            body_style,
        )
    )
    if exec_sum.get("risk_explanation"):
        story.append(Paragraph(exec_sum["risk_explanation"], body_style))

    # 2. Investigation Scope
    scope = payload["2_investigation_scope"]
    story.append(Paragraph("2. Investigation Scope & Reproducibility", h2_style))
    story.append(Paragraph(f"Lead Analyst: {scope['created_by']} | Opened: {scope['created_at']} | Description: {scope.get('description') or 'N/A'}", body_style))
    story.append(Paragraph(f"Reproducibility Versions: {json.dumps(scope.get('reproducibility_versions') or {})}", body_style))

    # 3. Endpoint Information
    story.append(Paragraph("3. Endpoint Identification", h2_style))
    story.append(
        Paragraph(
            f"Hostname: {ep.get('hostname')} | Machine GUID: {ep.get('machine_id')} | "
            f"OS: {ep.get('os_name')} ({ep.get('os_version')} Build {ep.get('os_build')}, {ep.get('architecture')}) | "
            f"Collection User: {ep.get('collection_user')} | Elevated: {ep.get('is_elevated')}",
            body_style,
        )
    )

    # 4. Acquisition Methodology
    meth = payload["4_acquisition_methodology"]
    story.append(Paragraph("4. Acquisition Methodology", h2_style))
    story.append(Paragraph("Methods: " + (", ".join(meth["methods"]) or "N/A"), body_style))
    for se in meth["side_effects"]:
        story.append(Paragraph(f"• {se}", body_style))

    # 5 & 6. Artifact Inventory & Integrity
    story.append(Paragraph("5 & 6. Artifact Inventory and SHA-256 Evidence Integrity", h2_style))
    integ = payload["6_evidence_integrity"]
    story.append(
        Paragraph(
            f"Verified Artifacts: {integ['verified_count']} | Mismatched: {integ['mismatched_count']} | "
            f"Unverified (status-only): {integ['unverified_count']} | Chain-of-Custody Entries: {integ['chain_of_custody_events']}",
            body_style,
        )
    )
    inv_table_data = [["Artifact Key", "Status", "Records", "Verification", "SHA-256 (Prefix)"]]
    integ_by_key = {a["artifact_key"]: a for a in integ["artifacts"]}
    for a in payload["5_artifact_inventory"]:
        ia = integ_by_key.get(a["artifact_key"], {})
        sha_val = ia.get("sha256") or ia.get("records_sha256") or "-"
        inv_table_data.append(
            [
                a["artifact_key"][:28],
                a["status"],
                str(a["record_count"]),
                ia.get("verification_status", "-"),
                sha_val[:20] + ("..." if len(sha_val) > 20 else ""),
            ]
        )
    t_inv = Table(inv_table_data, colWidths=[48 * mm, 28 * mm, 20 * mm, 26 * mm, 50 * mm])
    t_inv.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202733")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    story.append(t_inv)

    # 7. Suspicious Findings
    story.append(Paragraph("7. Rule-Based Forensic Findings", h2_style))
    findings = payload["7_suspicious_findings"]
    if not findings:
        story.append(Paragraph("No rule-based suspicious findings triggered.", body_style))
    for f in findings:
        story.append(
            Paragraph(
                f"<b>[{f['severity'].upper()}] {f['rule_id']} — {f['name']}</b> (Confidence: {int(f['confidence']*100)}%, Entity: {f.get('affected_entity') or 'N/A'})<br/>"
                f"{f['description']}<br/><i>Logic:</i> {f['detection_logic']}",
                body_style,
            )
        )
        story.append(Spacer(1, 1.5 * mm))

    # 8. Evidence Relationship Graph
    story.append(Paragraph("8. Evidence Relationship Graph Summary", h2_style))
    rels = payload["8_evidence_relationship_graph"]["relationships"][:25]
    if rels:
        rel_rows = [["Source", "Relationship", "Target", "Class / Conf", "Method"]]
        for r in rels:
            rel_rows.append(
                [
                    str(r.get("source_label", ""))[:26],
                    r["type"],
                    str(r.get("target_label", ""))[:26],
                    f"{r['evidence_class']} ({int(r['confidence']*100)}%)",
                    r["correlation_method"][:34],
                ]
            )
        t_rel = Table(rel_rows, colWidths=[38 * mm, 30 * mm, 38 * mm, 26 * mm, 40 * mm])
        t_rel.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202733")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ]
            )
        )
        story.append(t_rel)
    else:
        story.append(Paragraph("No correlated relationships recorded.", body_style))

    # 9. Chronological Reconstruction
    story.append(Paragraph("9. Chronological Reconstruction (Key Events)", h2_style))
    tl = payload["9_chronological_reconstruction"][:30]
    for ev in tl:
        flag = "[SUSPICIOUS] " if ev.get("suspicious") else ""
        story.append(
            Paragraph(
                f"<font size=7.5>{ev.get('timestamp') or 'no-timestamp'} | {ev['artifact_source'].upper()} | {flag}{ev['summary'][:130]}</font>",
                body_style,
            )
        )

    # 10. MITRE ATT&CK Mapping
    story.append(Paragraph("10. MITRE ATT&CK Mapping", h2_style))
    mitre_list = payload["10_mitre_attack_mapping"]
    if not mitre_list:
        story.append(Paragraph("No MITRE ATT&CK techniques mapped.", body_style))
    for m in mitre_list:
        story.append(
            Paragraph(
                f"• <b>{m['technique_id']}</b> ({m['technique_name']} — {m['tactic']}): {m['finding']}",
                body_style,
            )
        )

    # 11. Analyst Notes
    story.append(Paragraph("11. Analyst Notes", h2_style))
    notes = payload["11_analyst_notes"]
    if not notes:
        story.append(Paragraph("No analyst notes recorded.", body_style))
    for n in notes:
        story.append(Paragraph(f"• [{n['created_at']}] <b>{n['author']}</b>: {n['body']}", body_style))

    # 12. Conclusion
    conc = payload["12_conclusion"]
    story.append(Paragraph("12. Investigation Conclusion", h2_style))
    story.append(
        Paragraph(
            f"<b>Case:</b> {conc['incident_title']} (Status: {conc['incident_status']})<br/>"
            f"<b>Hypothesis:</b> {conc.get('hypothesis') or 'N/A'}<br/>"
            f"<b>Conclusion:</b> {conc['conclusion']}",
            body_style,
        )
    )

    # 13. Limitations
    story.append(Paragraph("13. Collection & Analytical Limitations", h2_style))
    for lim in payload["13_limitations"]:
        story.append(Paragraph(f"• {lim}", body_style))

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )
    doc.build(story)


def generate_investigation_report(
    db: Session,
    inv: InvestigationModel,
    fmt: str,
    incident_id: str | None,
    actor: str,
) -> ReportModel:
    payload = build_report_payload(db, inv, incident_id)
    reports_dir = get_evidence_root() / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    rep_id = new_uuid()
    ext = "pdf" if fmt == "pdf" else "json"
    out_path = reports_dir / f"report_{inv.id[:8]}_{rep_id[:8]}.{ext}"

    if fmt == "pdf":
        _render_pdf_file(payload, out_path)
    else:
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    sha256_hex = hashlib.sha256(out_path.read_bytes()).hexdigest()
    rep = ReportModel(
        id=rep_id,
        investigation_id=inv.id,
        incident_id=incident_id,
        format=fmt,
        status="ready",
        sha256=sha256_hex,
        file_path=str(out_path),
        created_at=utc_now_str(),
    )
    db.add(rep)
    db.add(
        ChainOfCustodyModel(
            investigation_id=inv.id,
            artifact_id=None,
            action=f"report_generated_{fmt}",
            actor=actor,
            timestamp=utc_now_str(),
            sha256=sha256_hex,
            verification_status="verified",
            details={"report_id": rep_id, "format": fmt, "incident_id": incident_id},
        )
    )
    db.commit()
    return rep
