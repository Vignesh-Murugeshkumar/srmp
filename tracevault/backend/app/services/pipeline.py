"""End-to-end forensic processing pipeline runner (inline or Celery worker)."""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy.orm import Session

from .. import (
    CORRELATION_RULES_VERSION,
    DETECTION_RULES_VERSION,
    NORMALIZATION_SCHEMA_VERSION,
    __version__,
)
from ..db import SessionLocal
from ..models import (
    ChainOfCustodyModel,
    CollectedArtifactModel,
    InvestigationModel,
    ScanJobModel,
    utc_now_str,
)
from .correlation import build_entities_and_correlations
from .detection import run_detections_and_risk
from .normalization import normalize_investigation_records
from sqlalchemy import select


def execute_processing_pipeline(db: Session, scan_id: str) -> dict[str, Any]:
    """Run normalization, entity extraction, correlation, detection, and risk scoring for a scan."""
    scan = db.get(ScanJobModel, scan_id)
    if not scan:
        return {"error": "scan_not_found"}

    inv = db.get(InvestigationModel, scan.investigation_id)
    if not inv:
        return {"error": "investigation_not_found"}

    t0 = time.perf_counter()
    # Update processing pseudo-stage
    stages = [s for s in (scan.stages or []) if s.get("stage") != "processing"]
    stages.append(
        {
            "stage": "processing",
            "status": "running",
            "records": 0,
            "progress": 0.25,
            "duration_ms": 0,
            "errors": [],
            "message": "Normalizing artifacts, correlating entities, and evaluating detection rules",
        }
    )
    scan.stages = stages
    db.commit()

    # 1. Normalize records -> normalized_events (scope to the current scan's artifacts)
    norm_count = normalize_investigation_records(db, inv.id, scan.endpoint_id, scan_id=scan.id)

    # 2. Extract entities, build relationships, and populate timeline_events
    corr_stats = build_entities_and_correlations(db, inv.id)

    # 3. Evaluate detection rules and compute risk assessment
    det_stats = run_detections_and_risk(db, inv.id, scan.endpoint_id)

    # 4. Record reproducibility versions on the investigation
    artifacts = db.scalars(
        select(CollectedArtifactModel).where(CollectedArtifactModel.investigation_id == inv.id)
    ).all()
    collector_versions = sorted({a.collector_version for a in artifacts if a.collector_version})
    parsers_used = sorted({a.parser for a in artifacts if a.parser})

    inv.reproducibility_versions = {
        "backend_version": __version__,
        "collector_versions": collector_versions or ["0.1.0"],
        "artifact_parsers": parsers_used,
        "normalization_schema_version": NORMALIZATION_SCHEMA_VERSION,
        "correlation_rules_version": CORRELATION_RULES_VERSION,
        "detection_rules_version": DETECTION_RULES_VERSION,
        "processed_at": utc_now_str(),
    }
    inv.updated_at = utc_now_str()

    dur_ms = int((time.perf_counter() - t0) * 1000)
    stages = [s for s in (scan.stages or []) if s.get("stage") != "processing"]
    stages.append(
        {
            "stage": "processing",
            "status": "completed",
            "records": norm_count,
            "progress": 1.0,
            "duration_ms": dur_ms,
            "errors": [],
            "message": f"Normalized {norm_count} event(s), built {corr_stats['relationships']} relationship(s), evaluated {det_stats['findings_count']} finding(s)",
        }
    )
    scan.stages = stages

    # Preserve "partial" if collection had permission_denied limitations, otherwise "completed"
    if scan.status == "processing":
        has_limitations = bool(scan.limitations) or any(a.status in ("permission_denied", "error") for a in artifacts)
        scan.status = "partial" if has_limitations else "completed"
    scan.finished_at = utc_now_str()

    db.add(
        ChainOfCustodyModel(
            investigation_id=inv.id,
            artifact_id=None,
            action="forensic_processing_completed",
            actor="tracevault-processing-engine",
            timestamp=utc_now_str(),
            sha256=None,
            verification_status="verified",
            details={
                "scan_id": scan.id,
                "normalized_events": norm_count,
                **corr_stats,
                **det_stats,
                "reproducibility_versions": inv.reproducibility_versions,
            },
        )
    )
    db.commit()
    return {
        "scan_id": scan.id,
        "normalized_events": norm_count,
        **corr_stats,
        **det_stats,
    }


def run_processing_in_background(scan_id: str) -> None:
    db = SessionLocal()
    try:
        execute_processing_pipeline(db, scan_id)
    finally:
        db.close()
