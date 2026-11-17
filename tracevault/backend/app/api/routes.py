"""FastAPI REST & WebSocket routers implementing docs/CONTRACT.md (v1)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import (
    check_investigation_access,
    create_access_token,
    decode_access_token,
    generate_agent_token,
    get_authenticated_agent,
    get_current_user,
    hash_token,
    require_write_access,
    verify_password,
    write_audit_log,
)
from ..config import settings
from ..db import SessionLocal, get_db
from ..models import (
    AlertModel,
    ArtifactRecordModel,
    ChainOfCustodyModel,
    CollectedArtifactModel,
    DeviceRiskAssessmentModel,
    EndpointAgentModel,
    EndpointModel,
    EvidenceEntityModel,
    EvidenceRelationshipModel,
    IncidentCaseModel,
    InvestigationModel,
    InvestigationNoteModel,
    NormalizedEventModel,
    ReportModel,
    ScanJobModel,
    TimelineEventModel,
    UserModel,
    new_uuid,
    utc_now_str,
)
from ..services.demo import seed_demo_investigation
from ..services.graph import (
    query_evidence_graph,
    query_timeline,
    query_timeline_range,
    serialize_entity,
    serialize_relationship,
    serialize_timeline_event,
)
from ..services.ingestion import ingest_uploaded_artifact
from ..services.pipeline import execute_processing_pipeline, run_processing_in_background
from ..services.reporting import generate_investigation_report

api_router = APIRouter(prefix="/api")
ws_router = APIRouter()


# --- Helper serializers ---
def _compute_agent_status(last_seen: str | None) -> str:
    if not last_seen:
        return "offline"
    try:
        dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - dt).total_seconds()
        if age < 120:
            return "online"
        if age < 1800:
            return "stale"
        return "offline"
    except Exception:
        return "offline"


def _serialize_endpoint(ep: EndpointModel) -> dict[str, Any]:
    return {
        "id": ep.id,
        "hostname": ep.hostname,
        "machine_id": ep.machine_id,
        "os_name": ep.os_name,
        "os_version": ep.os_version,
        "os_build": ep.os_build,
        "architecture": ep.architecture,
        "agent_version": ep.agent_version,
        "collection_user": ep.collection_user,
        "is_elevated": bool(ep.is_elevated),
        "storage": ep.storage or [],
        "registered_at": ep.registered_at,
        "last_seen": ep.last_seen,
        "agent_status": _compute_agent_status(ep.last_seen),
    }


def _serialize_scan(s: ScanJobModel) -> dict[str, Any]:
    return {
        "id": s.id,
        "investigation_id": s.investigation_id,
        "endpoint_id": s.endpoint_id,
        "scan_type": s.scan_type,
        "status": s.status,
        "time_window_hours": s.time_window_hours,
        "sources": s.sources or [],
        "created_at": s.created_at,
        "started_at": s.started_at,
        "finished_at": s.finished_at,
        "cancel_requested": bool(s.cancel_requested),
        "limitations": s.limitations or [],
        "side_effects": s.side_effects or [],
    }


def _serialize_investigation(inv: InvestigationModel, db: Session) -> dict[str, Any]:
    ep = db.get(EndpointModel, inv.endpoint_id)
    return {
        "id": inv.id,
        "title": inv.title,
        "description": inv.description,
        "endpoint_id": inv.endpoint_id,
        "endpoint_hostname": ep.hostname if ep else "Unknown",
        "status": inv.status,
        "is_demo": bool(inv.is_demo),
        "created_by": inv.created_by,
        "created_at": inv.created_at,
        "updated_at": inv.updated_at,
    }


def _serialize_artifact(a: CollectedArtifactModel) -> dict[str, Any]:
    return {
        "id": a.id,
        "artifact_key": a.artifact_key,
        "source": a.source,
        "name": a.name,
        "original_path": a.original_path,
        "status": a.status,
        "acquisition_method": a.acquisition_method,
        "sha256": a.sha256,
        "records_sha256": a.records_sha256,
        "size_bytes": a.size_bytes,
        "last_modified": a.last_modified,
        "collected_at": a.collected_at,
        "collector_version": a.collector_version,
        "record_count": a.record_count,
        "parser": a.parser,
        "side_effects": a.side_effects or [],
        "error": a.error,
        "time_window": a.time_window,
        "verified": bool(a.verified),
        "verification_status": a.verification_status,
        "storage_ref": a.storage_ref,
    }


def _serialize_finding(f: AlertModel) -> dict[str, Any]:
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "name": f.name,
        "severity": f.severity,
        "description": f.description,
        "affected_entity_id": f.affected_entity_id,
        "affected_entity_label": f.affected_entity_label,
        "detection_logic": f.detection_logic,
        "supporting_event_ids": f.supporting_event_ids or [],
        "timestamp": f.timestamp,
        "confidence": f.confidence,
        "mitre": f.mitre,
        "recommendations": f.recommendations or [],
        "disclaimer": f.disclaimer,
    }


def _serialize_incident(ic: IncidentCaseModel) -> dict[str, Any]:
    return {
        "id": ic.id,
        "investigation_id": ic.investigation_id,
        "title": ic.title,
        "status": ic.status,
        "hypothesis": ic.hypothesis,
        "affected_user": ic.affected_user,
        "affected_process": ic.affected_process,
        "attached_entity_ids": ic.attached_entity_ids or [],
        "attached_event_ids": ic.attached_event_ids or [],
        "attached_finding_ids": ic.attached_finding_ids or [],
        "conclusion": ic.conclusion,
        "created_at": ic.created_at,
        "updated_at": ic.updated_at,
    }


# --- 1. Auth ---
class LoginRequest(BaseModel):
    username: str
    password: str


@api_router.post("/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.scalar(select(UserModel).where(UserModel.username == body.username))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    token = create_access_token(user)
    write_audit_log(db, user.username, "user_login", "user", user.id)
    db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at,
        },
    }


@api_router.get("/auth/me")
def me(user: UserModel = Depends(get_current_user)) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "created_at": user.created_at,
    }


# --- 2. Endpoint Registration & Management ---
class EndpointRegisterRequest(BaseModel):
    machine_id: str
    hostname: str
    os_name: str = "Windows"
    os_version: str = "10.0"
    os_build: str = "22631"
    architecture: str = "AMD64"
    collection_user: str = "SYSTEM"
    is_elevated: bool = False
    agent_version: str = "0.1.0"
    storage: list[dict[str, Any]] = Field(default_factory=list)
    collected_at: str | None = None


@api_router.post("/endpoints/register")
def register_endpoint(
    body: EndpointRegisterRequest,
    x_enrollment_key: str | None = Header(default=None, alias="X-Enrollment-Key"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if not x_enrollment_key or x_enrollment_key != settings.enrollment_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-Enrollment-Key")

    now = utc_now_str()
    ep = db.scalar(select(EndpointModel).where(EndpointModel.machine_id == body.machine_id))
    if not ep:
        ep = EndpointModel(
            id=new_uuid(),
            machine_id=body.machine_id,
            hostname=body.hostname,
            os_name=body.os_name,
            os_version=body.os_version,
            os_build=body.os_build,
            architecture=body.architecture,
            agent_version=body.agent_version,
            collection_user=body.collection_user,
            is_elevated=body.is_elevated,
            storage=body.storage,
            discovery=[],
            registered_at=now,
            last_seen=now,
        )
        db.add(ep)
        db.flush()
    else:
        ep.hostname = body.hostname
        ep.os_name = body.os_name
        ep.os_version = body.os_version
        ep.os_build = body.os_build
        ep.architecture = body.architecture
        ep.agent_version = body.agent_version
        ep.collection_user = body.collection_user
        ep.is_elevated = body.is_elevated
        ep.storage = body.storage
        ep.last_seen = now
        # Revoke prior active tokens for this endpoint upon rotation
        prior_agents = db.scalars(
            select(EndpointAgentModel).where(EndpointAgentModel.endpoint_id == ep.id, EndpointAgentModel.revoked == False)  # noqa: E712
        ).all()
        for pa in prior_agents:
            pa.revoked = True

    raw_token = generate_agent_token()
    agent = EndpointAgentModel(
        id=new_uuid(),
        endpoint_id=ep.id,
        token_hash=hash_token(raw_token),
        agent_version=body.agent_version,
        revoked=False,
        created_at=now,
        last_heartbeat_at=now,
    )
    db.add(agent)
    write_audit_log(db, f"agent:{ep.hostname}", "endpoint_registered", "endpoint", ep.id, {"agent_id": agent.id})
    db.commit()
    return {
        "endpoint_id": ep.id,
        "agent_id": agent.id,
        "agent_token": raw_token,
    }


@api_router.post("/endpoints/{endpoint_id}/revoke-agents")
def revoke_endpoint_agents(
    endpoint_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required to revoke agent tokens")
    agents = db.scalars(select(EndpointAgentModel).where(EndpointAgentModel.endpoint_id == endpoint_id)).all()
    for ag in agents:
        ag.revoked = True
    write_audit_log(db, user.username, "revoke_endpoint_agents", "endpoint", endpoint_id, {"revoked_count": len(agents)})
    db.commit()
    return {"revoked": len(agents)}


@api_router.get("/endpoints")
def list_endpoints(
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    _ = user
    eps = db.scalars(select(EndpointModel).order_by(EndpointModel.registered_at.desc())).all()
    return [_serialize_endpoint(ep) for ep in eps]


@api_router.get("/endpoints/{endpoint_id}")
def get_endpoint(
    endpoint_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _ = user
    ep = db.get(EndpointModel, endpoint_id)
    if not ep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    return _serialize_endpoint(ep)


@api_router.get("/endpoints/{endpoint_id}/status")
def get_endpoint_status(
    endpoint_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _ = user
    ep = db.get(EndpointModel, endpoint_id)
    if not ep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    last_scan = db.scalar(
        select(ScanJobModel).where(ScanJobModel.endpoint_id == ep.id).order_by(ScanJobModel.created_at.desc())
    )
    return {
        "endpoint_id": ep.id,
        "agent_status": _compute_agent_status(ep.last_seen),
        "last_seen": ep.last_seen,
        "last_scan": _serialize_scan(last_scan) if last_scan else None,
        "discovery": ep.discovery or [],
    }


# --- 3. Agent Pull Protocol ---
class HeartbeatRequest(BaseModel):
    discovery: list[dict[str, Any]] | None = None


@api_router.post("/agent/heartbeat")
def agent_heartbeat(
    body: HeartbeatRequest,
    agent_ep: tuple[EndpointAgentModel, EndpointModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    agent, ep = agent_ep
    now = utc_now_str()
    agent.last_heartbeat_at = now
    ep.last_seen = now
    if body.discovery is not None:
        ep.discovery = body.discovery
    db.commit()
    return {"ok": True}


@api_router.get("/agent/jobs/next")
def agent_next_job(
    agent_ep: tuple[EndpointAgentModel, EndpointModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db),
):
    _, ep = agent_ep
    ep.last_seen = utc_now_str()
    # Recover interrupted collecting jobs or claim next queued scan for this endpoint
    job = db.scalar(
        select(ScanJobModel)
        .where(
            ScanJobModel.endpoint_id == ep.id,
            ScanJobModel.status.in_(["queued", "collecting"]),
            ScanJobModel.cancel_requested == False,  # noqa: E712
        )
        .order_by(ScanJobModel.created_at.asc())
    )
    if not job:
        db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    job.status = "collecting"
    if not job.started_at:
        job.started_at = utc_now_str()
    db.commit()
    return {
        "scan_id": job.id,
        "investigation_id": job.investigation_id,
        "scan_type": job.scan_type,
        "time_window_hours": job.time_window_hours,
        "sources": job.sources or ["evtx", "registry", "prefetch", "amcache", "browser", "filesystem"],
        "options": {"max_records_per_source": 50000},
    }


class StageProgressBody(BaseModel):
    stage: str
    status: str
    records: int = 0
    progress: float = 0.0
    duration_ms: int | None = 0
    errors: list[str] = Field(default_factory=list)
    message: str | None = None


@api_router.post("/agent/scans/{scan_id}/progress")
def agent_scan_progress(
    scan_id: str,
    body: StageProgressBody,
    agent_ep: tuple[EndpointAgentModel, EndpointModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _, ep = agent_ep
    scan = db.get(ScanJobModel, scan_id)
    if not scan or scan.endpoint_id != ep.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found for endpoint")
    stages = list(scan.stages or [])
    updated = False
    stage_dict = body.model_dump()
    for idx, st in enumerate(stages):
        if st.get("stage") == body.stage:
            stages[idx] = stage_dict
            updated = True
            break
    if not updated:
        stages.append(stage_dict)
    scan.stages = stages
    db.commit()
    return {"cancel_requested": bool(scan.cancel_requested)}


@api_router.post("/agent/scans/{scan_id}/artifacts")
def agent_upload_artifact(
    scan_id: str,
    meta: UploadFile = File(...),
    records: UploadFile | None = File(default=None),
    original: UploadFile | None = File(default=None),
    agent_ep: tuple[EndpointAgentModel, EndpointModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    agent, ep = agent_ep
    scan = db.get(ScanJobModel, scan_id)
    if not scan or scan.endpoint_id != ep.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found for endpoint")

    try:
        meta_obj = json.loads(meta.file.read().decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid meta JSON: {exc}") from exc

    try:
        res = ingest_uploaded_artifact(
            db=db,
            scan=scan,
            meta=meta_obj,
            records_stream=records.file if records else None,
            original_stream=original.file if original else None,
            actor=f"agent:{ep.hostname}:{agent.id[:8]}",
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(ve)) from ve

    return res


class CompleteScanBody(BaseModel):
    status: str = "completed"
    limitations: list[str] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)


@api_router.post("/agent/scans/{scan_id}/complete")
def agent_complete_scan(
    scan_id: str,
    body: CompleteScanBody,
    background_tasks: BackgroundTasks,
    agent_ep: tuple[EndpointAgentModel, EndpointModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _, ep = agent_ep
    scan = db.get(ScanJobModel, scan_id)
    if not scan or scan.endpoint_id != ep.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found for endpoint")

    scan.limitations = body.limitations
    scan.side_effects = body.side_effects
    if scan.cancel_requested or body.status == "cancelled":
        scan.status = "cancelled"
        scan.finished_at = utc_now_str()
        db.commit()
        return {"ok": True}

    scan.status = "processing"
    db.commit()

    # Run synchronously inside the request when in inline mode so immediate caller / tests see completed results,
    # or dispatch to Celery when task_mode == "celery"
    if settings.task_mode == "celery":
        from ..worker import process_scan_task

        process_scan_task.delay(scan.id)
    else:
        execute_processing_pipeline(db, scan.id)
        _ = background_tasks

    return {"ok": True}


# --- 4. Scan Management (Analyst) ---
class StartScanRequest(BaseModel):
    investigation_id: str
    scan_type: str = "quick"
    time_window_hours: int | None = 72
    sources: list[str] | None = None


@api_router.post("/endpoints/{endpoint_id}/scans")
def create_scan(
    endpoint_id: str,
    body: StartScanRequest,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    inv = check_investigation_access(db, body.investigation_id, user, write=True)
    ep = db.get(EndpointModel, endpoint_id)
    if not ep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    srcs = body.sources or ["evtx", "registry", "prefetch", "amcache", "browser", "filesystem"]
    initial_stages = [
        {"stage": s, "status": "pending", "records": 0, "progress": 0.0, "duration_ms": 0, "errors": [], "message": "Queued for endpoint agent"}
        for s in srcs
    ]
    scan = ScanJobModel(
        id=new_uuid(),
        investigation_id=inv.id,
        endpoint_id=ep.id,
        scan_type=body.scan_type,
        status="queued",
        time_window_hours=body.time_window_hours if body.scan_type == "quick" else None,
        sources=srcs,
        stages=initial_stages,
        cancel_requested=False,
        limitations=[],
        side_effects=[],
        created_at=utc_now_str(),
    )
    db.add(scan)
    write_audit_log(db, user.username, "start_scan", "scan_job", scan.id, {"scan_type": scan.scan_type, "endpoint_id": ep.id})
    db.commit()
    return _serialize_scan(scan)


@api_router.get("/scans/{scan_id}")
def get_scan(
    scan_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = db.get(ScanJobModel, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    check_investigation_access(db, scan.investigation_id, user)
    return _serialize_scan(scan)


@api_router.get("/scans/{scan_id}/progress")
def get_scan_progress(
    scan_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = db.get(ScanJobModel, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    check_investigation_access(db, scan.investigation_id, user)
    stages = list(scan.stages or [])
    if not any(s.get("stage") == "processing" for s in stages):
        stages.append(
            {
                "stage": "processing",
                "status": "completed" if scan.status in ("completed", "partial") else ("running" if scan.status == "processing" else "pending"),
                "records": 0,
                "progress": 1.0 if scan.status in ("completed", "partial") else 0.0,
                "duration_ms": 0,
                "errors": [],
                "message": "Normalization, correlation & detection",
            }
        )
    return {"scan": _serialize_scan(scan), "stages": stages}


@api_router.post("/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = db.get(ScanJobModel, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    check_investigation_access(db, scan.investigation_id, user, write=True)
    scan.cancel_requested = True
    if scan.status == "queued":
        scan.status = "cancelled"
        scan.finished_at = utc_now_str()
    write_audit_log(db, user.username, "cancel_scan", "scan_job", scan.id)
    db.commit()
    return _serialize_scan(scan)


@api_router.get("/scans/{scan_id}/artifacts")
def get_scan_artifacts(
    scan_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    scan = db.get(ScanJobModel, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    check_investigation_access(db, scan.investigation_id, user)
    rows = db.scalars(select(CollectedArtifactModel).where(CollectedArtifactModel.scan_id == scan_id)).all()
    return [_serialize_artifact(a) for a in rows]


# --- 5. Investigations ---
class CreateInvestigationRequest(BaseModel):
    title: str
    description: str | None = None
    endpoint_id: str
    assigned_user_ids: list[str] = Field(default_factory=list)


@api_router.post("/investigations")
def create_investigation(
    body: CreateInvestigationRequest,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    require_write_access(user)
    ep = db.get(EndpointModel, body.endpoint_id)
    if not ep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    inv = InvestigationModel(
        id=new_uuid(),
        title=body.title,
        description=body.description,
        endpoint_id=ep.id,
        status="open",
        is_demo=False,
        created_by=user.username,
        assigned_user_ids=body.assigned_user_ids,
        created_at=utc_now_str(),
        updated_at=utc_now_str(),
    )
    db.add(inv)
    write_audit_log(db, user.username, "create_investigation", "investigation", inv.id)
    db.commit()
    return _serialize_investigation(inv, db)


@api_router.get("/investigations")
def list_investigations(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    all_invs = db.scalars(select(InvestigationModel).order_by(InvestigationModel.created_at.desc())).all()
    visible = [
        inv
        for inv in all_invs
        if user.role == "admin"
        or inv.is_demo
        or inv.created_by == user.username
        or user.id in (inv.assigned_user_ids or [])
    ]
    total = len(visible)
    start = (page - 1) * page_size
    sliced = visible[start : start + page_size]
    return {
        "items": [_serialize_investigation(i, db) for i in sliced],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@api_router.get("/investigations/{inv_id}")
def get_investigation(
    inv_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    inv = check_investigation_access(db, inv_id, user)
    return _serialize_investigation(inv, db)


@api_router.get("/investigations/{inv_id}/summary")
def get_investigation_summary(
    inv_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    inv = check_investigation_access(db, inv_id, user)
    artifacts = db.scalars(select(CollectedArtifactModel).where(CollectedArtifactModel.investigation_id == inv.id)).all()
    events_total = db.scalar(select(func.count()).select_from(NormalizedEventModel).where(NormalizedEventModel.investigation_id == inv.id)) or 0
    findings_count = db.scalar(select(func.count()).select_from(AlertModel).where(AlertModel.investigation_id == inv.id)) or 0
    rels = db.scalars(select(EvidenceRelationshipModel).where(EvidenceRelationshipModel.investigation_id == inv.id)).all()
    latest_scan = db.scalar(
        select(ScanJobModel).where(ScanJobModel.investigation_id == inv.id).order_by(ScanJobModel.created_at.desc())
    )

    corr_ev_ids: set[str] = set()
    high_conf_rels = 0
    for r in rels:
        corr_ev_ids.update(r.supporting_event_ids or [])
        if r.confidence >= 0.85:
            high_conf_rels += 1

    by_source: dict[str, dict[str, Any]] = {}
    for s in ("evtx", "registry", "prefetch", "amcache", "browser", "filesystem"):
        src_arts = [a for a in artifacts if a.source == s]
        recs = sum(a.record_count for a in src_arts)
        if not src_arts:
            st = "not_collected"
        elif any(a.status == "collected" for a in src_arts):
            st = "collected"
        elif any(a.status == "permission_denied" for a in src_arts):
            st = "permission_denied"
        else:
            st = src_arts[0].status
        by_source[s] = {"source": s, "status": st, "records": recs}

    return {
        "evidence_collected": sum(1 for a in artifacts if a.status == "collected"),
        "records_total": sum(a.record_count for a in artifacts),
        "events_total": events_total,
        "suspicious_findings": findings_count,
        "correlated_events": len(corr_ev_ids),
        "high_confidence_relationships": high_conf_rels,
        "integrity": {
            "verified": sum(1 for a in artifacts if a.verification_status == "verified"),
            "mismatched": sum(1 for a in artifacts if a.verification_status == "mismatch"),
            "unverified": sum(1 for a in artifacts if a.verification_status == "unverified"),
        },
        "sources": list(by_source.values()),
        "latest_scan": _serialize_scan(latest_scan) if latest_scan else None,
    }


# --- 6. Evidence, Graph & Timeline ---
@api_router.get("/investigations/{inv_id}/evidence")
def list_evidence_entities(
    inv_id: str,
    type: str | None = Query(default=None),
    q: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user)
    rows = db.scalars(select(EvidenceEntityModel).where(EvidenceEntityModel.investigation_id == inv_id)).all()
    filtered = []
    for r in rows:
        if type and r.type != type:
            continue
        if q and q.lower() not in r.label.lower() and q.lower() not in r.key.lower():
            continue
        filtered.append(r)
    total = len(filtered)
    start = (page - 1) * page_size
    return {
        "items": [serialize_entity(e) for e in filtered[start : start + page_size]],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@api_router.get("/investigations/{inv_id}/evidence/{evidence_id}")
def get_evidence_detail(
    inv_id: str,
    evidence_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user)
    ent = db.get(EvidenceEntityModel, evidence_id)
    if not ent or ent.investigation_id != inv_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence entity not found")

    rels = db.scalars(
        select(EvidenceRelationshipModel).where(
            EvidenceRelationshipModel.investigation_id == inv_id,
            (EvidenceRelationshipModel.source_id == evidence_id) | (EvidenceRelationshipModel.target_id == evidence_id),
        )
    ).all()
    all_tl = db.scalars(
        select(TimelineEventModel).where(TimelineEventModel.investigation_id == inv_id).order_by(TimelineEventModel.timestamp.asc())
    ).all()
    related_tl = [t for t in all_tl if evidence_id in (t.entity_ids or [])]
    findings = db.scalars(
        select(AlertModel).where(AlertModel.investigation_id == inv_id, AlertModel.affected_entity_id == evidence_id)
    ).all()

    return {
        "entity": serialize_entity(ent),
        "relationships": [serialize_relationship(r) for r in rels],
        "events": [serialize_timeline_event(t) for t in related_tl[:200]],
        "findings": [_serialize_finding(f) for f in findings],
    }


@api_router.get("/investigations/{inv_id}/evidence-graph")
def get_evidence_graph(
    inv_id: str,
    at: str | None = Query(default=None),
    sources: str | None = Query(default=None),
    relationship_types: str | None = Query(default=None),
    evidence_classes: str | None = Query(default=None),
    focus: str | None = Query(default=None),
    depth: int = Query(default=2, ge=1, le=5),
    suspicious_only: bool = Query(default=False),
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user)
    src_list = [s.strip() for s in sources.split(",") if s.strip()] if sources else None
    rel_list = [r.strip() for r in relationship_types.split(",") if r.strip()] if relationship_types else None
    cls_list = [c.strip() for c in evidence_classes.split(",") if c.strip()] if evidence_classes else None
    return query_evidence_graph(
        db=db,
        investigation_id=inv_id,
        at=at,
        sources=src_list,
        relationship_types=rel_list,
        evidence_classes=cls_list,
        focus=focus,
        depth=depth,
        suspicious_only=suspicious_only,
    )


@api_router.get("/investigations/{inv_id}/relationships")
def list_relationships(
    inv_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=200, ge=1, le=1000),
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user)
    rows = db.scalars(
        select(EvidenceRelationshipModel).where(EvidenceRelationshipModel.investigation_id == inv_id)
    ).all()
    total = len(rows)
    start = (page - 1) * page_size
    return {
        "items": [serialize_relationship(r) for r in rows[start : start + page_size]],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@api_router.get("/investigations/{inv_id}/timeline")
def get_timeline(
    inv_id: str,
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    groups: str | None = Query(default=None),
    sources: str | None = Query(default=None),
    suspicious_only: bool = Query(default=False),
    limit: int = Query(default=5000, ge=1, le=10000),
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user)
    grp_list = [g.strip() for g in groups.split(",") if g.strip()] if groups else None
    src_list = [s.strip() for s in sources.split(",") if s.strip()] if sources else None
    return query_timeline(
        db=db,
        investigation_id=inv_id,
        start=start,
        end=end,
        groups=grp_list,
        sources=src_list,
        suspicious_only=suspicious_only,
        limit=limit,
    )


@api_router.get("/investigations/{inv_id}/timeline/range")
def get_timeline_range(
    inv_id: str,
    buckets: int = Query(default=200, ge=10, le=500),
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user)
    return query_timeline_range(db, inv_id, buckets=buckets)


# --- 7. Artifact Explorers ---
@api_router.get("/investigations/{inv_id}/artifacts/{source_kind}")
def get_artifact_records(
    inv_id: str,
    source_kind: str,
    q: str | None = Query(default=None),
    event_id: int | None = Query(default=None),
    channel: str | None = Query(default=None),
    category: str | None = Query(default=None),
    kind: str | None = Query(default=None),
    browser: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user)
    if source_kind not in ("evtx", "registry", "prefetch", "amcache", "browser", "filesystem"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unsupported artifact source")

    rows = db.scalars(
        select(ArtifactRecordModel).where(
            ArtifactRecordModel.investigation_id == inv_id,
            ArtifactRecordModel.source == source_kind,
        )
    ).all()

    filtered: list[ArtifactRecordModel] = []
    q_low = q.lower() if q else None
    for r in rows:
        d = r.data or {}
        if event_id is not None and d.get("event_id") != event_id:
            continue
        if channel and str(d.get("channel") or "").lower() != channel.lower():
            continue
        if category and str(d.get("category") or "").lower() != category.lower():
            continue
        if kind and str(d.get("kind") or "").lower() != kind.lower():
            continue
        if browser and str(d.get("browser") or "").lower() != browser.lower():
            continue
        if q_low and q_low not in json.dumps(d).lower() and q_low not in r.record_id.lower():
            continue
        filtered.append(r)

    total = len(filtered)
    start_idx = (page - 1) * page_size
    sliced = filtered[start_idx : start_idx + page_size]

    return {
        "items": [
            {
                "id": r.id,
                "artifact_id": r.artifact_id,
                "artifact_key": r.artifact_key,
                "record_id": r.record_id,
                "original_path": r.original_path,
                "sha256": r.sha256,
                "data": r.data,
                "related_event_ids": r.related_event_ids or [],
            }
            for r in sliced
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


# --- 8. Threat Findings & Risk ---
@api_router.get("/investigations/{inv_id}/findings")
def get_findings(
    inv_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    check_investigation_access(db, inv_id, user)
    rows = db.scalars(select(AlertModel).where(AlertModel.investigation_id == inv_id)).all()
    return [_serialize_finding(f) for f in rows]


@api_router.get("/investigations/{inv_id}/risk")
def get_risk(
    inv_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user)
    risk = db.scalar(select(DeviceRiskAssessmentModel).where(DeviceRiskAssessmentModel.investigation_id == inv_id))
    if not risk:
        return {
            "score": 0.0,
            "level": "minimal",
            "factors": [],
            "explanation": "No risk assessment generated yet. Run a forensic scan first.",
        }
    return {
        "score": risk.score,
        "level": risk.level,
        "factors": risk.factors or [],
        "explanation": risk.explanation,
    }


# --- 9. Incidents, Notes, Custody & Reports ---
class IncidentCreateBody(BaseModel):
    title: str
    status: str = "hypothesis"
    hypothesis: str | None = None
    affected_user: str | None = None
    affected_process: str | None = None
    attached_entity_ids: list[str] = Field(default_factory=list)
    attached_event_ids: list[str] = Field(default_factory=list)
    attached_finding_ids: list[str] = Field(default_factory=list)
    conclusion: str | None = None


@api_router.get("/investigations/{inv_id}/incidents")
def list_incidents(
    inv_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    check_investigation_access(db, inv_id, user)
    rows = db.scalars(
        select(IncidentCaseModel).where(IncidentCaseModel.investigation_id == inv_id).order_by(IncidentCaseModel.created_at.desc())
    ).all()
    return [_serialize_incident(r) for r in rows]


@api_router.post("/investigations/{inv_id}/incidents")
def create_incident(
    inv_id: str,
    body: IncidentCreateBody,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user, write=True)
    now = utc_now_str()
    ic = IncidentCaseModel(
        id=new_uuid(),
        investigation_id=inv_id,
        title=body.title,
        status=body.status,
        hypothesis=body.hypothesis,
        affected_user=body.affected_user,
        affected_process=body.affected_process,
        attached_entity_ids=body.attached_entity_ids,
        attached_event_ids=body.attached_event_ids,
        attached_finding_ids=body.attached_finding_ids,
        conclusion=body.conclusion,
        created_at=now,
        updated_at=now,
    )
    db.add(ic)
    db.commit()
    return _serialize_incident(ic)


@api_router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ic = db.get(IncidentCaseModel, incident_id)
    if not ic:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident case not found")
    check_investigation_access(db, ic.investigation_id, user)
    return _serialize_incident(ic)


class IncidentPatchBody(BaseModel):
    title: str | None = None
    status: str | None = None
    hypothesis: str | None = None
    affected_user: str | None = None
    affected_process: str | None = None
    attached_entity_ids: list[str] | None = None
    attached_event_ids: list[str] | None = None
    attached_finding_ids: list[str] | None = None
    conclusion: str | None = None


@api_router.patch("/incidents/{incident_id}")
def patch_incident(
    incident_id: str,
    body: IncidentPatchBody,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ic = db.get(IncidentCaseModel, incident_id)
    if not ic:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident case not found")
    check_investigation_access(db, ic.investigation_id, user, write=True)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(ic, k, v)
    ic.updated_at = utc_now_str()
    db.commit()
    return _serialize_incident(ic)


class NoteCreateBody(BaseModel):
    body: str
    incident_id: str | None = None


@api_router.get("/investigations/{inv_id}/notes")
def list_notes(
    inv_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    check_investigation_access(db, inv_id, user)
    rows = db.scalars(
        select(InvestigationNoteModel).where(InvestigationNoteModel.investigation_id == inv_id).order_by(InvestigationNoteModel.created_at.desc())
    ).all()
    return [
        {
            "id": n.id,
            "body": n.body,
            "incident_id": n.incident_id,
            "author": n.author,
            "created_at": n.created_at,
        }
        for n in rows
    ]


@api_router.post("/investigations/{inv_id}/notes")
def create_note(
    inv_id: str,
    body: NoteCreateBody,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    check_investigation_access(db, inv_id, user, write=True)
    n = InvestigationNoteModel(
        id=new_uuid(),
        investigation_id=inv_id,
        incident_id=body.incident_id,
        body=body.body,
        author=user.username,
        created_at=utc_now_str(),
    )
    db.add(n)
    db.commit()
    return {
        "id": n.id,
        "body": n.body,
        "incident_id": n.incident_id,
        "author": n.author,
        "created_at": n.created_at,
    }


@api_router.get("/investigations/{inv_id}/custody")
def list_custody(
    inv_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    check_investigation_access(db, inv_id, user)
    rows = db.scalars(
        select(ChainOfCustodyModel).where(ChainOfCustodyModel.investigation_id == inv_id).order_by(ChainOfCustodyModel.timestamp.desc())
    ).all()
    return [
        {
            "id": c.id,
            "artifact_id": c.artifact_id,
            "action": c.action,
            "actor": c.actor,
            "timestamp": c.timestamp,
            "sha256": c.sha256,
            "verification_status": c.verification_status,
            "details": c.details,
        }
        for c in rows
    ]


class CreateReportBody(BaseModel):
    format: str = "pdf"
    incident_id: str | None = None


@api_router.post("/investigations/{inv_id}/reports")
def create_report(
    inv_id: str,
    body: CreateReportBody,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    inv = check_investigation_access(db, inv_id, user, write=True)
    fmt = body.format.lower()
    if fmt not in ("pdf", "json"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="format must be 'pdf' or 'json'")
    rep = generate_investigation_report(db, inv, fmt, body.incident_id, user.username)
    write_audit_log(db, user.username, "generate_report", "report", rep.id, {"format": fmt, "investigation_id": inv.id})
    db.commit()
    return {
        "id": rep.id,
        "format": rep.format,
        "status": rep.status,
        "sha256": rep.sha256,
        "created_at": rep.created_at,
        "download_url": f"/api/reports/{rep.id}/download",
    }


@api_router.get("/investigations/{inv_id}/reports")
def list_reports(
    inv_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    check_investigation_access(db, inv_id, user)
    rows = db.scalars(
        select(ReportModel).where(ReportModel.investigation_id == inv_id).order_by(ReportModel.created_at.desc())
    ).all()
    return [
        {
            "id": r.id,
            "format": r.format,
            "status": r.status,
            "sha256": r.sha256,
            "created_at": r.created_at,
            "download_url": f"/api/reports/{r.id}/download",
        }
        for r in rows
    ]


@api_router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rep = db.get(ReportModel, report_id)
    if not rep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    check_investigation_access(db, rep.investigation_id, user)
    fpath = Path(rep.file_path)
    if not fpath.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file missing from storage")
    media_type = "application/pdf" if rep.format == "pdf" else "application/json"
    return FileResponse(str(fpath), media_type=media_type, filename=fpath.name)


@api_router.post("/demo/seed")
def seed_demo_endpoint(
    user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins may seed the demo dataset")
    inv = seed_demo_investigation(db, created_by=user.username)
    write_audit_log(db, user.username, "seed_demo", "investigation", inv.id)
    db.commit()
    return _serialize_investigation(inv, db)


# --- 10. WebSocket for live scan progress ---
@ws_router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str, token: str = Query(default="")) -> None:
    try:
        decode_access_token(token)
    except Exception:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    try:
        while True:
            db = SessionLocal()
            try:
                scan = db.get(ScanJobModel, scan_id)
                if not scan:
                    await websocket.close(code=4404)
                    return
                stages = list(scan.stages or [])
                payload = {"scan": _serialize_scan(scan), "stages": stages}
                await websocket.send_json({"type": "progress", "data": payload})
                if scan.status in ("completed", "partial", "failed", "cancelled"):
                    await websocket.send_json({"type": "status", "data": _serialize_scan(scan)})
                    break
            finally:
                db.close()
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return
