"""All 20 SQLAlchemy 2.0 database tables specified in TraceVault Spec §11 & CONTRACT.md."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from ..db import Base

JSONType = JSON().with_variant(JSONB, "postgresql")


def new_uuid() -> str:
    return str(uuid.uuid4())


def utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


# 1. users
class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="investigator")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)


# 2. endpoints
class EndpointModel(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    machine_id: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    os_name: Mapped[str] = mapped_column(String(255), nullable=False)
    os_version: Mapped[str] = mapped_column(String(64), nullable=False)
    os_build: Mapped[str] = mapped_column(String(64), nullable=False)
    architecture: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    collection_user: Mapped[str] = mapped_column(String(255), nullable=False)
    is_elevated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    storage: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)
    discovery: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)
    registered_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)
    last_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)


# 3. endpoint_agents
class EndpointAgentModel(Base):
    __tablename__ = "endpoint_agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False, default="0.1.0")
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)
    last_heartbeat_at: Mapped[str | None] = mapped_column(String(64), nullable=True)


# 4. investigations
class InvestigationModel(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    assigned_user_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    reproducibility_versions: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)


# 5. scan_jobs
class ScanJobModel(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, default="quick")
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False, default="queued")
    time_window_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sources: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    stages: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    limitations: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    side_effects: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)
    started_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finished_at: Mapped[str | None] = mapped_column(String(64), nullable=True)


# 6. artifact_sources
class ArtifactSourceModel(Base):
    __tablename__ = "artifact_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    records_collected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    errors: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)


# 7. collected_artifacts
class CollectedArtifactModel(Base):
    __tablename__ = "collected_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    artifact_key: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    original_path: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    acquisition_method: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    records_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String(64), nullable=True)
    collected_at: Mapped[str] = mapped_column(String(64), nullable=False)
    collector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    parser: Mapped[str] = mapped_column(String(128), nullable=False)
    side_effects: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    time_window: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified")
    storage_ref: Mapped[str | None] = mapped_column(Text, nullable=True)


# 8. artifact_records
class ArtifactRecordModel(Base):
    __tablename__ = "artifact_records"
    __table_args__ = (
        Index("ix_artifact_records_inv_src", "investigation_id", "source"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("collected_artifacts.id", ondelete="CASCADE"), index=True, nullable=False
    )
    artifact_key: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    record_id: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    original_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    related_event_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)


# 9. normalized_events
class NormalizedEventModel(Base):
    __tablename__ = "normalized_events"
    __table_args__ = (
        Index("ix_norm_events_inv_ts", "investigation_id", "timestamp"),
        Index("ix_norm_events_inv_type", "investigation_id", "event_type"),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    artifact_source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    timestamp: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    timestamp_precision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(32), nullable=True, default="UTC")
    user_identifier: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    process_identifier: Mapped[str | None] = mapped_column(String(128), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    registry_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    network_indicator: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_artifact_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    source_record_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    raw_metadata: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    suspicious: Mapped[bool] = mapped_column(Boolean, index=True, nullable=False, default=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="info")


# 10. evidence_entities
class EvidenceEntityModel(Base):
    __tablename__ = "evidence_entities"
    __table_args__ = (
        Index("ix_entities_inv_type_key", "investigation_id", "type", "key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    key: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    label: Mapped[str] = mapped_column(String(512), nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    sources: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    first_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    suspicious: Mapped[bool] = mapped_column(Boolean, index=True, nullable=False, default=False)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)


# 11. evidence_relationships
class EvidenceRelationshipModel(Base):
    __tablename__ = "evidence_relationships"
    __table_args__ = (
        Index("ix_rel_inv_src_tgt", "investigation_id", "source_id", "target_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_entities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_entities.id", ondelete="CASCADE"), index=True, nullable=False
    )
    type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    evidence_class: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    correlation_method: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    supporting_event_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    supporting_artifact_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)


# 12. correlations
class CorrelationModel(Base):
    __tablename__ = "correlations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    relationship_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_relationships.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_event_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)


# 13. alerts (findings)
class AlertModel(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    affected_entity_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    affected_entity_label: Mapped[str | None] = mapped_column(String(512), nullable=True)
    detection_logic: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_event_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    mitre: Mapped[dict[str, str] | None] = mapped_column(JSONType, nullable=True)
    recommendations: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    disclaimer: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="A detection indicates activity worth review, not proof of malicious intent.",
    )


# 14. device_risk_assessments
class DeviceRiskAssessmentModel(Base):
    __tablename__ = "device_risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    level: Mapped[str] = mapped_column(String(32), nullable=False, default="low")
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    calculated_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)


# 15. investigation_notes
class InvestigationNoteModel(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)


# 16. incident_cases
class IncidentCaseModel(Base):
    __tablename__ = "incident_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="hypothesis")
    hypothesis: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attached_entity_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    attached_event_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    attached_finding_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    conclusion: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)


# 17. timeline_events
class TimelineEventModel(Base):
    __tablename__ = "timeline_events"
    __table_args__ = (
        Index("ix_timeline_inv_ts", "investigation_id", "timestamp"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    normalized_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("normalized_events.event_id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    timestamp_precision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    group: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    suspicious: Mapped[bool] = mapped_column(Boolean, index=True, nullable=False, default=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="info")
    entity_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    source_record_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_artifact_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


# 18. reports
class ReportModel(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ready")
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)


# 19. chain_of_custody
class ChainOfCustodyModel(Base):
    __tablename__ = "chain_of_custody"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    artifact_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False, default=utc_now_str)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)


# 20. audit_logs
class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    actor: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    timestamp: Mapped[str] = mapped_column(String(64), index=True, nullable=False, default=utc_now_str)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
