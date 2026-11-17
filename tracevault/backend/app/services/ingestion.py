"""Evidence ingestion, SHA-256 verification, NDJSON streaming, and chain-of-custody logging."""

from __future__ import annotations

import json
from typing import Any, BinaryIO

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import (
    ArtifactRecordModel,
    ArtifactSourceModel,
    ChainOfCustodyModel,
    CollectedArtifactModel,
    ScanJobModel,
    new_uuid,
    utc_now_str,
)
from .storage import resolve_storage_ref, store_stream_content_addressed


def ingest_uploaded_artifact(
    db: Session,
    scan: ScanJobModel,
    meta: dict[str, Any],
    records_stream: BinaryIO | None,
    original_stream: BinaryIO | None,
    actor: str,
) -> dict[str, Any]:
    """Ingest a single artifact upload, verify hashes, store originals content-addressed, and stream NDJSON records.

    Idempotent per `(scan.id, artifact_key)`: re-uploading replaces prior partial records for that artifact key.
    """
    artifact_key = str(meta.get("artifact_key") or "unknown")
    source = str(meta.get("source") or "evtx")
    expected_orig_sha = meta.get("sha256")
    expected_rec_sha = meta.get("records_sha256")

    orig_sha_actual: str | None = None
    rec_sha_actual: str | None = None
    storage_ref: str | None = None
    records_storage_ref: str | None = None

    # Stream files to disk and parse NDJSON in memory BEFORE opening a SQLite write transaction
    if original_stream is not None:
        orig_sha_actual, _, storage_ref = store_stream_content_addressed(original_stream)

    if records_stream is not None:
        rec_sha_actual, _, records_storage_ref = store_stream_content_addressed(records_stream)
        if not storage_ref:
            storage_ref = records_storage_ref

    # Hash verification logic
    verified = True
    verification_status = "verified"
    mismatches: list[str] = []

    if expected_orig_sha:
        if orig_sha_actual != expected_orig_sha:
            verified = False
            verification_status = "mismatch"
            mismatches.append(f"original sha256 mismatch (expected {expected_orig_sha}, got {orig_sha_actual})")

    if expected_rec_sha:
        if rec_sha_actual != expected_rec_sha:
            verified = False
            verification_status = "mismatch"
            mismatches.append(f"records sha256 mismatch (expected {expected_rec_sha}, got {rec_sha_actual})")

    if not expected_orig_sha and not expected_rec_sha:
        verified = False
        verification_status = "unverified"

    art_id = new_uuid()
    orig_path_str = str(meta.get("original_path") or "")
    effective_sha = orig_sha_actual or expected_orig_sha or rec_sha_actual or expected_rec_sha

    parsed_rows: list[dict[str, Any]] = []
    if records_storage_ref and verification_status != "mismatch":
        ndjson_file = resolve_storage_ref(records_storage_ref)
        with ndjson_file.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec_obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rec_id = str(rec_obj.get("record_id") or f"{artifact_key}:{line_no}")
                parsed_rows.append(
                    {
                        "id": new_uuid(),
                        "investigation_id": scan.investigation_id,
                        "artifact_id": art_id,
                        "artifact_key": artifact_key,
                        "source": source,
                        "record_id": rec_id,
                        "original_path": orig_path_str,
                        "sha256": effective_sha,
                        "data": rec_obj,
                        "related_event_ids": [],
                    }
                )

    inserted_count = len(parsed_rows)

    # Remove any prior upload of the same artifact_key in this scan (idempotency for retryable uploads)
    existing = db.scalars(
        select(CollectedArtifactModel).where(
            CollectedArtifactModel.scan_id == scan.id,
            CollectedArtifactModel.artifact_key == artifact_key,
        )
    ).all()
    for ex in existing:
        db.execute(delete(ArtifactRecordModel).where(ArtifactRecordModel.artifact_id == ex.id))
        db.delete(ex)

    artifact_row = CollectedArtifactModel(
        id=art_id,
        scan_id=scan.id,
        investigation_id=scan.investigation_id,
        endpoint_id=scan.endpoint_id,
        artifact_key=artifact_key,
        source=source,
        name=str(meta.get("name") or artifact_key),
        original_path=orig_path_str,
        status=str(meta.get("status") or "collected"),
        acquisition_method=str(meta.get("acquisition_method") or "collector"),
        sha256=orig_sha_actual or expected_orig_sha,
        records_sha256=rec_sha_actual or expected_rec_sha,
        size_bytes=meta.get("size_bytes"),
        last_modified=meta.get("last_modified"),
        collected_at=str(meta.get("collected_at") or utc_now_str()),
        collector_version=str(meta.get("collector_version") or "0.1.0"),
        record_count=inserted_count,
        parser=str(meta.get("parser") or "collector"),
        side_effects=list(meta.get("side_effects") or []),
        error=meta.get("error"),
        time_window=meta.get("time_window"),
        verified=verified,
        verification_status=verification_status,
        storage_ref=storage_ref,
    )
    db.add(artifact_row)

    if parsed_rows:
        db.bulk_insert_mappings(ArtifactRecordModel, parsed_rows)

    # Update or create ArtifactSourceModel summary for this scan
    src_row = db.scalar(
        select(ArtifactSourceModel).where(
            ArtifactSourceModel.scan_id == scan.id,
            ArtifactSourceModel.source == source,
        )
    )
    if not src_row:
        src_row = ArtifactSourceModel(
            scan_id=scan.id,
            investigation_id=scan.investigation_id,
            source=source,
            status=artifact_row.status,
            records_collected=inserted_count,
            errors=[artifact_row.error] if artifact_row.error else [],
        )
        db.add(src_row)
    else:
        src_row.records_collected = (src_row.records_collected or 0) + inserted_count
        if artifact_row.status == "collected" and src_row.status != "collected":
            src_row.status = "collected"
        if artifact_row.error:
            errs = list(src_row.errors or [])
            if artifact_row.error not in errs:
                errs.append(artifact_row.error)
            src_row.errors = errs
        src_row.updated_at = utc_now_str()

    # Record Chain of Custody entry
    db.add(
        ChainOfCustodyModel(
            investigation_id=scan.investigation_id,
            artifact_id=art_id,
            action="artifact_ingested",
            actor=actor,
            timestamp=utc_now_str(),
            sha256=artifact_row.sha256 or artifact_row.records_sha256,
            verification_status=verification_status,
            details={
                "artifact_key": artifact_key,
                "source": source,
                "status": artifact_row.status,
                "record_count": inserted_count,
                "acquisition_method": artifact_row.acquisition_method,
                "collector_version": artifact_row.collector_version,
                "storage_ref": storage_ref,
                "mismatches": mismatches,
            },
        )
    )
    db.commit()
    return {
        "artifact_id": art_id,
        "verified": verified,
        "verification_status": verification_status,
        "record_count": inserted_count,
    }
