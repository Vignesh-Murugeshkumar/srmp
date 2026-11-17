"""Evidence Graph and Temporal Reconstruction query services (CONTRACT §6 & Spec §8-9)."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (
    CollectedArtifactModel,
    EvidenceEntityModel,
    EvidenceRelationshipModel,
    TimelineEventModel,
)


def serialize_entity(ent: EvidenceEntityModel) -> dict[str, Any]:
    return {
        "id": ent.id,
        "type": ent.type,
        "key": ent.key,
        "label": ent.label,
        "properties": ent.properties or {},
        "sources": ent.sources or [],
        "first_seen": ent.first_seen,
        "last_seen": ent.last_seen,
        "suspicious": bool(ent.suspicious),
        "risk_score": ent.risk_score,
    }


def serialize_relationship(rel: EvidenceRelationshipModel) -> dict[str, Any]:
    return {
        "id": rel.id,
        "source": rel.source_id,
        "target": rel.target_id,
        "type": rel.type,
        "evidence_class": rel.evidence_class,
        "correlation_method": rel.correlation_method,
        "confidence": rel.confidence,
        "explanation": rel.explanation,
        "timestamp": rel.timestamp,
        "supporting_event_ids": rel.supporting_event_ids or [],
        "supporting_artifact_ids": rel.supporting_artifact_ids or [],
    }


def serialize_timeline_event(ev: TimelineEventModel) -> dict[str, Any]:
    return {
        "id": ev.id,
        "timestamp": ev.timestamp,
        "timestamp_precision": ev.timestamp_precision,
        "group": ev.group,
        "event_type": ev.event_type,
        "artifact_source": ev.artifact_source,
        "summary": ev.summary,
        "suspicious": bool(ev.suspicious),
        "severity": ev.severity,
        "entity_ids": ev.entity_ids or [],
        "source_record_id": ev.source_record_id,
        "source_artifact_id": ev.source_artifact_id,
    }


def query_evidence_graph(
    db: Session,
    investigation_id: str,
    at: str | None = None,
    sources: list[str] | None = None,
    relationship_types: list[str] | None = None,
    evidence_classes: list[str] | None = None,
    focus: str | None = None,
    depth: int = 2,
    suspicious_only: bool = False,
) -> dict[str, Any]:
    """Build the filtered Evidence Universe graph, supporting Time Travel (`at`) and BFS focus expansion."""
    all_entities = db.scalars(
        select(EvidenceEntityModel).where(EvidenceEntityModel.investigation_id == investigation_id)
    ).all()
    all_rels = db.scalars(
        select(EvidenceRelationshipModel).where(EvidenceRelationshipModel.investigation_id == investigation_id)
    ).all()

    entity_map = {e.id: e for e in all_entities}

    # Filter relationships
    filtered_rels: list[EvidenceRelationshipModel] = []
    for rel in all_rels:
        if rel.source_id not in entity_map or rel.target_id not in entity_map:
            continue
        if at:
            # Time Travel: include only relationships with a known timestamp <= at
            if not rel.timestamp or rel.timestamp > at:
                continue
        if relationship_types and rel.type not in relationship_types:
            continue
        if evidence_classes and rel.evidence_class not in evidence_classes:
            continue
        filtered_rels.append(rel)

    # Filter nodes by source / suspicious_only
    valid_node_ids: set[str] = set()
    if at:
        # When Time Travel `at` is active, include only nodes touched by active relationships up to `at`
        for r in filtered_rels:
            valid_node_ids.add(r.source_id)
            valid_node_ids.add(r.target_id)
    else:
        valid_node_ids = set(entity_map.keys())

    if sources:
        src_set = set(sources)
        valid_node_ids = {
            nid for nid in valid_node_ids if set(entity_map[nid].sources or []) & src_set
        }

    if suspicious_only:
        susp_ids = {nid for nid in valid_node_ids if entity_map[nid].suspicious}
        # Keep suspicious nodes plus immediate neighbors connected by filtered relationships
        neighbor_ids = set(susp_ids)
        for r in filtered_rels:
            if r.source_id in susp_ids or r.target_id in susp_ids:
                neighbor_ids.add(r.source_id)
                neighbor_ids.add(r.target_id)
        valid_node_ids &= neighbor_ids

    # Optional BFS focus neighborhood filter
    if focus and focus in entity_map:
        adj: dict[str, set[str]] = {}
        for r in filtered_rels:
            adj.setdefault(r.source_id, set()).add(r.target_id)
            adj.setdefault(r.target_id, set()).add(r.source_id)
        visited = {focus}
        queue = deque([(focus, 0)])
        while queue:
            curr, d = queue.popleft()
            if d >= max(1, depth):
                continue
            for nxt in adj.get(curr, set()):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, d + 1))
        valid_node_ids &= visited

    # Keep only edges where both endpoints remain in valid_node_ids
    final_rels = [
        r for r in filtered_rels if r.source_id in valid_node_ids and r.target_id in valid_node_ids
    ]

    # Prioritize nodes connected by edges + suspicious nodes when capping at graph_max_nodes
    connected_ids = {r.source_id for r in final_rels} | {r.target_id for r in final_rels}
    ordered_nodes = sorted(
        (entity_map[nid] for nid in valid_node_ids),
        key=lambda n: (
            0 if n.suspicious else 1,
            0 if n.id in connected_ids else 1,
            -(n.risk_score or 0.0),
        ),
    )

    truncated = False
    if len(ordered_nodes) > settings.graph_max_nodes:
        ordered_nodes = ordered_nodes[: settings.graph_max_nodes]
        truncated = True
        kept_ids = {n.id for n in ordered_nodes}
        final_rels = [r for r in final_rels if r.source_id in kept_ids and r.target_id in kept_ids]

    return {
        "nodes": [serialize_entity(n) for n in ordered_nodes],
        "edges": [serialize_relationship(r) for r in final_rels],
        "stats": {
            "node_count": len(ordered_nodes),
            "edge_count": len(final_rels),
            "truncated": truncated,
        },
    }


def query_timeline(
    db: Session,
    investigation_id: str,
    start: str | None = None,
    end: str | None = None,
    groups: list[str] | None = None,
    sources: list[str] | None = None,
    suspicious_only: bool = False,
    limit: int = 5000,
) -> dict[str, Any]:
    rows = db.scalars(
        select(TimelineEventModel)
        .where(TimelineEventModel.investigation_id == investigation_id)
        .order_by(TimelineEventModel.timestamp.asc())
    ).all()

    all_ts = [r.timestamp for r in rows if r.timestamp]
    bounds = {
        "start": min(all_ts) if all_ts else None,
        "end": max(all_ts) if all_ts else None,
    }

    artifacts = db.scalars(
        select(CollectedArtifactModel).where(CollectedArtifactModel.investigation_id == investigation_id)
    ).all()
    coll_times = [a.collected_at for a in artifacts if a.collected_at]
    collection_time = max(coll_times) if coll_times else None

    filtered: list[TimelineEventModel] = []
    for r in rows:
        if start and (not r.timestamp or r.timestamp < start):
            continue
        if end and (not r.timestamp or r.timestamp > end):
            continue
        if groups and r.group not in groups:
            continue
        if sources and r.artifact_source not in sources:
            continue
        if suspicious_only and not r.suspicious:
            continue
        filtered.append(r)

    total = len(filtered)
    truncated = total > limit
    sliced = filtered[:limit]

    return {
        "events": [serialize_timeline_event(e) for e in sliced],
        "bounds": bounds,
        "collection_time": collection_time,
        "total": total,
        "truncated": truncated,
    }


def query_timeline_range(db: Session, investigation_id: str, buckets: int = 120) -> dict[str, Any]:
    rows = db.scalars(
        select(TimelineEventModel).where(TimelineEventModel.investigation_id == investigation_id)
    ).all()

    parsed: list[tuple[float, bool]] = []
    for r in rows:
        if not r.timestamp:
            continue
        try:
            dt = datetime.fromisoformat(r.timestamp.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed.append((dt.timestamp(), bool(r.suspicious)))
        except ValueError:
            continue

    if not parsed:
        return {"start": None, "end": None, "buckets": []}

    min_t = min(p[0] for p in parsed)
    max_t = max(p[0] for p in parsed)
    if max_t <= min_t:
        max_t = min_t + 60.0

    num_b = max(10, min(500, buckets))
    step = (max_t - min_t) / num_b
    counts = [[0, 0] for _ in range(num_b)]
    for ts_val, is_susp in parsed:
        idx = min(num_b - 1, int((ts_val - min_t) / step))
        counts[idx][0] += 1
        if is_susp:
            counts[idx][1] += 1

    out_buckets = []
    for i, (cnt, susp) in enumerate(counts):
        bt = datetime.fromtimestamp(min_t + i * step, tz=timezone.utc).isoformat()
        out_buckets.append({"t": bt, "count": cnt, "suspicious": susp})

    return {
        "start": datetime.fromtimestamp(min_t, tz=timezone.utc).isoformat(),
        "end": datetime.fromtimestamp(max_t, tz=timezone.utc).isoformat(),
        "buckets": out_buckets,
    }
