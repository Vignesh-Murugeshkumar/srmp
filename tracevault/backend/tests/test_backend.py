"""Comprehensive unit and API integration test suite for the TraceVault backend."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Point to an isolated test SQLite DB before importing app
os.environ["TRACEVAULT_DATABASE_URL"] = "sqlite:///./test_tracevault.db"
os.environ["TRACEVAULT_EVIDENCE_DIR"] = str(Path(__file__).resolve().parent / "_test_evidence_store")

from app.auth import hash_password
from app.db import Base, SessionLocal, engine
from app.main import app, bootstrap_database
from app.models import UserModel, new_uuid, utc_now_str
from app.services.storage import resolve_storage_ref


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    bootstrap_database()
    yield


def _admin_headers(client: TestClient) -> dict[str, str]:
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "tracevault-admin"})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_twenty_tables_and_auth_rbac() -> None:
    # Verify all 20 tables exist in metadata
    expected_tables = {
        "users",
        "endpoints",
        "endpoint_agents",
        "investigations",
        "scan_jobs",
        "artifact_sources",
        "collected_artifacts",
        "artifact_records",
        "normalized_events",
        "evidence_entities",
        "evidence_relationships",
        "correlations",
        "alerts",
        "device_risk_assessments",
        "investigation_notes",
        "incident_cases",
        "timeline_events",
        "reports",
        "chain_of_custody",
        "audit_logs",
    }
    assert expected_tables.issubset(set(Base.metadata.tables.keys()))

    with TestClient(app) as client:
        headers = _admin_headers(client)
        me_resp = client.get("/api/auth/me", headers=headers)
        assert me_resp.status_code == 200
        assert me_resp.json()["role"] == "admin"

        # Create investigator and viewer users to verify investigation isolation
        db = SessionLocal()
        inv_user = UserModel(id=new_uuid(), username="alice", password_hash=hash_password("alice-pw"), role="investigator", created_at=utc_now_str())
        other_user = UserModel(id=new_uuid(), username="bob", password_hash=hash_password("bob-pw"), role="investigator", created_at=utc_now_str())
        db.add_all([inv_user, other_user])
        db.commit()
        db.close()

        alice_tok = client.post("/api/auth/login", json={"username": "alice", "password": "alice-pw"}).json()["access_token"]
        bob_tok = client.post("/api/auth/login", json={"username": "bob", "password": "bob-pw"}).json()["access_token"]

        # Register an endpoint
        ep_reg = client.post(
            "/api/endpoints/register",
            headers={"X-Enrollment-Key": "dev-enrollment-key"},
            json={"machine_id": "M-100", "hostname": "HOST-100"},
        ).json()

        # Alice creates an investigation
        inv = client.post(
            "/api/investigations",
            headers={"Authorization": f"Bearer {alice_tok}"},
            json={"title": "Alice Private Case", "endpoint_id": ep_reg["endpoint_id"]},
        ).json()

        # Bob is blocked from viewing Alice's unassigned investigation (403)
        bob_get = client.get(f"/api/investigations/{inv['id']}", headers={"Authorization": f"Bearer {bob_tok}"})
        assert bob_get.status_code == 403

        # Admin can view Alice's investigation
        adm_get = client.get(f"/api/investigations/{inv['id']}", headers=headers)
        assert adm_get.status_code == 200


def test_agent_enrollment_upload_hash_verification_and_cancel() -> None:
    with TestClient(app) as client:
        adm = _admin_headers(client)
        reg = client.post(
            "/api/endpoints/register",
            headers={"X-Enrollment-Key": "dev-enrollment-key"},
            json={"machine_id": "M-200", "hostname": "WS-200"},
        ).json()
        ep_id = reg["endpoint_id"]
        ag_headers = {"Authorization": f"Agent {reg['agent_id']}:{reg['agent_token']}"}

        inv = client.post("/api/investigations", headers=adm, json={"title": "Upload Test", "endpoint_id": ep_id}).json()
        scan = client.post(f"/api/endpoints/{ep_id}/scans", headers=adm, json={"investigation_id": inv["id"], "scan_type": "quick"}).json()

        # Agent claims job
        job_resp = client.get("/api/agent/jobs/next", headers=ag_headers)
        assert job_resp.status_code == 200
        assert job_resp.json()["scan_id"] == scan["id"]

        # Valid NDJSON upload with matching SHA-256
        ndjson_bytes = (json.dumps({"record_id": "r1", "source": "evtx", "channel": "Security", "event_id": 1102, "time_created": "2026-11-16T10:00:00Z"}) + "\n").encode("utf-8")
        good_sha = hashlib.sha256(ndjson_bytes).hexdigest()
        meta_good = {
            "artifact_key": "evtx:Security",
            "source": "evtx",
            "name": "Security",
            "original_path": "C:\\Security.evtx",
            "status": "collected",
            "acquisition_method": "test",
            "sha256": None,
            "records_sha256": good_sha,
            "collected_at": "2026-11-16T10:05:00+00:00",
            "collector_version": "0.1.0",
            "record_count": 1,
            "parser": "test",
        }
        up_ok = client.post(
            f"/api/agent/scans/{scan['id']}/artifacts",
            headers=ag_headers,
            files={
                "meta": ("meta.json", json.dumps(meta_good).encode("utf-8"), "application/json"),
                "records": ("records.ndjson", ndjson_bytes, "application/x-ndjson"),
            },
        )
        assert up_ok.status_code == 200
        assert up_ok.json()["verified"] is True
        assert up_ok.json()["record_count"] == 1

        # Tampered upload with mismatched SHA-256 -> verified=False, record_count=0
        meta_bad = {**meta_good, "artifact_key": "evtx:Tampered", "records_sha256": "0" * 64}
        up_bad = client.post(
            f"/api/agent/scans/{scan['id']}/artifacts",
            headers=ag_headers,
            files={
                "meta": ("meta.json", json.dumps(meta_bad).encode("utf-8"), "application/json"),
                "records": ("records.ndjson", ndjson_bytes, "application/x-ndjson"),
            },
        )
        assert up_bad.status_code == 200
        assert up_bad.json()["verified"] is False
        assert up_bad.json()["record_count"] == 0

        # Test scan cancellation propagation
        cancel_resp = client.post(f"/api/scans/{scan['id']}/cancel", headers=adm)
        assert cancel_resp.json()["cancel_requested"] is True
        prog_resp = client.post(
            f"/api/agent/scans/{scan['id']}/progress",
            headers=ag_headers,
            json={"stage": "evtx", "status": "running", "records": 1, "progress": 0.5},
        )
        assert prog_resp.json()["cancel_requested"] is True


def test_no_correlation_from_time_proximity_alone() -> None:
    """Verify two unrelated events occurring at the exact same timestamp do NOT form a relationship."""
    with TestClient(app) as client:
        adm = _admin_headers(client)
        reg = client.post(
            "/api/endpoints/register",
            headers={"X-Enrollment-Key": "dev-enrollment-key"},
            json={"machine_id": "M-300", "hostname": "WS-300"},
        ).json()
        ep_id = reg["endpoint_id"]
        ag_headers = {"Authorization": f"Agent {reg['agent_id']}:{reg['agent_token']}"}
        inv = client.post("/api/investigations", headers=adm, json={"title": "Time Proximity Guard Test", "endpoint_id": ep_id}).json()
        scan = client.post(f"/api/endpoints/{ep_id}/scans", headers=adm, json={"investigation_id": inv["id"], "scan_type": "quick"}).json()

        # Upload a browser visit to example.org AND an unrelated filesystem file at the exact same timestamp
        b_rec = (
            json.dumps(
                {
                    "record_id": "b1",
                    "source": "browser",
                    "browser": "chrome",
                    "profile": "Default",
                    "kind": "visit",
                    "url": "https://unrelated-news.example.org/",
                    "visit_time": "2026-11-16T12:00:00+00:00",
                }
            )
            + "\n"
        ).encode("utf-8")
        fs_rec = (
            json.dumps(
                {
                    "record_id": "f1",
                    "source": "filesystem",
                    "kind": "file_metadata",
                    "path": r"C:\Users\Public\notes.txt",
                    "created": "2026-11-16T12:00:00+00:00",
                }
            )
            + "\n"
        ).encode("utf-8")

        for a_key, src, payload in [("browser:Chrome", "browser", b_rec), ("filesystem:UserFiles", "filesystem", fs_rec)]:
            client.post(
                f"/api/agent/scans/{scan['id']}/artifacts",
                headers=ag_headers,
                files={
                    "meta": (
                        "meta.json",
                        json.dumps(
                            {
                                "artifact_key": a_key,
                                "source": src,
                                "name": a_key,
                                "original_path": "C:\\test",
                                "status": "collected",
                                "acquisition_method": "test",
                                "records_sha256": hashlib.sha256(payload).hexdigest(),
                                "collected_at": "2026-11-16T12:01:00+00:00",
                                "collector_version": "0.1.0",
                                "record_count": 1,
                                "parser": "test",
                            }
                        ).encode("utf-8"),
                        "application/json",
                    ),
                    "records": ("r.ndjson", payload, "application/x-ndjson"),
                },
            )
        client.post(f"/api/agent/scans/{scan['id']}/complete", headers=ag_headers, json={"status": "completed", "limitations": [], "side_effects": []})

        graph = client.get(f"/api/investigations/{inv['id']}/evidence-graph", headers=adm).json()
        assert graph["stats"]["node_count"] == 2
        assert graph["stats"]["edge_count"] == 0


def test_demo_seed_graph_timetravel_and_pdf_report() -> None:
    with TestClient(app) as client:
        adm = _admin_headers(client)
        demo_inv = client.post("/api/demo/seed", headers=adm).json()
        assert demo_inv["is_demo"] is True
        inv_id = demo_inv["id"]

        summary = client.get(f"/api/investigations/{inv_id}/summary", headers=adm).json()
        assert summary["evidence_collected"] == 6
        assert summary["suspicious_findings"] >= 6
        assert summary["high_confidence_relationships"] >= 6

        # Full graph vs Time Travel graph before 14:02:00Z (before dropper execution)
        full_graph = client.get(f"/api/investigations/{inv_id}/evidence-graph", headers=adm).json()
        early_graph = client.get(
            f"/api/investigations/{inv_id}/evidence-graph",
            params={"at": "2026-11-16T14:01:30+00:00"},
            headers=adm,
        ).json()
        assert full_graph["stats"]["edge_count"] > early_graph["stats"]["edge_count"]
        assert early_graph["stats"]["edge_count"] >= 1

        # Every relationship must have explanation and supporting_event_ids
        for edge in full_graph["edges"]:
            assert edge["explanation"]
            assert len(edge["supporting_event_ids"]) >= 1

        # Generate PDF and JSON reports
        pdf_rep = client.post(f"/api/investigations/{inv_id}/reports", headers=adm, json={"format": "pdf"}).json()
        assert pdf_rep["sha256"]
        dl_pdf = client.get(pdf_rep["download_url"], headers=adm)
        assert dl_pdf.status_code == 200
        assert dl_pdf.content.startswith(b"%PDF")

        json_rep = client.post(f"/api/investigations/{inv_id}/reports", headers=adm, json={"format": "json"}).json()
        dl_json = client.get(json_rep["download_url"], headers=adm)
        assert dl_json.status_code == 200
        parsed_report = dl_json.json()
        assert "1_executive_summary" in parsed_report
        assert "13_limitations" in parsed_report


def test_path_traversal_protection() -> None:
    with pytest.raises(ValueError):
        resolve_storage_ref("../../Windows/System32/cmd.exe")
