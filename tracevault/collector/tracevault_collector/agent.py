"""Offline bundle scan orchestrator and backend protocol client (CONTRACT §3)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable

import requests

from . import __version__
from .collectors.amcache import collect_amcache
from .collectors.browser import collect_browsers
from .collectors.evtx import collect_evtx
from .collectors.filesystem import collect_filesystem
from .collectors.prefetch import collect_prefetch
from .collectors.registry import collect_registry
from .discovery import discover_artifacts
from .identity import identify_endpoint, is_process_elevated
from .utils import utc_now_iso

ALL_SOURCES = ["evtx", "registry", "prefetch", "amcache", "browser", "filesystem"]


def default_agent_credentials_path() -> Path:
    local_app = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return Path(local_app) / "TraceVault" / "agent.json"


def save_agent_credentials(data: dict[str, Any], path: Path | None = None) -> Path:
    target = path or default_agent_credentials_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return target


def load_agent_credentials(path: Path | None = None) -> dict[str, Any]:
    target = path or default_agent_credentials_path()
    if not target.is_file():
        raise FileNotFoundError(f"Agent credentials not found at {target}. Run 'register' first.")
    return json.loads(target.read_text(encoding="utf-8"))


def run_scan_to_bundle(
    out_dir: Path,
    scan_type: str = "quick",
    time_window_hours: int | None = 72,
    sources: list[str] | None = None,
    progress_cb: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Execute forensic collection across requested sources and write a deterministic bundle directory.

    If `progress_cb` returns True (indicating `cancel_requested`), remaining stages are marked cancelled.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    selected_sources = [s for s in (sources or ALL_SOURCES) if s in ALL_SOURCES]
    identity = identify_endpoint()
    discovery = discover_artifacts()

    stage_dispatch: list[tuple[str, str, Callable[[], list[dict[str, Any]]]]] = [
        ("evtx", "Collecting Windows Event Logs (EVTX)", lambda: collect_evtx(out_dir, scan_type, time_window_hours)),
        ("registry", "Inspecting Windows Registry persistence & activity keys", lambda: collect_registry(out_dir, scan_type)),
        ("prefetch", "Inspecting Windows Prefetch execution artifacts", lambda: collect_prefetch(out_dir, scan_type)),
        ("amcache", "Inspecting Amcache application inventory", lambda: collect_amcache(out_dir, scan_type)),
        ("browser", "Extracting Browser History & Downloads via read-only snapshots", lambda: collect_browsers(out_dir, scan_type)),
        ("filesystem", "Inspecting Recycle Bin ($I), User Files, USN Journal & $MFT", lambda: collect_filesystem(out_dir, scan_type)),
    ]

    all_artifacts: list[dict[str, Any]] = []
    limitations: list[str] = []
    side_effects: list[str] = [
        "Live endpoint collection: collector process memory and staging directory written on disk",
        "All source registry keys, event logs, and SQLite databases opened strictly read-only",
    ]
    if not is_process_elevated():
        limitations.append(
            "Collector ran at Medium integrity (non-elevated): Security EVTX, Prefetch, Amcache, USN Journal, and $MFT reported permission_denied."
        )

    cancelled = False
    for idx, (stage_name, msg, fn) in enumerate(stage_dispatch):
        if stage_name not in selected_sources:
            if progress_cb:
                progress_cb(
                    {
                        "stage": stage_name,
                        "status": "skipped",
                        "records": 0,
                        "progress": 1.0,
                        "duration_ms": 0,
                        "errors": [],
                        "message": "Source not selected for scan",
                    }
                )
            continue

        if cancelled:
            if progress_cb:
                progress_cb(
                    {
                        "stage": stage_name,
                        "status": "cancelled",
                        "records": 0,
                        "progress": 0.0,
                        "duration_ms": 0,
                        "errors": ["Cancelled by analyst"],
                        "message": "Cancelled",
                    }
                )
            continue

        t0 = time.perf_counter()
        if progress_cb:
            cancel_req = progress_cb(
                {
                    "stage": stage_name,
                    "status": "running",
                    "records": 0,
                    "progress": 0.1,
                    "duration_ms": 0,
                    "errors": [],
                    "message": msg,
                }
            )
            if cancel_req:
                cancelled = True
                continue

        stage_items = fn()
        dur_ms = int((time.perf_counter() - t0) * 1000)
        all_artifacts.extend(stage_items)

        stage_records = sum(int(item["meta"].get("record_count", 0)) for item in stage_items)
        stage_errors = [item["meta"]["error"] for item in stage_items if item["meta"].get("error")]
        for err in stage_errors:
            if err not in limitations:
                limitations.append(err)
        for item in stage_items:
            for se in item["meta"].get("side_effects", []):
                if se not in side_effects:
                    side_effects.append(se)

        collected_any = any(item["meta"]["status"] == "collected" for item in stage_items)
        failed_any = any(item["meta"]["status"] in ("permission_denied", "error", "unsupported") for item in stage_items)
        if collected_any and failed_any:
            st_status = "partial"
        elif collected_any:
            st_status = "completed"
        elif all(item["meta"]["status"] == "not_found" for item in stage_items):
            st_status = "completed"
        else:
            st_status = "partial"

        if progress_cb:
            cancel_req = progress_cb(
                {
                    "stage": stage_name,
                    "status": st_status,
                    "records": stage_records,
                    "progress": 1.0,
                    "duration_ms": dur_ms,
                    "errors": stage_errors,
                    "message": f"{stage_records} record(s) acquired across {len(stage_items)} artifact(s)",
                }
            )
            if cancel_req:
                cancelled = True

    overall_status = "cancelled" if cancelled else "completed"
    if not cancelled:
        has_collected = any(a["meta"]["status"] == "collected" for a in all_artifacts)
        has_denied = any(a["meta"]["status"] in ("permission_denied", "error") for a in all_artifacts)
        if has_collected and has_denied:
            overall_status = "partial"
        elif not has_collected:
            overall_status = "failed"

    manifest = {
        "bundle_version": "1.0",
        "collector_version": __version__,
        "created_at": utc_now_iso(),
        "scan_type": scan_type,
        "time_window_hours": time_window_hours,
        "status": overall_status,
        "endpoint": identity,
        "discovery": discovery,
        "artifacts": all_artifacts,
        "limitations": limitations,
        "side_effects": side_effects,
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


class CollectorClient:
    """Retryable HTTP client for agent enrollment, heartbeats, job polling, and artifact upload."""

    def __init__(
        self,
        server_url: str,
        agent_id: str | None = None,
        agent_token: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h: dict[str, str] = {"Accept": "application/json"}
        if self.agent_id and self.agent_token:
            h["Authorization"] = f"Agent {self.agent_id}:{self.agent_token}"
        if extra:
            h.update(extra)
        return h

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.server_url}{path}"
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
                if resp.status_code in (502, 503, 504) and attempt + 1 < self.max_retries:
                    time.sleep(0.5 * (2**attempt))
                    continue
                return resp
            except requests.RequestException as exc:
                last_exc = exc
                if attempt + 1 < self.max_retries:
                    time.sleep(0.5 * (2**attempt))
        raise RuntimeError(f"Request {method} {url} failed after {self.max_retries} attempts: {last_exc}")

    def register_endpoint(self, enrollment_key: str, identity: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = identity or identify_endpoint()
        resp = self._request(
            "POST",
            "/api/endpoints/register",
            headers=self._headers({"X-Enrollment-Key": enrollment_key}),
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        self.agent_id = data["agent_id"]
        self.agent_token = data["agent_token"]
        return data

    def heartbeat(self, discovery: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        resp = self._request(
            "POST",
            "/api/agent/heartbeat",
            headers=self._headers(),
            json={"discovery": discovery if discovery is not None else discover_artifacts()},
        )
        resp.raise_for_status()
        return resp.json()

    def poll_next_job(self) -> dict[str, Any] | None:
        resp = self._request("GET", "/api/agent/jobs/next", headers=self._headers())
        if resp.status_code == 204:
            return None
        resp.raise_for_status()
        return resp.json()

    def post_progress(self, scan_id: str, stage_progress: dict[str, Any]) -> bool:
        resp = self._request(
            "POST",
            f"/api/agent/scans/{scan_id}/progress",
            headers=self._headers(),
            json=stage_progress,
        )
        resp.raise_for_status()
        return bool(resp.json().get("cancel_requested", False))

    def upload_artifact(
        self,
        scan_id: str,
        meta: dict[str, Any],
        records_path: str | Path | None = None,
        original_path: str | Path | None = None,
    ) -> dict[str, Any]:
        for attempt in range(self.max_retries):
            files: dict[str, Any] = {
                "meta": ("meta.json", json.dumps(meta).encode("utf-8"), "application/json"),
            }
            opened_handles = []
            try:
                if records_path and Path(records_path).is_file():
                    rf = Path(records_path).open("rb")
                    opened_handles.append(rf)
                    files["records"] = (Path(records_path).name, rf, "application/x-ndjson")
                if original_path and Path(original_path).is_file():
                    of = Path(original_path).open("rb")
                    opened_handles.append(of)
                    files["original"] = (Path(original_path).name, of, "application/octet-stream")

                resp = self.session.post(
                    f"{self.server_url}/api/agent/scans/{scan_id}/artifacts",
                    headers=self._headers(),
                    files=files,
                    timeout=max(self.timeout, 60.0),
                )
                if resp.status_code in (502, 503, 504) and attempt + 1 < self.max_retries:
                    time.sleep(0.5 * (2**attempt))
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException:
                if attempt + 1 >= self.max_retries:
                    raise
                time.sleep(0.5 * (2**attempt))
            finally:
                for h in opened_handles:
                    try:
                        h.close()
                    except Exception:
                        pass
        raise RuntimeError("Artifact upload failed")

    def complete_scan(
        self,
        scan_id: str,
        status: str,
        limitations: list[str],
        side_effects: list[str],
    ) -> dict[str, Any]:
        resp = self._request(
            "POST",
            f"/api/agent/scans/{scan_id}/complete",
            headers=self._headers(),
            json={
                "status": status,
                "limitations": limitations,
                "side_effects": side_effects,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def upload_bundle(self, scan_id: str, bundle_dir: Path) -> dict[str, Any]:
        manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        uploaded = []
        for item in manifest.get("artifacts", []):
            res = self.upload_artifact(
                scan_id=scan_id,
                meta=item["meta"],
                records_path=item.get("records_path"),
                original_path=item.get("original_path"),
            )
            uploaded.append(res)
        comp = self.complete_scan(
            scan_id=scan_id,
            status=manifest.get("status", "completed"),
            limitations=manifest.get("limitations", []),
            side_effects=manifest.get("side_effects", []),
        )
        return {"uploaded": uploaded, "complete": comp}
