"""CLI entrypoint for `python -m tracevault_collector`."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

from .agent import (
    ALL_SOURCES,
    CollectorClient,
    load_agent_credentials,
    run_scan_to_bundle,
    save_agent_credentials,
)
from .discovery import discover_artifacts
from .identity import identify_endpoint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tracevault_collector",
        description="TraceVault Windows Endpoint Digital Forensics Collector",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("identify", help="Print endpoint identification JSON")
    sub.add_parser("discover", help="Inspect and print forensic artifact availability JSON")

    p_scan = sub.add_parser("scan", help="Run a local forensic scan and write an evidence bundle directory")
    p_scan.add_argument("--type", choices=["quick", "full"], default="quick")
    p_scan.add_argument("--hours", type=int, default=72, help="Time window in hours for quick scan")
    p_scan.add_argument("--sources", default=",".join(ALL_SOURCES), help="Comma-separated artifact sources")
    p_scan.add_argument("--out", required=True, help="Output bundle directory")

    p_reg = sub.add_parser("register", help="Enroll this Windows endpoint with the TraceVault backend")
    p_reg.add_argument("--server", default="http://127.0.0.1:8000")
    p_reg.add_argument("--enrollment-key", default="dev-enrollment-key")
    p_reg.add_argument("--creds-file", default=None)

    p_agent = sub.add_parser("agent", help="Run the pull-model agent loop (poll jobs, collect, upload)")
    p_agent.add_argument("--server", default="http://127.0.0.1:8000")
    p_agent.add_argument("--creds-file", default=None)
    p_agent.add_argument("--once", action="store_true", help="Send one heartbeat, process at most one queued job, and exit")
    p_agent.add_argument("--interval", type=float, default=5.0)

    p_up = sub.add_parser("upload", help="Upload an offline scan bundle into a scan job")
    p_up.add_argument("--server", default="http://127.0.0.1:8000")
    p_up.add_argument("--scan-id", required=True)
    p_up.add_argument("--bundle", required=True)
    p_up.add_argument("--creds-file", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "identify":
        print(json.dumps(identify_endpoint(), indent=2))
        return 0

    if args.cmd == "discover":
        print(json.dumps(discover_artifacts(), indent=2))
        return 0

    if args.cmd == "scan":
        sources = [s.strip() for s in args.sources.split(",") if s.strip()]
        manifest = run_scan_to_bundle(
            out_dir=Path(args.out),
            scan_type=args.type,
            time_window_hours=args.hours,
            sources=sources,
        )
        summary = {
            "status": manifest["status"],
            "bundle_dir": str(Path(args.out).resolve()),
            "artifacts": [
                {
                    "artifact_key": a["meta"]["artifact_key"],
                    "status": a["meta"]["status"],
                    "record_count": a["meta"]["record_count"],
                    "records_sha256": a["meta"]["records_sha256"],
                }
                for a in manifest["artifacts"]
            ],
            "limitations": manifest["limitations"],
        }
        print(json.dumps(summary, indent=2))
        return 0

    if args.cmd == "register":
        client = CollectorClient(args.server)
        reg = client.register_endpoint(args.enrollment_key)
        creds_path = Path(args.creds_file) if args.creds_file else None
        saved_to = save_agent_credentials(
            {
                "server_url": args.server,
                "endpoint_id": reg["endpoint_id"],
                "agent_id": reg["agent_id"],
                "agent_token": reg["agent_token"],
            },
            creds_path,
        )
        # Send immediate heartbeat with artifact discovery so the endpoint status is populated
        client.heartbeat()
        print(
            json.dumps(
                {
                    "endpoint_id": reg["endpoint_id"],
                    "agent_id": reg["agent_id"],
                    "credentials_saved_to": str(saved_to),
                },
                indent=2,
            )
        )
        return 0

    if args.cmd == "upload":
        creds = load_agent_credentials(Path(args.creds_file) if args.creds_file else None)
        client = CollectorClient(args.server or creds["server_url"], creds["agent_id"], creds["agent_token"])
        res = client.upload_bundle(args.scan_id, Path(args.bundle))
        print(json.dumps(res, indent=2))
        return 0

    if args.cmd == "agent":
        creds = load_agent_credentials(Path(args.creds_file) if args.creds_file else None)
        client = CollectorClient(args.server or creds["server_url"], creds["agent_id"], creds["agent_token"])
        while True:
            client.heartbeat()
            job = client.poll_next_job()
            if job:
                scan_id = job["scan_id"]
                with tempfile.TemporaryDirectory(prefix=f"tv_scan_{scan_id[:8]}_") as tmp_dir:
                    bundle_path = Path(tmp_dir)

                    def _progress(stage_payload: dict) -> bool:
                        return client.post_progress(scan_id, stage_payload)

                    manifest = run_scan_to_bundle(
                        out_dir=bundle_path,
                        scan_type=job.get("scan_type", "quick"),
                        time_window_hours=job.get("time_window_hours", 72),
                        sources=job.get("sources") or ALL_SOURCES,
                        progress_cb=_progress,
                    )
                    for item in manifest["artifacts"]:
                        client.upload_artifact(
                            scan_id=scan_id,
                            meta=item["meta"],
                            records_path=item.get("records_path"),
                            original_path=item.get("original_path"),
                        )
                    client.complete_scan(
                        scan_id=scan_id,
                        status=manifest["status"],
                        limitations=manifest["limitations"],
                        side_effects=manifest["side_effects"],
                    )
                if args.once:
                    return 0
            elif args.once:
                return 0
            time.sleep(args.interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
