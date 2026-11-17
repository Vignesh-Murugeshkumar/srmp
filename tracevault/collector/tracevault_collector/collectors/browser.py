"""Browser forensic collector for Chrome, Edge, and Firefox (CONTRACT §4 & Spec §5.9).

Uses read-only SQLite access on safe temporary snapshot copies.
Strictly avoids collecting saved passwords, cookies, tokens, or autofill credentials.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Iterator

from .. import __version__
from ..utils import prtime_to_iso, safe_artifact_filename, sha256_file, stat_info, utc_now_iso, webkit_to_iso, write_ndjson_records

CHROMIUM_DANGER_TYPES = {
    0: "NOT_DANGEROUS",
    1: "DANGEROUS_FILE",
    2: "DANGEROUS_URL",
    3: "DANGEROUS_CONTENT",
    4: "MAYBE_DANGEROUS_CONTENT",
    5: "UNCOMMON_CONTENT",
    6: "USER_VALIDATED",
    7: "DANGEROUS_HOST",
    8: "POTENTIALLY_UNWANTED",
}

CHROMIUM_STATES = {
    0: "IN_PROGRESS",
    1: "COMPLETE",
    2: "CANCELLED",
    3: "INTERRUPTED",
}


def extract_chromium_sqlite_records(
    db_path: Path,
    browser_name: str,
    profile_name: str,
    max_records: int = 1000,
) -> Iterator[dict[str, Any]]:
    """Extract visit and download records from a Chromium (Chrome/Edge) History SQLite database."""
    with tempfile.TemporaryDirectory(prefix="tv_browser_") as tmp:
        snap = Path(tmp) / "History.sqlite"
        try:
            shutil.copy2(db_path, snap)
            for ext in ("-wal", "-journal"):
                aux = Path(str(db_path) + ext)
                if aux.is_file():
                    shutil.copy2(aux, Path(str(snap) + ext))
        except OSError:
            # Fallback to immutable URI read
            snap = db_path

        uri = f"file:{snap.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.cursor()
            # 1. Downloads
            dl_limit = max(100, max_records // 3)
            try:
                cur.execute(
                    """
                    SELECT d.id, d.target_path, d.current_path, d.start_time, d.end_time,
                           d.received_bytes, d.total_bytes, d.state, d.danger_type,
                           d.referrer, d.tab_url, d.mime_type,
                           (SELECT c.url FROM downloads_url_chains c WHERE c.id = d.id ORDER BY c.chain_index DESC LIMIT 1) AS chain_url
                    FROM downloads d
                    ORDER BY d.start_time DESC
                    LIMIT ?
                    """,
                    (dl_limit,),
                )
                for row in cur.fetchall():
                    url = row["chain_url"] or row["tab_url"] or row["referrer"] or ""
                    target = row["target_path"] or row["current_path"]
                    yield {
                        "record_id": f"{browser_name}:{profile_name}:download:{row['id']}",
                        "source": "browser",
                        "browser": browser_name,
                        "profile": profile_name,
                        "kind": "download",
                        "url": url,
                        "title": Path(target).name if target else None,
                        "visit_time": webkit_to_iso(row["start_time"]),
                        "timestamp_precision": "microsecond",
                        "visit_count": None,
                        "transition": None,
                        "target_path": target,
                        "start_time": webkit_to_iso(row["start_time"]),
                        "end_time": webkit_to_iso(row["end_time"]),
                        "received_bytes": int(row["received_bytes"]) if row["received_bytes"] is not None else None,
                        "total_bytes": int(row["total_bytes"]) if row["total_bytes"] is not None else None,
                        "mime_type": row["mime_type"],
                        "referrer": row["referrer"] or None,
                        "danger_type": CHROMIUM_DANGER_TYPES.get(row["danger_type"], str(row["danger_type"])),
                        "state": CHROMIUM_STATES.get(row["state"], str(row["state"])),
                    }
            except sqlite3.Error:
                pass

            # 2. Visits
            visit_limit = max(100, max_records - dl_limit)
            try:
                cur.execute(
                    """
                    SELECT v.id AS visit_id, u.url, u.title, u.visit_count, v.visit_time, v.transition
                    FROM visits v
                    JOIN urls u ON v.url = u.id
                    ORDER BY v.visit_time DESC
                    LIMIT ?
                    """,
                    (visit_limit,),
                )
                for row in cur.fetchall():
                    yield {
                        "record_id": f"{browser_name}:{profile_name}:visit:{row['visit_id']}",
                        "source": "browser",
                        "browser": browser_name,
                        "profile": profile_name,
                        "kind": "visit",
                        "url": row["url"],
                        "title": row["title"] or None,
                        "visit_time": webkit_to_iso(row["visit_time"]),
                        "timestamp_precision": "microsecond",
                        "visit_count": int(row["visit_count"]) if row["visit_count"] is not None else None,
                        "transition": str(row["transition"]) if row["transition"] is not None else None,
                        "target_path": None,
                        "start_time": None,
                        "end_time": None,
                        "received_bytes": None,
                        "total_bytes": None,
                        "mime_type": None,
                        "referrer": None,
                        "danger_type": None,
                        "state": None,
                    }
            except sqlite3.Error:
                pass
        finally:
            conn.close()


def extract_firefox_sqlite_records(
    db_path: Path,
    profile_name: str,
    max_records: int = 1000,
) -> Iterator[dict[str, Any]]:
    """Extract visit and download records from a Firefox places.sqlite database."""
    with tempfile.TemporaryDirectory(prefix="tv_ff_") as tmp:
        snap = Path(tmp) / "places.sqlite"
        try:
            shutil.copy2(db_path, snap)
            for ext in ("-wal", "-journal"):
                aux = Path(str(db_path) + ext)
                if aux.is_file():
                    shutil.copy2(aux, Path(str(snap) + ext))
        except OSError:
            snap = db_path

        uri = f"file:{snap.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    """
                    SELECT h.id AS visit_id, p.url, p.title, p.visit_count, h.visit_date, h.visit_type
                    FROM moz_historyvisits h
                    JOIN moz_places p ON h.place_id = p.id
                    ORDER BY h.visit_date DESC
                    LIMIT ?
                    """,
                    (max_records,),
                )
                for row in cur.fetchall():
                    yield {
                        "record_id": f"firefox:{profile_name}:visit:{row['visit_id']}",
                        "source": "browser",
                        "browser": "firefox",
                        "profile": profile_name,
                        "kind": "visit",
                        "url": row["url"],
                        "title": row["title"] or None,
                        "visit_time": prtime_to_iso(row["visit_date"]),
                        "timestamp_precision": "microsecond",
                        "visit_count": int(row["visit_count"]) if row["visit_count"] is not None else None,
                        "transition": str(row["visit_type"]) if row["visit_type"] is not None else None,
                        "target_path": None,
                        "start_time": None,
                        "end_time": None,
                        "received_bytes": None,
                        "total_bytes": None,
                        "mime_type": None,
                        "referrer": None,
                        "danger_type": None,
                        "state": None,
                    }
            except sqlite3.Error:
                pass
        finally:
            conn.close()


def collect_browsers(out_dir: Path, scan_type: str = "quick", max_records_per_browser: int = 1200) -> list[dict[str, Any]]:
    """Collect Chrome, Edge, and Firefox history and download records via safe read-only SQLite snapshots."""
    local_app = os.environ.get("LOCALAPPDATA", "")
    roaming_app = os.environ.get("APPDATA", "")
    records_dir = out_dir / "records"
    originals_dir = out_dir / "originals"
    records_dir.mkdir(parents=True, exist_ok=True)
    originals_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        ("browser:Chrome", "Google Chrome History & Downloads", "chrome", os.path.join(local_app, r"Google\Chrome\User Data"), "History"),
        ("browser:Edge", "Microsoft Edge History & Downloads", "edge", os.path.join(local_app, r"Microsoft\Edge\User Data"), "History"),
        ("browser:Firefox", "Mozilla Firefox Places & Downloads", "firefox", os.path.join(roaming_app, r"Mozilla\Firefox\Profiles"), "places.sqlite"),
    ]

    results: list[dict[str, Any]] = []
    for artifact_key, name, b_code, root_str, db_filename in targets:
        root = Path(root_str) if root_str else Path("nonexistent")
        safe_stem = safe_artifact_filename(artifact_key)
        ndjson_path = records_dir / f"{safe_stem}.ndjson"
        original_copy: Path | None = None
        orig_sha256: str | None = None
        status = "collected"
        error_msg: str | None = None
        record_count = 0
        records_sha256: str | None = None
        total_size: int | None = None
        latest_mod: str | None = None

        if not root.exists():
            status = "not_found"
            error_msg = f"{name}: Profile root directory not present for current user"
        else:
            db_files = sorted(list(root.glob(f"*/{db_filename}")) + list(root.glob(db_filename)))
            if not db_files:
                status = "not_found"
                error_msg = f"{name}: No {db_filename} databases found under {root}"
            else:
                total_size = sum((f.stat().st_size for f in db_files if f.is_file()), 0)
                for f in db_files:
                    _, m = stat_info(f)
                    if m and (latest_mod is None or m > latest_mod):
                        latest_mod = m

                def _all_profiles_gen() -> Iterator[dict[str, Any]]:
                    per_prof = max(150, max_records_per_browser // max(1, len(db_files)))
                    for db_f in db_files:
                        prof = db_f.parent.name
                        if b_code in ("chrome", "edge"):
                            yield from extract_chromium_sqlite_records(db_f, b_code, prof, per_prof)
                        else:
                            yield from extract_firefox_sqlite_records(db_f, prof, per_prof)

                try:
                    record_count, records_sha256, _ = write_ndjson_records(ndjson_path, _all_profiles_gen())
                    # Copy primary profile SQLite db as faithful original in full scan (or if <= 35MB in quick scan)
                    primary_db = db_files[0]
                    if primary_db.stat().st_size <= (100 * 1024 * 1024 if scan_type == "full" else 35 * 1024 * 1024):
                        target_orig = originals_dir / f"{safe_stem}_{primary_db.parent.name}_{db_filename}"
                        try:
                            shutil.copy2(primary_db, target_orig)
                            original_copy = target_orig
                            orig_sha256 = sha256_file(target_orig)
                        except OSError:
                            pass
                except Exception as exc:
                    status = "error"
                    error_msg = f"{name} extraction failed: {str(exc)[:180]}"
                    if ndjson_path.exists():
                        ndjson_path.unlink(missing_ok=True)

        meta = {
            "artifact_key": artifact_key,
            "source": "browser",
            "name": name,
            "original_path": str(root),
            "status": status,
            "acquisition_method": "Snapshot SQLite copy + read-only sqlite3 URI query (credentials/cookies excluded)",
            "sha256": orig_sha256,
            "records_sha256": records_sha256,
            "size_bytes": total_size,
            "last_modified": latest_mod,
            "collected_at": utc_now_iso(),
            "collector_version": __version__,
            "record_count": record_count,
            "parser": "sqlite3",
            "side_effects": [
                "Temporary snapshot copy in system temp directory during read; source browser DB unmodified",
                "Cookies, Login Data, and saved credentials intentionally excluded",
            ],
            "error": error_msg,
            "time_window": None,
        }
        results.append(
            {
                "meta": meta,
                "records_path": str(ndjson_path) if (status == "collected" and ndjson_path.is_file()) else None,
                "original_path": str(original_copy) if original_copy else None,
            }
        )
    return results
