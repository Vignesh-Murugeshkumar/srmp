"""Windows Amcache collector (CONTRACT §4 & Spec §5.8).

Clearly distinguishes application inventory from proof of execution.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from .. import __version__
from ..identity import is_process_elevated
from ..utils import safe_artifact_filename, stat_info, utc_now_iso, write_ndjson_records


def _find_amcache_parser() -> str | None:
    ez_dir = os.environ.get("TRACEVAULT_EZTOOLS_DIR")
    if ez_dir:
        candidate = Path(ez_dir) / "AmcacheParser.exe"
        if candidate.is_file():
            return str(candidate)
    return shutil.which("AmcacheParser.exe") or shutil.which("AmcacheParser")


def _iter_amcache_csv_records(csv_dir: Path, max_records: int = 2000) -> Iterator[dict[str, Any]]:
    emitted = 0
    for csv_file in sorted(csv_dir.glob("*.csv")):
        with csv_file.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                full_path = row.get("FullPath") or row.get("LowerCaseLongPath") or row.get("Name")
                sha1 = row.get("SHA1")
                prog_id = row.get("ProgramId") or row.get("FileKeyLastWriteTimestamp")
                yield {
                    "record_id": f"amcache:{full_path or emitted}",
                    "source": "amcache",
                    "record_type": "InventoryApplicationFile",
                    "program_path": full_path,
                    "name": row.get("Name") or (Path(full_path).name if full_path else None),
                    "sha1": sha1.lower() if sha1 else None,
                    "publisher": row.get("Publisher"),
                    "version": row.get("Version"),
                    "size": int(row["Size"]) if (row.get("Size") and str(row["Size"]).isdigit()) else None,
                    "link_date": row.get("LinkDate"),
                    "key_last_write": row.get("FileKeyLastWriteTimestamp"),
                    "timestamp_precision": "100ns",
                    "program_id": prog_id,
                }
                emitted += 1
                if emitted >= max_records:
                    return


def collect_amcache(out_dir: Path, scan_type: str = "quick") -> list[dict[str, Any]]:
    """Collect Amcache.hve inventory records or report honest permission_denied/locked status."""
    am_path = Path(r"C:\Windows\appcompat\Programs\Amcache.hve")
    records_dir = out_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    artifact_key = "amcache:AmcacheHve"
    safe_stem = safe_artifact_filename(artifact_key)
    ndjson_path = records_dir / f"{safe_stem}.ndjson"

    parser_bin = _find_amcache_parser()
    size_bytes, last_mod = stat_info(am_path)
    status = "permission_denied"
    error_msg: str | None = None
    record_count = 0
    records_sha256: str | None = None

    try:
        am_exists = am_path.exists()
    except PermissionError:
        am_exists = True

    if not am_exists:
        status = "not_found"
        error_msg = "Amcache.hve not found at C:\\Windows\\appcompat\\Programs\\Amcache.hve"
    elif not is_process_elevated():
        status = "permission_denied"
        error_msg = "Amcache.hve is locked by the Windows kernel and requires Administrator elevation"
    elif parser_bin:
        with tempfile.TemporaryDirectory(prefix="tv_amcache_") as tmp:
            try:
                subprocess.run(
                    [parser_bin, "-f", str(am_path), "--csv", tmp, "-i"],
                    check=True,
                    capture_output=True,
                    timeout=90,
                )
                record_count, records_sha256, _ = write_ndjson_records(
                    ndjson_path,
                    _iter_amcache_csv_records(Path(tmp)),
                )
                status = "collected"
            except Exception as exc:
                status = "error"
                error_msg = f"AmcacheParser error: {str(exc)[:180]}"
    else:
        status = "unsupported"
        error_msg = "Amcache.hve is locked by the OS; configure TRACEVAULT_EZTOOLS_DIR with AmcacheParser.exe for live hive parsing"

    meta = {
        "artifact_key": artifact_key,
        "source": "amcache",
        "name": "Amcache Application Inventory (Amcache.hve)",
        "original_path": str(am_path),
        "status": status,
        "acquisition_method": "AmcacheParser CLI" if parser_bin else "Direct hive inspection check",
        "sha256": None,
        "records_sha256": records_sha256,
        "size_bytes": size_bytes,
        "last_modified": last_mod,
        "collected_at": utc_now_iso(),
        "collector_version": __version__,
        "record_count": record_count,
        "parser": "AmcacheParser",
        "side_effects": ["Read-only inspection; Amcache records represent inventory, not proof of execution"],
        "error": error_msg,
        "time_window": None,
    }
    return [
        {
            "meta": meta,
            "records_path": str(ndjson_path) if (status == "collected" and ndjson_path.is_file()) else None,
            "original_path": None,
        }
    ]
