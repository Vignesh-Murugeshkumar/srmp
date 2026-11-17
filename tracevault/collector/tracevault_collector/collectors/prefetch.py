"""Windows Prefetch collector and parser (CONTRACT §4 & Spec §5.7).

Uses Eric Zimmerman's PECmd.exe if available on PATH or TRACEVAULT_EZTOOLS_DIR;
otherwise falls back to honest metadata-only inspection (without fabricating run_count).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from .. import __version__
from ..utils import safe_artifact_filename, sha256_file, stat_info, unix_ts_to_iso, utc_now_iso, write_ndjson_records


def _find_pecmd() -> str | None:
    ez_dir = os.environ.get("TRACEVAULT_EZTOOLS_DIR")
    if ez_dir:
        candidate = Path(ez_dir) / "PECmd.exe"
        if candidate.is_file():
            return str(candidate)
    return shutil.which("PECmd.exe") or shutil.which("PECmd")


def parse_prefetch_filename(filename: str) -> tuple[str, str | None]:
    """Parse 'CMD.EXE-4A81B364.pf' into ('CMD.EXE', '4A81B364')."""
    stem = filename[:-3] if filename.lower().endswith(".pf") else filename
    if "-" in stem:
        exe_part, hash_part = stem.rsplit("-", 1)
        return exe_part, hash_part.upper()
    return stem, None


def _iter_prefetch_records(pf_files: list[Path], pecmd_bin: str | None) -> Iterator[dict[str, Any]]:
    if pecmd_bin:
        with tempfile.TemporaryDirectory(prefix="tv_pecmd_") as tmp:
            try:
                subprocess.run(
                    [pecmd_bin, "-d", r"C:\Windows\Prefetch", "--json", tmp, "--jsonf", "pecmd.json", "-q"],
                    check=True,
                    capture_output=True,
                    timeout=60,
                )
                json_file = Path(tmp) / "pecmd.json"
                if json_file.is_file():
                    with json_file.open("r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            row = json.loads(line)
                            exe = row.get("ExecutableName") or ""
                            pf_hash = row.get("Hash")
                            pf_path = row.get("SourceFilename") or f"C:\\Windows\\Prefetch\\{exe}-{pf_hash}.pf"
                            files_str = row.get("FilesLoaded") or ""
                            dirs_str = row.get("DirectoriesReferenced") or ""
                            last_runs = [
                                row[k]
                                for k in ("LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2")
                                if row.get(k)
                            ]
                            yield {
                                "record_id": f"prefetch:{Path(pf_path).name}",
                                "source": "prefetch",
                                "executable": exe,
                                "prefetch_hash": pf_hash,
                                "pf_path": pf_path,
                                "pf_created": row.get("SourceCreated"),
                                "pf_modified": row.get("SourceModified"),
                                "timestamp_precision": "100ns",
                                "run_count": int(row["RunCount"]) if row.get("RunCount") is not None else None,
                                "last_run_times": last_runs,
                                "referenced_files": [x.strip() for x in files_str.split(",") if x.strip()],
                                "referenced_dirs": [x.strip() for x in dirs_str.split(",") if x.strip()],
                                "volume_serials": [],
                                "parser": "PECmd",
                            }
                    return
            except Exception:
                pass

    # Fallback: metadata-only inspection (does not infer run counts beyond filesystem timestamps)
    for pf in pf_files:
        try:
            st = pf.stat()
            exe, pf_hash = parse_prefetch_filename(pf.name)
            yield {
                "record_id": f"prefetch:{pf.name}",
                "source": "prefetch",
                "executable": exe,
                "prefetch_hash": pf_hash,
                "pf_path": str(pf),
                "pf_created": unix_ts_to_iso(st.st_ctime),
                "pf_modified": unix_ts_to_iso(st.st_mtime),
                "timestamp_precision": "100ns",
                "run_count": None,
                "last_run_times": [],
                "referenced_files": [],
                "referenced_dirs": [],
                "volume_serials": [],
                "parser": "prefetch-metadata",
            }
        except OSError:
            continue


def collect_prefetch(out_dir: Path, scan_type: str = "quick") -> list[dict[str, Any]]:
    """Collect Windows Prefetch records or report honest permission_denied status."""
    pf_dir = Path(r"C:\Windows\Prefetch")
    records_dir = out_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    artifact_key = "prefetch:WindowsPrefetch"
    safe_stem = safe_artifact_filename(artifact_key)
    ndjson_path = records_dir / f"{safe_stem}.ndjson"

    pecmd_bin = _find_pecmd()
    parser_name = "PECmd" if pecmd_bin else "prefetch-metadata"
    status = "collected"
    error_msg: str | None = None
    record_count = 0
    records_sha256: str | None = None
    total_size, last_mod = stat_info(pf_dir)

    if not pf_dir.exists():
        status = "not_found"
        error_msg = "C:\\Windows\\Prefetch directory not present on this endpoint"
    else:
        try:
            # os.scandir raises PermissionError when non-elevated, whereas Path.glob swallows it
            with os.scandir(pf_dir) as it:
                pf_files = sorted(Path(entry.path) for entry in it if entry.name.lower().endswith(".pf"))
            total_size = sum((f.stat().st_size for f in pf_files if f.is_file()), 0)
            record_count, records_sha256, _ = write_ndjson_records(
                ndjson_path,
                _iter_prefetch_records(pf_files, pecmd_bin),
            )
        except PermissionError:
            status = "permission_denied"
            error_msg = "C:\\Windows\\Prefetch: Access is denied (requires Administrator elevation)"
            if ndjson_path.exists():
                ndjson_path.unlink(missing_ok=True)
        except OSError as exc:
            status = "error"
            error_msg = f"Prefetch access error: {exc}"
            if ndjson_path.exists():
                ndjson_path.unlink(missing_ok=True)

    meta = {
        "artifact_key": artifact_key,
        "source": "prefetch",
        "name": "Windows Prefetch (*.pf)",
        "original_path": str(pf_dir),
        "status": status,
        "acquisition_method": "PECmd execution" if pecmd_bin else "Read-only directory & file metadata scan",
        "sha256": None,
        "records_sha256": records_sha256,
        "size_bytes": total_size,
        "last_modified": last_mod,
        "collected_at": utc_now_iso(),
        "collector_version": __version__,
        "record_count": record_count,
        "parser": parser_name,
        "side_effects": ["Read-only inspection of C:\\Windows\\Prefetch"],
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
