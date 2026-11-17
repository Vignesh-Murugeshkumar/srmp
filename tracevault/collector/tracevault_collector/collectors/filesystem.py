"""File System forensic collector: Recycle Bin ($I), User files metadata, USN Journal, and $MFT (CONTRACT §4 & Spec §5.10)."""

from __future__ import annotations

import csv
import io
import os
import struct
import subprocess
from pathlib import Path
from typing import Any, Iterator

from .. import __version__
from ..identity import is_process_elevated
from ..utils import (
    filetime_to_iso,
    safe_artifact_filename,
    sha256_file,
    stat_info,
    unix_ts_to_iso,
    utc_now_iso,
    write_ndjson_records,
)


def parse_recycle_bin_i_bytes(data: bytes, i_file_path: str = "$I000000") -> dict[str, Any] | None:
    """Parse a Windows Vista/7/8/10/11 Recycle Bin $I metadata binary buffer.

    Version 1 (Vista/Win7/Win8):
      0..8   : int64 version == 1
      8..16  : int64 original file size
      16..24 : int64 deleted_time FILETIME
      24..544: 520 bytes UTF-16LE null-terminated original path (260 WCHARs)

    Version 2 (Win10/Win11):
      0..8   : int64 version == 2
      8..16  : int64 original file size
      16..24 : int64 deleted_time FILETIME
      24..28 : uint32 character count (N)
      28..28+2N : UTF-16LE original path
    """
    if len(data) < 28:
        return None
    version, file_size, del_ft = struct.unpack_from("<QQQ", data, 0)
    if version == 1 and len(data) >= 26:
        raw_path = data[24:544]
        orig_path = raw_path.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    elif version == 2 and len(data) >= 28:
        (char_count,) = struct.unpack_from("<I", data, 24)
        byte_len = min(len(data) - 28, int(char_count) * 2)
        raw_path = data[28 : 28 + byte_len]
        orig_path = raw_path.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    else:
        return None

    return {
        "record_id": f"recyclebin:{Path(i_file_path).name}",
        "source": "filesystem",
        "kind": "recycle_bin",
        "path": i_file_path,
        "size": int(file_size),
        "created": None,
        "modified": None,
        "accessed": None,
        "mft_changed": None,
        "deleted_time": filetime_to_iso(del_ft),
        "timestamp_precision": "100ns",
        "original_path": orig_path,
        "usn_reason": None,
        "usn": None,
        "mft_entry": None,
        "mft_sequence": None,
        "sha256": None,
        "attributes": f"RecycleBin_v{version}",
    }


def _iter_recycle_bin_records() -> Iterator[dict[str, Any]]:
    rb_root = Path(r"C:\$Recycle.Bin")
    if not rb_root.exists():
        return
    try:
        sid_dirs = list(rb_root.iterdir())
    except OSError:
        return
    for sid_dir in sid_dirs:
        try:
            for i_file in sid_dir.glob("$I*"):
                if not i_file.is_file():
                    continue
                try:
                    raw = i_file.read_bytes()
                    parsed = parse_recycle_bin_i_bytes(raw, str(i_file))
                    if parsed:
                        r_candidate = i_file.with_name("$R" + i_file.name[2:])
                        if r_candidate.is_file() and r_candidate.stat().st_size <= 25 * 1024 * 1024:
                            parsed["sha256"] = sha256_file(r_candidate)
                        yield parsed
                except OSError:
                    continue
        except OSError:
            continue


INTERESTING_EXTENSIONS = {
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".hta",
    ".msi",
    ".scr",
    ".zip",
    ".7z",
    ".rar",
    ".iso",
    ".lnk",
    ".pf",
    ".sys",
    ".py",
}


def _iter_user_file_metadata(max_records: int = 400) -> Iterator[dict[str, Any]]:
    user_profile = os.environ.get("USERPROFILE", "")
    local_temp = os.environ.get("TEMP", "")
    scan_roots: list[tuple[Path, bool]] = []
    if user_profile:
        scan_roots.append((Path(user_profile) / "Downloads", True))
        scan_roots.append((Path(user_profile) / "Desktop", True))
    if local_temp:
        scan_roots.append((Path(local_temp), False))  # In %TEMP%, focus on executables/scripts

    emitted = 0
    for root, include_all in scan_roots:
        if not root.exists():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                # Limit recursion depth to keep scans fast and deterministic
                rel_depth = len(Path(dirpath).relative_to(root).parts)
                if rel_depth > 2:
                    dirnames[:] = []
                    continue
                for fname in filenames:
                    fpath = Path(dirpath) / fname
                    ext = fpath.suffix.lower()
                    if not include_all and ext not in INTERESTING_EXTENSIONS:
                        continue
                    try:
                        st = fpath.stat()
                        f_hash = None
                        if st.st_size <= 25 * 1024 * 1024 and (ext in INTERESTING_EXTENSIONS or include_all):
                            f_hash = sha256_file(fpath, max_bytes=25 * 1024 * 1024)
                        yield {
                            "record_id": f"file:{fpath}",
                            "source": "filesystem",
                            "kind": "file_metadata",
                            "path": str(fpath),
                            "size": int(st.st_size),
                            "created": unix_ts_to_iso(st.st_ctime),
                            "modified": unix_ts_to_iso(st.st_mtime),
                            "accessed": unix_ts_to_iso(st.st_atime),
                            "mft_changed": None,
                            "deleted_time": None,
                            "timestamp_precision": "100ns",
                            "original_path": None,
                            "usn_reason": None,
                            "usn": None,
                            "mft_entry": None,
                            "mft_sequence": None,
                            "sha256": f_hash,
                            "attributes": f"ext={ext or 'none'}",
                        }
                        emitted += 1
                        if emitted >= max_records:
                            return
                    except OSError:
                        continue
        except OSError:
            continue


def _iter_usn_journal_records(max_records: int = 500) -> Iterator[dict[str, Any]]:
    proc = subprocess.run(
        ["fsutil.exe", "usn", "readjournal", "C:", "csv"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=True,
    )
    emitted = 0
    reader = csv.reader(io.StringIO(proc.stdout))
    for row in reader:
        if len(row) < 6 or row[0].strip().lower() == "usn":
            continue
        try:
            usn_val = int(row[0].strip())
        except ValueError:
            continue
        fname = row[1].strip()
        reason_hex = row[3].strip()
        ts_str = row[5].strip()
        yield {
            "record_id": f"usn:{usn_val}",
            "source": "filesystem",
            "kind": "usn",
            "path": fname,
            "size": None,
            "created": None,
            "modified": ts_str if ts_str else None,
            "accessed": None,
            "mft_changed": ts_str if ts_str else None,
            "deleted_time": None,
            "timestamp_precision": "second",
            "original_path": None,
            "usn_reason": reason_hex,
            "usn": usn_val,
            "mft_entry": None,
            "mft_sequence": None,
            "sha256": None,
            "attributes": None,
        }
        emitted += 1
        if emitted >= max_records:
            return


def collect_filesystem(out_dir: Path, scan_type: str = "quick") -> list[dict[str, Any]]:
    """Collect Recycle Bin $I records, user file metadata, and (when elevated) USN Journal / MFT status."""
    records_dir = out_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    elevated = is_process_elevated()

    # 1. Recycle Bin
    rb_key = "filesystem:RecycleBin"
    rb_ndjson = records_dir / f"{safe_artifact_filename(rb_key)}.ndjson"
    rb_count, rb_sha, rb_sz = write_ndjson_records(rb_ndjson, _iter_recycle_bin_records())
    results.append(
        {
            "meta": {
                "artifact_key": rb_key,
                "source": "filesystem",
                "name": "Recycle Bin Deletion Metadata ($I records)",
                "original_path": r"C:\$Recycle.Bin",
                "status": "collected",
                "acquisition_method": "Binary $I v1/v2 header parser",
                "sha256": None,
                "records_sha256": rb_sha,
                "size_bytes": rb_sz,
                "last_modified": None,
                "collected_at": utc_now_iso(),
                "collector_version": __version__,
                "record_count": rb_count,
                "parser": "recyclebin-$I",
                "side_effects": ["Read-only inspection of $Recycle.Bin SID folders"],
                "error": None,
                "time_window": None,
            },
            "records_path": str(rb_ndjson) if rb_ndjson.is_file() else None,
            "original_path": None,
        }
    )

    # 2. User Files (Downloads, Desktop, Temp)
    uf_key = "filesystem:UserFiles"
    uf_ndjson = records_dir / f"{safe_artifact_filename(uf_key)}.ndjson"
    max_uf = 250 if scan_type == "quick" else 800
    uf_count, uf_sha, uf_sz = write_ndjson_records(uf_ndjson, _iter_user_file_metadata(max_uf))
    user_dl = os.path.join(os.environ.get("USERPROFILE", r"C:\Users"), "Downloads")
    results.append(
        {
            "meta": {
                "artifact_key": uf_key,
                "source": "filesystem",
                "name": "User Downloads, Desktop & Temp File Metadata",
                "original_path": user_dl,
                "status": "collected",
                "acquisition_method": "Read-only os.stat + SHA-256 file hashing",
                "sha256": None,
                "records_sha256": uf_sha,
                "size_bytes": uf_sz,
                "last_modified": None,
                "collected_at": utc_now_iso(),
                "collector_version": __version__,
                "record_count": uf_count,
                "parser": "fs-stat",
                "side_effects": ["Read-only file stat and SHA-256 calculation; timestamps preserved in metadata"],
                "error": None,
                "time_window": None,
            },
            "records_path": str(uf_ndjson) if uf_ndjson.is_file() else None,
            "original_path": None,
        }
    )

    # 3. USN Journal
    usn_key = "filesystem:USNJournal"
    usn_ndjson = records_dir / f"{safe_artifact_filename(usn_key)}.ndjson"
    usn_status = "permission_denied"
    usn_err: str | None = "USN Journal requires Administrator elevation"
    usn_count = 0
    usn_sha = None
    usn_sz = 0
    if elevated:
        try:
            usn_count, usn_sha, usn_sz = write_ndjson_records(usn_ndjson, _iter_usn_journal_records(500))
            usn_status = "collected"
            usn_err = None
        except Exception as exc:
            usn_status = "error"
            usn_err = f"fsutil usn readjournal failed: {str(exc)[:180]}"
            if usn_ndjson.exists():
                usn_ndjson.unlink(missing_ok=True)
    results.append(
        {
            "meta": {
                "artifact_key": usn_key,
                "source": "filesystem",
                "name": "NTFS Change Journal ($UsnJrnl:$J)",
                "original_path": r"\\.\C:\$Extend\$UsnJrnl:$J",
                "status": usn_status,
                "acquisition_method": "fsutil usn readjournal C: csv",
                "sha256": None,
                "records_sha256": usn_sha,
                "size_bytes": usn_sz,
                "last_modified": None,
                "collected_at": utc_now_iso(),
                "collector_version": __version__,
                "record_count": usn_count,
                "parser": "usn-fsutil",
                "side_effects": ["Read-only journal query when elevated"],
                "error": usn_err,
                "time_window": None,
            },
            "records_path": str(usn_ndjson) if (usn_status == "collected" and usn_ndjson.is_file()) else None,
            "original_path": None,
        }
    )

    # 4. NTFS $MFT
    mft_key = "filesystem:MFT"
    mft_status = "permission_denied" if not elevated else "unsupported"
    mft_err = (
        "Raw volume read of \\\\.\\C:\\$MFT requires Administrator elevation"
        if not elevated
        else "Raw $MFT extraction requires external MFTECmd.exe in TRACEVAULT_EZTOOLS_DIR"
    )
    results.append(
        {
            "meta": {
                "artifact_key": mft_key,
                "source": "filesystem",
                "name": "NTFS Master File Table ($MFT)",
                "original_path": r"\\.\C:\$MFT",
                "status": mft_status,
                "acquisition_method": "Raw volume handle check (\\\\.\\C:)",
                "sha256": None,
                "records_sha256": None,
                "size_bytes": None,
                "last_modified": None,
                "collected_at": utc_now_iso(),
                "collector_version": __version__,
                "record_count": 0,
                "parser": "mft-inspector",
                "side_effects": ["No raw volume lock acquired"],
                "error": mft_err,
                "time_window": None,
            },
            "records_path": None,
            "original_path": None,
        }
    )

    return results
