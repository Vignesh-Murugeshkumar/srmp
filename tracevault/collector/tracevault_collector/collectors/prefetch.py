"""Windows Prefetch collector and parser (CONTRACT §4 & Spec §5.7).

Uses Eric Zimmerman's PECmd.exe if available on PATH or TRACEVAULT_EZTOOLS_DIR;
otherwise falls back to honest metadata-only inspection (without fabricating run_count).
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from .. import __version__
from ..utils import (
    filetime_to_iso,
    safe_artifact_filename,
    sha256_file,
    stat_info,
    unix_ts_to_iso,
    utc_now_iso,
    write_ndjson_records,
)


def decompress_mam_prefetch(raw: bytes) -> bytes | None:
    """Decompress a Windows 10/11 MAM-compressed .pf file using native ntdll.RtlDecompressBufferEx."""
    if len(raw) < 8 or raw[:3] != b"MAM":
        if len(raw) >= 8 and raw[4:8] == b"SCCA":
            return raw
        return None
    if os.name != "nt":
        return None
    uncompressed_size = struct.unpack_from("<I", raw, 4)[0]
    if uncompressed_size <= 0 or uncompressed_size > 32 * 1024 * 1024:
        return None
    # MAM header is 8 bytes (or 12 bytes if checksum flag 0x80 is set in byte 3)
    has_crc = bool(raw[3] & 0x80)
    header_len = 12 if has_crc else 8
    compressed_buf = raw[header_len:]
    try:
        ntdll = ctypes.windll.ntdll
        # COMPRESSION_FORMAT_XPRESS_HUFF = 4
        fmt = 4
        ws_buf_size = ctypes.c_ulong(0)
        frag_ws_size = ctypes.c_ulong(0)
        status = ntdll.RtlGetCompressionWorkSpaceSize(
            ctypes.c_ushort(fmt),
            ctypes.byref(ws_buf_size),
            ctypes.byref(frag_ws_size),
        )
        if status != 0:
            return None
        workspace = ctypes.create_string_buffer(ws_buf_size.value)
        out_buf = ctypes.create_string_buffer(uncompressed_size)
        final_size = ctypes.c_ulong(0)
        status = ntdll.RtlDecompressBufferEx(
            ctypes.c_ushort(fmt),
            out_buf,
            ctypes.c_ulong(uncompressed_size),
            ctypes.c_char_p(compressed_buf),
            ctypes.c_ulong(len(compressed_buf)),
            ctypes.byref(final_size),
            workspace,
        )
        if status == 0 and final_size.value > 0:
            return out_buf.raw[: final_size.value]
    except Exception:
        return None
    return None


def parse_scca_prefetch_bytes(data: bytes, pf_path: str) -> dict[str, Any] | None:
    """Parse an uncompressed SCCA Windows Prefetch buffer (versions 23, 26, 30 / Win8.1-Win11)."""
    buf = decompress_mam_prefetch(data) if data[:3] == b"MAM" else data
    if not buf or len(buf) < 0x100 or buf[4:8] != b"SCCA":
        return None

    version = struct.unpack_from("<I", buf, 0)[0]
    raw_exe = buf[16:76].decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    pf_hash = f"{struct.unpack_from('<I', buf, 76)[0]:08X}"

    # File metrics & filename strings table offsets inside SCCA header (offset 84)
    fn_strings_offset = struct.unpack_from("<I", buf, 100)[0]
    fn_strings_size = struct.unpack_from("<I", buf, 104)[0]

    # FileInformation block begins at offset 84; last_run_times (8 x FILETIME = 64 bytes) sits at offset 128 (0x80)
    last_run_times: list[str] = []
    for i in range(8):
        ft = struct.unpack_from("<Q", buf, 128 + i * 8)[0]
        iso = filetime_to_iso(ft)
        if iso:
            last_run_times.append(iso)

    # Run count in SCCA v30 (Win10/11) is at offset 208 (0xD0) or 204 (0xCC) depending on build; in v26 at 208
    run_count: int | None = None
    if version == 30 and len(buf) >= 216:
        rc_a = struct.unpack_from("<I", buf, 208)[0]
        rc_b = struct.unpack_from("<I", buf, 204)[0]
        if 0 < rc_a < 1000000:
            run_count = int(rc_a)
        elif 0 < rc_b < 1000000:
            run_count = int(rc_b)
    elif version in (23, 26) and len(buf) >= 212:
        rc = struct.unpack_from("<I", buf, 208)[0]
        if 0 < rc < 1000000:
            run_count = int(rc)

    referenced_files: list[str] = []
    if 0 < fn_strings_offset < len(buf) and fn_strings_size > 0:
        end_off = min(len(buf), fn_strings_offset + fn_strings_size)
        raw_strings = buf[fn_strings_offset:end_off].decode("utf-16-le", errors="replace")
        for s in raw_strings.split("\x00"):
            s_clean = s.strip()
            if s_clean:
                # Normalize \VOLUME{...}\ paths to C:\ when possible for cleaner correlation
                s_norm = re.sub(r"^\\VOLUME\{[^}]+\}\\", r"C:\\", s_clean, flags=re.IGNORECASE)
                s_norm = re.sub(r"^\\DEVICE\\HARDDISKVOLUME\d+\\", r"C:\\", s_norm, flags=re.IGNORECASE)
                referenced_files.append(s_norm)

    referenced_dirs = sorted({str(Path(f).parent) for f in referenced_files[:100] if "\\" in f})

    return {
        "record_id": f"prefetch:{Path(pf_path).name}",
        "source": "prefetch",
        "executable": raw_exe or parse_prefetch_filename(Path(pf_path).name)[0],
        "prefetch_hash": pf_hash,
        "pf_path": pf_path,
        "pf_created": None,
        "pf_modified": None,
        "timestamp_precision": "100ns",
        "run_count": run_count,
        "last_run_times": last_run_times,
        "referenced_files": referenced_files[:150],
        "referenced_dirs": referenced_dirs[:50],
        "volume_serials": [],
        "parser": "native-scca-mam",
    }


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

    # Native SCCA / MAM binary parser (parses run_count, 8 last_run_times, and referenced_files directly from .pf bytes)
    for pf in pf_files:
        try:
            st = pf.stat()
            raw_bytes = pf.read_bytes()
            parsed = parse_scca_prefetch_bytes(raw_bytes, str(pf))
            if parsed is not None:
                parsed["pf_created"] = unix_ts_to_iso(st.st_ctime)
                parsed["pf_modified"] = unix_ts_to_iso(st.st_mtime)
                yield parsed
                continue
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
