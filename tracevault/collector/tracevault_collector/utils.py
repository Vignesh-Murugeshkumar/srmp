"""Deterministic hashing, timestamp conversion, and safe NDJSON writer utilities."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Tuple

EPOCH_FILETIME = datetime(1601, 1, 1, tzinfo=timezone.utc)
EPOCH_UNIX = datetime(1970, 1, 1, tzinfo=timezone.utc)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def filetime_to_iso(ft: int | None) -> str | None:
    """Convert Windows 100-ns FILETIME since 1601-01-01 UTC to ISO-8601 UTC."""
    if not ft or ft <= 0:
        return None
    try:
        dt = EPOCH_FILETIME + timedelta(microseconds=ft / 10.0)
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt.isoformat()
    except (OverflowError, ValueError):
        return None


def webkit_to_iso(us: int | None) -> str | None:
    """Convert Chromium WebKit microseconds since 1601-01-01 UTC to ISO-8601 UTC."""
    if not us or us <= 0:
        return None
    try:
        dt = EPOCH_FILETIME + timedelta(microseconds=int(us))
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt.isoformat()
    except (OverflowError, ValueError):
        return None


def prtime_to_iso(us: int | None) -> str | None:
    """Convert Mozilla PRTime microseconds since 1970-01-01 UTC to ISO-8601 UTC."""
    if not us or us <= 0:
        return None
    try:
        dt = EPOCH_UNIX + timedelta(microseconds=int(us))
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt.isoformat()
    except (OverflowError, ValueError):
        return None


def unix_ts_to_iso(ts: float | int | None) -> str | None:
    if ts is None or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def sha256_file(path: str | Path, max_bytes: int | None = None) -> str | None:
    """Compute SHA-256 hex digest of a file without loading into memory."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        if max_bytes is not None and p.stat().st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_artifact_filename(artifact_key: str) -> str:
    """Convert 'evtx:Security' into a safe filename stem."""
    cleaned = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in artifact_key)
    return cleaned.strip("_") or "artifact"


def write_ndjson_records(path: str | Path, records: Iterable[dict[str, Any]]) -> Tuple[int, str, int]:
    """Stream records to an NDJSON file and return (count, sha256_hex, size_bytes)."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    count = 0
    size = 0
    with dest.open("wb") as f:
        for rec in records:
            line = (json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str) + "\n").encode("utf-8")
            f.write(line)
            h.update(line)
            count += 1
            size += len(line)
    return count, h.hexdigest(), size


def rot13(text: str) -> str:
    """Decode/encode ROT13 used by Windows UserAssist registry value names."""
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(((o - 65 + 13) % 26) + 65))
        elif 97 <= o <= 122:
            out.append(chr(((o - 97 + 13) % 26) + 97))
        else:
            out.append(ch)
    return "".join(out)


def stat_info(path: str | Path) -> Tuple[int | None, str | None]:
    """Return (size_bytes, last_modified_iso) for a path if accessible."""
    try:
        st = os.stat(path)
        return st.st_size, unix_ts_to_iso(st.st_mtime)
    except OSError:
        return None, None
