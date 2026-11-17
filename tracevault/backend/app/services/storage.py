"""Content-addressed evidence store with path-traversal protection and SHA-256 verification."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Tuple

from ..config import settings


def get_evidence_root() -> Path:
    root = Path(settings.evidence_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def store_stream_content_addressed(
    stream: BinaryIO,
    max_bytes: int | None = None,
) -> Tuple[str, int, str]:
    """Stream bytes to a temporary file, compute SHA-256, and move to `root/sha256[:2]/sha256`.

    Returns (sha256_hex, size_bytes, relative_storage_ref).
    Never trusts client-supplied filenames.
    """
    limit = max_bytes or settings.max_upload_bytes
    root = get_evidence_root()
    tmp_dir = root / "_staging"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    size = 0
    tmp_file = tmp_dir / f"upload_{id(stream)}.part"
    try:
        with tmp_file.open("wb") as out:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError(f"Upload exceeds maximum allowed size of {limit} bytes")
                hasher.update(chunk)
                out.write(chunk)
        digest = hasher.hexdigest()
        shard_dir = (root / digest[:2]).resolve()
        # Path traversal guard
        if not str(shard_dir).startswith(str(root)):
            raise ValueError("Invalid storage shard path")
        shard_dir.mkdir(parents=True, exist_ok=True)
        final_path = shard_dir / digest
        if not final_path.exists():
            tmp_file.replace(final_path)
        else:
            tmp_file.unlink(missing_ok=True)
        rel_ref = f"{digest[:2]}/{digest}"
        return digest, size, rel_ref
    finally:
        if tmp_file.exists():
            tmp_file.unlink(missing_ok=True)


def resolve_storage_ref(storage_ref: str) -> Path:
    """Safely resolve a relative content-addressed reference inside the evidence store."""
    root = get_evidence_root()
    candidate = (root / storage_ref).resolve()
    if not str(candidate).startswith(str(root)):
        raise ValueError("Path traversal attempt blocked")
    return candidate
