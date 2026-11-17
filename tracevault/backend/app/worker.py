"""Celery background worker configuration for TraceVault."""

from __future__ import annotations

from celery import Celery

from .config import settings
from .services.pipeline import run_processing_in_background

celery_app = Celery("tracevault", broker=settings.redis_url, backend=settings.redis_url)


@celery_app.task(name="tracevault.process_scan")
def process_scan_task(scan_id: str) -> None:
    run_processing_in_background(scan_id)
