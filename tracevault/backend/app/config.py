"""Configuration settings for TraceVault backend."""

from __future__ import annotations

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACEVAULT_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./tracevault.db"
    secret_key: str = "tracevault-dev-secret-key-change-in-production-9f8e7d6c5b4a"
    jwt_expire_minutes: int = 720
    admin_username: str = "admin"
    admin_password: str = "tracevault-admin"
    enrollment_key: str = "dev-enrollment-key"
    evidence_dir: str = str(Path(__file__).resolve().parent.parent / "evidence_store")
    max_upload_bytes: int = 200 * 1024 * 1024  # 200 MB
    task_mode: str = "inline"  # "inline" or "celery"
    redis_url: str = "redis://127.0.0.1:6379/0"
    correlation_window_seconds: int = 300  # 5 min proximity boost window
    graph_max_nodes: int = 250


settings = Settings()
