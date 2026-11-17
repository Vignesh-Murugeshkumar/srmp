"""FastAPI application entrypoint for TraceVault."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from . import __version__
from .api.routes import api_router, ws_router
from .auth import hash_password
from .config import settings
from .db import Base, SessionLocal, engine
from .models import UserModel, new_uuid, utc_now_str

logger = logging.getLogger("tracevault")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def bootstrap_database() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin = db.scalar(select(UserModel).where(UserModel.username == settings.admin_username))
        if not admin:
            if settings.admin_password == "tracevault-admin":
                logger.warning(
                    "Bootstrapping default dev admin account '%s'. Set TRACEVAULT_ADMIN_PASSWORD in production.",
                    settings.admin_username,
                )
            db.add(
                UserModel(
                    id=new_uuid(),
                    username=settings.admin_username,
                    password_hash=hash_password(settings.admin_password),
                    role="admin",
                    created_at=utc_now_str(),
                )
            )
            db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap_database()
    yield


app = FastAPI(
    title="TraceVault Forensic Reconstruction API",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(ws_router)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
