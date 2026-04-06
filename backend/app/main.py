import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import async_session, engine, init_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    # Ensure tables exist then auto-seed demo data
    from app.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Lightweight migration: add columns that create_all won't add to existing tables
    async with engine.begin() as conn:
        import sqlalchemy as sa
        try:
            await conn.execute(sa.text(
                "ALTER TABLE audit_findings ADD COLUMN source VARCHAR(20) DEFAULT 'llm'"
            ))
            logger.info("Migration: added 'source' column to audit_findings")
        except Exception:
            pass  # column already exists

    from app.seed_demo import seed_demo
    async with async_session() as db:
        result = await seed_demo(db)
        logger.info("Demo seed: %s", result.get("status", "unknown"))

    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="FlameGuard",
        description="LLM-powered firewall rule auditor and policy generator",
        version="0.1.0",
        lifespan=lifespan,
        debug=False,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type"],
    )

    from app.api import audit, chat, compliance, generate, rules, seed, upload

    app.include_router(upload.router, prefix="/api/v1", tags=["upload"])
    app.include_router(audit.router, prefix="/api/v1", tags=["audit"])
    app.include_router(rules.router, prefix="/api/v1", tags=["rules"])
    app.include_router(compliance.router, prefix="/api/v1", tags=["compliance"])
    app.include_router(generate.router, prefix="/api/v1", tags=["generate"])
    app.include_router(chat.router, prefix="/api/v1", tags=["chat"])
    app.include_router(seed.router, prefix="/api/v1", tags=["seed"])

    return app


app = create_app()
