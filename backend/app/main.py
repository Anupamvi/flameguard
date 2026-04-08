import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import async_session, engine, init_db
from app.security import (
    ADMIN_TOKEN_HEADER,
    RATE_LIMIT_HEADER_LIMIT,
    RATE_LIMIT_HEADER_REMAINING,
    RATE_LIMIT_HEADER_RESET,
    apply_api_security_headers,
)

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
    from app.privacy_backfill import backfill_privacy_redactions
    async with async_session() as db:
        result = await seed_demo(db)
        logger.info("Demo seed: %s", result.get("status", "unknown"))
        backfill_result = await backfill_privacy_redactions(db)
        logger.info("Privacy backfill: %s", backfill_result)

    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="FlameGuard",
        description="LLM-powered network security configuration and log auditor with policy generation",
        version="0.1.0",
        lifespan=lifespan,
        debug=False,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.parsed_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", ADMIN_TOKEN_HEADER],
        expose_headers=[RATE_LIMIT_HEADER_LIMIT, RATE_LIMIT_HEADER_REMAINING, RATE_LIMIT_HEADER_RESET, "Retry-After"],
    )

    @app.middleware("http")
    async def security_headers_middleware(request, call_next):
        response = await call_next(request)
        apply_api_security_headers(request, response)
        return response

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
