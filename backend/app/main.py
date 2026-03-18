from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
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
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from app.api import audit, chat, compliance, generate, rules, upload

    app.include_router(upload.router, prefix="/api/v1", tags=["upload"])
    app.include_router(audit.router, prefix="/api/v1", tags=["audit"])
    app.include_router(rules.router, prefix="/api/v1", tags=["rules"])
    app.include_router(compliance.router, prefix="/api/v1", tags=["compliance"])
    app.include_router(generate.router, prefix="/api/v1", tags=["generate"])
    app.include_router(chat.router, prefix="/api/v1", tags=["chat"])

    return app


app = create_app()
