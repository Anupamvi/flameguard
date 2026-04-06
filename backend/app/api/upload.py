import logging

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session, get_db
from app.schemas.audit import UploadResponse
from app.services.audit_service import run_audit_pipeline, upload_and_parse

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_UPLOAD_BYTES = settings.upload_max_size_mb * 1024 * 1024


async def run_audit_background(audit_id: str, ruleset_id: str) -> None:
    """Background task: open a fresh DB session and run the LLM audit pipeline."""
    try:
        async with async_session() as db:
            await run_audit_pipeline(audit_id=audit_id, ruleset_id=ruleset_id, db=db)
    except Exception:
        logger.exception("Background audit failed for audit_id=%s", audit_id)


@router.post("/upload", response_model=UploadResponse, status_code=201)
async def upload_ruleset(
    file: UploadFile = File(...),
    vendor_hint: str | None = Query(None, description="Optional vendor hint: azure_firewall, azure_nsg, azure_waf"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
) -> UploadResponse:
    """Upload a firewall config file, parse it, and kick off the audit pipeline."""

    # --- Validate file type ---
    filename = file.filename or "unknown"
    if not filename.lower().endswith(".json"):
        raise HTTPException(400, "Only JSON files are accepted")
    if file.content_type and file.content_type not in (
        "application/json",
        "text/json",
        "application/octet-stream",
    ):
        raise HTTPException(400, "Only JSON files are accepted")

    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(400, f"File too large. Maximum size: {settings.upload_max_size_mb}MB")

    raw = content.decode("utf-8-sig", errors="replace")

    try:
        ruleset, audit, warnings = await upload_and_parse(
            raw_content=raw,
            filename=file.filename or "unknown.json",
            vendor_hint=vendor_hint,
            db=db,
        )
    except ValueError as e:
        logger.warning("Upload parse error: %s", e)
        raise HTTPException(400, "Unable to parse the uploaded file. Ensure it is a valid Azure firewall export.")

    # Kick off LLM audit in background
    background_tasks.add_task(run_audit_background, audit.id, ruleset.id)

    return UploadResponse(
        ruleset_id=ruleset.id,
        audit_id=audit.id,
        status=audit.status,
        rule_count=ruleset.rule_count,
        vendor=ruleset.vendor,
        parse_warnings=warnings,
    )
