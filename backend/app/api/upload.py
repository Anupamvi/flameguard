import logging
import zlib
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session, get_db
from app.schemas.audit import TextUploadRequest, UploadResponse
from app.security import acquire_audit_job_slot, enforce_upload_content_length, upload_rate_limit
from app.services.audit_service import run_audit_pipeline, upload_and_parse

logger = logging.getLogger(__name__)

router = APIRouter()

SUPPORTED_UPLOAD_EXTENSIONS = {".json", ".csv"}
SUPPORTED_UPLOAD_CONTENT_TYPES = {
    "application/json",
    "text/json",
    "text/csv",
    "application/csv",
    "application/vnd.ms-excel",
    "text/plain",
    "application/octet-stream",
    "application/gzip",
    "application/x-gzip",
}
_UPLOAD_CHUNK_SIZE_BYTES = 1024 * 1024


def _max_upload_bytes() -> int:
    return settings.upload_max_size_mb * 1024 * 1024


async def run_audit_background(audit_id: str, ruleset_id: str) -> None:
    """Background task: open a fresh DB session and run the LLM audit pipeline."""
    try:
        async with acquire_audit_job_slot():
            async with async_session() as db:
                await run_audit_pipeline(audit_id=audit_id, ruleset_id=ruleset_id, db=db)
    except Exception:
        logger.exception("Background audit failed for audit_id=%s", audit_id)


def _validate_upload_metadata(filename: str, content_type: str | None = None) -> None:
    extension = Path(_normalize_upload_filename(filename)).suffix.lower()
    if extension not in SUPPORTED_UPLOAD_EXTENSIONS:
        raise HTTPException(400, "Only JSON files and supported Azure WAF CSV log exports are accepted")
    if content_type and content_type not in SUPPORTED_UPLOAD_CONTENT_TYPES:
        raise HTTPException(400, "Only JSON files and supported Azure WAF CSV log exports are accepted")


def _normalize_upload_filename(filename: str) -> str:
    path = Path(filename)
    suffixes = [suffix.lower() for suffix in path.suffixes]

    if len(suffixes) >= 2 and suffixes[-1] == ".gz" and suffixes[-2] in SUPPORTED_UPLOAD_EXTENSIONS:
        return str(path.with_suffix(""))

    return filename


def _upload_too_large() -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=f"File too large. Maximum size: {settings.upload_max_size_mb}MB",
    )


async def _read_plain_upload_content(file: UploadFile) -> bytes:
    max_upload_bytes = _max_upload_bytes()
    content = bytearray()

    while True:
        chunk = await file.read(_UPLOAD_CHUNK_SIZE_BYTES)
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > max_upload_bytes:
            raise _upload_too_large()

    return bytes(content)


async def _read_gzip_upload_content(file: UploadFile) -> bytes:
    max_upload_bytes = _max_upload_bytes()
    compressed_bytes = 0
    content = bytearray()
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)

    try:
        while True:
            chunk = await file.read(_UPLOAD_CHUNK_SIZE_BYTES)
            if not chunk:
                break

            compressed_bytes += len(chunk)
            if compressed_bytes > max_upload_bytes:
                raise _upload_too_large()

            remaining = max_upload_bytes - len(content)
            decoded = decompressor.decompress(chunk, remaining + 1)
            content.extend(decoded)
            if len(content) > max_upload_bytes or decompressor.unconsumed_tail:
                raise _upload_too_large()

        if not decompressor.eof:
            raise HTTPException(status_code=400, detail="Unable to decompress gzip upload")

        remaining = max_upload_bytes - len(content)
        flushed = decompressor.flush(remaining + 1)
        content.extend(flushed)
        if len(content) > max_upload_bytes:
            raise _upload_too_large()
    except zlib.error as exc:
        raise HTTPException(status_code=400, detail="Unable to decompress gzip upload") from exc

    return bytes(content)


async def _decode_upload_content(file: UploadFile, filename: str) -> str:
    if _normalize_upload_filename(filename) != filename:
        content = await _read_gzip_upload_content(file)
    else:
        content = await _read_plain_upload_content(file)

    return content.decode("utf-8-sig", errors="replace")


async def _store_upload(
    raw_content: str,
    filename: str,
    vendor_hint: str | None,
    background_tasks: BackgroundTasks,
    db: AsyncSession,
) -> UploadResponse:
    try:
        ruleset, audit, warnings = await upload_and_parse(
            raw_content=raw_content,
            filename=filename,
            vendor_hint=vendor_hint,
            db=db,
        )
    except ValueError as e:
        logger.warning("Upload parse error: %s", e)
        raise HTTPException(
            400,
            str(e)
            or "Unable to parse the uploaded file. Ensure it is a valid Azure Firewall, NSG, or WAF JSON export, or a supported Azure WAF CSV log export.",
        )

    background_tasks.add_task(run_audit_background, audit.id, ruleset.id)

    return UploadResponse(
        ruleset_id=ruleset.id,
        audit_id=audit.id,
        status=audit.status,
        rule_count=ruleset.rule_count,
        vendor=ruleset.vendor,
        parse_warnings=warnings,
    )


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=201,
    dependencies=[Depends(enforce_upload_content_length), Depends(upload_rate_limit)],
)
async def upload_ruleset(
    file: UploadFile = File(...),
    vendor_hint: str | None = Query(None, description="Optional vendor hint: azure_firewall, azure_nsg, azure_waf"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
) -> UploadResponse:
    """Upload a firewall config file, parse it, and kick off the audit pipeline."""

    filename = file.filename or "unknown"
    _validate_upload_metadata(filename, file.content_type)
    normalized_filename = _normalize_upload_filename(filename)
    raw = await _decode_upload_content(file, filename)

    return await _store_upload(
        raw_content=raw,
        filename=normalized_filename,
        vendor_hint=vendor_hint,
        background_tasks=background_tasks,
        db=db,
    )


@router.post(
    "/upload/text",
    response_model=UploadResponse,
    status_code=201,
    dependencies=[Depends(enforce_upload_content_length), Depends(upload_rate_limit)],
)
async def upload_ruleset_text(
    request: TextUploadRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> UploadResponse:
    """Upload a text-based firewall config payload for browser clients."""

    filename = request.filename or "unknown"
    _validate_upload_metadata(filename, "application/json")

    content_bytes = request.content.encode("utf-8")
    if len(content_bytes) > _max_upload_bytes():
        raise _upload_too_large()

    return await _store_upload(
        raw_content=request.content,
        filename=filename,
        vendor_hint=request.vendor_hint,
        background_tasks=background_tasks,
        db=db,
    )
