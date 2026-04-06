import json
import uuid
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.audit import AuditReport, AuditFinding
from app.models.rule import RuleSet
from app.schemas.audit import DeleteAuditsRequest, DeleteAuditsResponse, AuditRequest, AuditResponse, FindingOut

router = APIRouter()


def _validate_uuid(value: str, name: str = "ID") -> None:
    """Raise 400 if value is not a valid UUID."""
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        raise HTTPException(400, f"Invalid {name} format")


async def _delete_audit_records(audit_ids: list[str], db: AsyncSession) -> DeleteAuditsResponse:
    for aid in audit_ids:
        _validate_uuid(aid, "audit_id")
    result = await db.execute(
        select(AuditReport)
        .options(selectinload(AuditReport.findings))
        .options(selectinload(AuditReport.compliance_checks))
        .options(selectinload(AuditReport.chat_messages))
        .options(selectinload(AuditReport.ruleset))
        .where(AuditReport.id.in_(audit_ids))
    )
    reports = result.scalars().all()
    if not reports:
        raise HTTPException(status_code=404, detail="No matching audits found")

    found_ids = {report.id for report in reports}
    missing_ids = [audit_id for audit_id in audit_ids if audit_id not in found_ids]
    if missing_ids:
        raise HTTPException(status_code=404, detail=f"Audits not found: {', '.join(missing_ids)}")

    ruleset_ids = [report.ruleset_id for report in reports]
    counts_result = await db.execute(
        select(AuditReport.ruleset_id, func.count(AuditReport.id))
        .where(AuditReport.ruleset_id.in_(ruleset_ids))
        .group_by(AuditReport.ruleset_id)
    )
    total_reports_by_ruleset = {ruleset_id: count for ruleset_id, count in counts_result.all()}
    deleting_reports_by_ruleset = Counter(ruleset_ids)
    orphan_ruleset_ids = [
        ruleset_id
        for ruleset_id, delete_count in deleting_reports_by_ruleset.items()
        if total_reports_by_ruleset.get(ruleset_id, 0) == delete_count
    ]

    for report in reports:
        await db.delete(report)

    await db.flush()

    if orphan_ruleset_ids:
        rulesets_result = await db.execute(
            select(RuleSet)
            .options(selectinload(RuleSet.rules))
            .where(RuleSet.id.in_(orphan_ruleset_ids))
        )
        for ruleset in rulesets_result.scalars().all():
            await db.delete(ruleset)

    await db.commit()

    return DeleteAuditsResponse(
        deleted_audit_ids=audit_ids,
        deleted_ruleset_ids=orphan_ruleset_ids,
    )


def _report_to_response(report: AuditReport) -> AuditResponse:
    findings = []
    for f in report.findings:
        related = []
        if f.related_rule_ids:
            try:
                related = json.loads(f.related_rule_ids)
            except (json.JSONDecodeError, TypeError):
                related = []
        findings.append(FindingOut(
            id=f.id,
            severity=f.severity,
            category=f.category,
            title=f.title,
            description=f.description,
            recommendation=f.recommendation,
            confidence=f.confidence,
            affected_rule_ids=related,
        ))

    return AuditResponse(
        id=report.id,
        ruleset_id=report.ruleset_id,
        filename=report.ruleset.filename,
        vendor=report.ruleset.vendor,
        rule_count=report.ruleset.rule_count,
        status=report.status,
        summary=report.summary,
        error_message=report.error_message,
        findings=findings,
        total_findings=report.total_findings,
        critical_count=report.critical_count,
        high_count=report.high_count,
        medium_count=report.medium_count,
        low_count=report.low_count,
        created_at=report.created_at,
        completed_at=report.completed_at,
    )


@router.post("/audit", response_model=AuditResponse, status_code=201)
async def create_audit(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
) -> AuditResponse:
    """Create and run a new audit on an uploaded ruleset. (LLM pipeline in Phase 1.2)"""
    raise HTTPException(status_code=501, detail="LLM audit pipeline not implemented yet. Upload triggers a pending audit automatically.")


@router.get("/audit/{audit_id}", response_model=AuditResponse)
async def get_audit(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
) -> AuditResponse:
    """Retrieve audit results by ID."""
    _validate_uuid(audit_id, "audit_id")
    result = await db.execute(
        select(AuditReport)
        .options(selectinload(AuditReport.findings))
        .options(selectinload(AuditReport.ruleset))
        .where(AuditReport.id == audit_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Audit not found")
    return _report_to_response(report)


@router.get("/audits", response_model=list[AuditResponse])
async def list_audits(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> list[AuditResponse]:
    """List audits with pagination."""
    offset = (page - 1) * per_page
    result = await db.execute(
        select(AuditReport)
        .options(selectinload(AuditReport.findings))
        .options(selectinload(AuditReport.ruleset))
        .order_by(AuditReport.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    reports = result.scalars().all()
    return [_report_to_response(r) for r in reports]


@router.delete("/audit/{audit_id}", response_model=DeleteAuditsResponse)
async def delete_audit(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
) -> DeleteAuditsResponse:
    """Delete a single audit and its orphaned ruleset, if any."""
    _validate_uuid(audit_id, "audit_id")
    return await _delete_audit_records([audit_id], db)


@router.delete("/audits", response_model=DeleteAuditsResponse)
async def delete_audits(
    request: DeleteAuditsRequest,
    db: AsyncSession = Depends(get_db),
) -> DeleteAuditsResponse:
    """Delete multiple audits in one request."""
    return await _delete_audit_records(request.audit_ids, db)
