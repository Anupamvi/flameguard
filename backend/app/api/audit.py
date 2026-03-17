import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.audit import AuditReport, AuditFinding
from app.schemas.audit import AuditRequest, AuditResponse, FindingOut

router = APIRouter()


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
    result = await db.execute(
        select(AuditReport)
        .options(selectinload(AuditReport.findings))
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
        .order_by(AuditReport.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    reports = result.scalars().all()
    return [_report_to_response(r) for r in reports]
