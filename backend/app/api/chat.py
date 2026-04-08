"""POST /audit/{audit_id}/chat -- SSE streaming chat about audit findings.
   POST /chat/general       -- SSE streaming general firewall policy chat.
"""

from __future__ import annotations

import json
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from app.api.deps import get_db
from app.config import settings
from app.llm.client import ClaudeClient
from app.llm.prompts.chat import SYSTEM_CHAT
from app.models.audit import AuditFinding, AuditReport
from app.models.chat import ChatMessage
from app.models.rule import Rule
from app.schemas.chat import ChatRequest
from app.security import chat_rate_limit

logger = logging.getLogger(__name__)

router = APIRouter()


def _build_rules_summary(rules: list[Rule], limit: int = 20) -> str:
    """Build a compact text summary of rules for the system prompt."""
    if not rules:
        return "No rules loaded."

    lines = []
    for r in rules[:limit]:
        src = r.source_addresses or '["*"]'
        dst = r.dest_addresses or '["*"]'
        ports = r.dest_ports or '["*"]'
        lines.append(
            f"- {r.name}: {r.action} {r.direction} {r.protocol or 'Any'} "
            f"src={src} dst={dst} ports={ports} pri={r.priority}"
        )
    suffix = f"\n... and {len(rules) - limit} more rules" if len(rules) > limit else ""
    return "\n".join(lines) + suffix


def _build_findings_summary(findings: list[AuditFinding]) -> str:
    """Build a compact text summary of audit findings for the system prompt."""
    if not findings:
        return "No findings."

    lines = []
    for f in findings:
        lines.append(f"- [{f.severity.upper()}] {f.title}: {f.description[:120]}")
    return "\n".join(lines)


@router.post("/audit/{audit_id}/chat", dependencies=[Depends(chat_rate_limit)])
async def chat_about_audit(
    audit_id: str,
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
):
    """Chat with the AI about audit findings. Returns an SSE stream."""

    # --- Validate audit_id format ---
    try:
        uuid.UUID(audit_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid audit_id format")

    # --- Validate LLM config ---
    if settings.llm_provider == "azure" and not settings.azure_api_key:
        raise HTTPException(status_code=503, detail="LLM service is not configured")
    if settings.llm_provider == "openai" and not settings.openai_api_key:
        raise HTTPException(status_code=503, detail="LLM service is not configured")

    # --- Load audit report ---
    result = await db.execute(
        select(AuditReport).where(AuditReport.id == audit_id)
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail=f"Audit report '{audit_id}' not found")

    # --- Load rules for this audit's ruleset ---
    rules_result = await db.execute(
        select(Rule).where(Rule.ruleset_id == audit.ruleset_id)
    )
    rules = list(rules_result.scalars().all())

    # --- Load findings ---
    findings_result = await db.execute(
        select(AuditFinding).where(AuditFinding.audit_id == audit_id)
    )
    findings = list(findings_result.scalars().all())

    # --- Build system prompt ---
    rules_summary = _build_rules_summary(rules)
    findings_summary = _build_findings_summary(findings)
    system_prompt = SYSTEM_CHAT.format(
        rules_summary=rules_summary,
        findings_summary=findings_summary,
    )

    # --- Load chat history ---
    history_result = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.audit_id == audit_id)
        .order_by(ChatMessage.created_at)
    )
    history = list(history_result.scalars().all())

    # --- Save user message ---
    user_msg = ChatMessage(
        audit_id=audit_id,
        role="user",
        content=request.message,
    )
    db.add(user_msg)
    await db.commit()

    # --- Build conversation for LLM ---
    conversation: list[dict[str, str]] = []
    for msg in history:
        conversation.append({"role": msg.role, "content": msg.content})
    conversation.append({"role": "user", "content": request.message})

    # --- Stream response ---
    llm = ClaudeClient()

    async def event_generator():
        full_response = ""
        try:
            stream = llm.stream(system=system_prompt, messages=conversation)
            for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta and delta.content:
                    full_response += delta.content
                    yield {"data": json.dumps({"content": delta.content})}
        except Exception as exc:
            logger.error("LLM streaming error: %s", exc)
            yield {"data": json.dumps({"error": "An error occurred while processing your request"})}
            return

        # Save assistant message to DB after stream completes
        try:
            async with db.begin():
                assistant_msg = ChatMessage(
                    audit_id=audit_id,
                    role="assistant",
                    content=full_response,
                )
                db.add(assistant_msg)
        except Exception as exc:
            logger.error("Failed to save assistant message: %s", exc)

        yield {"data": json.dumps({"done": True, "full_content": full_response})}

    return EventSourceResponse(event_generator())


# ---------------------------------------------------------------------------
# General (no-audit) chat
# ---------------------------------------------------------------------------

SYSTEM_GENERAL = """\
You are FlameGuard, an expert network security policy assistant. \
You help security engineers with:
- Network security policy design and best practices (Azure NSG, Azure Firewall, Azure WAF, AWS SG, Palo Alto, etc.)
- Network segmentation strategies and zero-trust architectures
- Compliance frameworks (CIS, PCI DSS, NIST, SOC 2) as they relate to network security
- Troubleshooting connectivity issues caused by security policies and controls
- Explaining security concepts in plain English

Be concise, specific, and actionable. When discussing rules, use concrete examples \
with realistic IP ranges and ports. If the user asks about a specific vendor, give \
vendor-specific guidance. If they ask you to generate rules, tell them to use the \
Rule Generator page for vendor-specific output.
"""


@router.post("/chat/general", dependencies=[Depends(chat_rate_limit)])
async def general_chat(request: ChatRequest):
    """General firewall policy chat — no audit context required. Returns SSE stream."""

    # Validate LLM config
    if settings.llm_provider == "azure" and not settings.azure_api_key:
        raise HTTPException(status_code=503, detail="LLM service is not configured")
    if settings.llm_provider == "openai" and not settings.openai_api_key:
        raise HTTPException(status_code=503, detail="LLM service is not configured")

    llm = ClaudeClient()
    conversation = [{"role": "user", "content": request.message}]

    async def event_generator():
        full_response = ""
        try:
            stream = llm.stream(system=SYSTEM_GENERAL, messages=conversation)
            for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta and delta.content:
                    full_response += delta.content
                    yield {"data": json.dumps({"content": delta.content})}
        except Exception as exc:
            logger.error("General chat LLM error: %s", exc)
            yield {"data": json.dumps({"error": "An error occurred while processing your request"})}
            return

        yield {"data": json.dumps({"done": True, "full_content": full_response})}

    return EventSourceResponse(event_generator())
