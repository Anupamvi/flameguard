"""Main LLM audit pipeline: load rules -> chunk -> analyze -> score -> store."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.deterministic import DeterministicFinding, run_deterministic_checks
from app.compliance.engine import get_compliance_engine
from app.llm.chunker import RuleSetChunker
from app.llm.client import ClaudeClient
from app.llm.prompts.audit import (
    SYSTEM_AUDIT,
    SYSTEM_RISK_SCORE,
    USER_AUDIT_TEMPLATE,
    USER_RISK_SCORE_TEMPLATE,
)
from app.llm.response_parser import parse_audit_response, parse_risk_response
from app.models.audit import AuditFinding, AuditReport
from app.models.compliance import ComplianceCheck
from app.models.rule import Rule, RuleSet
from app.parsers.base import NormalizedRule, RuleAction, RuleDirection, VendorType

logger = logging.getLogger(__name__)


def _db_rule_to_normalized(rule: Rule) -> NormalizedRule:
    """Convert a DB Rule row back to a NormalizedRule for LLM consumption."""

    def _json_list(val: str | None) -> list[str]:
        if not val:
            return []
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return []

    def _json_dict(val: str | None) -> dict:
        if not val:
            return {}
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return {}

    return NormalizedRule(
        original_id=rule.original_id or rule.id,
        name=rule.name,
        vendor=VendorType(rule.ruleset.vendor) if rule.ruleset else VendorType.AZURE_FIREWALL,
        action=RuleAction(rule.action),
        direction=RuleDirection(rule.direction),
        protocol=rule.protocol or "Any",
        source_addresses=_json_list(rule.source_addresses),
        source_ports=_json_list(rule.source_ports),
        destination_addresses=_json_list(rule.dest_addresses),
        destination_ports=_json_list(rule.dest_ports),
        priority=rule.priority,
        collection_name=rule.collection_name,
        collection_priority=rule.collection_priority,
        description=rule.description or "",
        enabled=rule.enabled,
        tags=_json_dict(rule.tags),
    )


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Merge findings with the same category and overlapping affected_rules."""
    merged: list[dict] = []

    for f in findings:
        matched = False
        for existing in merged:
            if existing["category"] != f["category"]:
                continue
            overlap = set(existing["affected_rules"]) & set(f["affected_rules"])
            if overlap:
                # Merge: union affected_rules, keep higher severity, append descriptions
                existing["affected_rules"] = list(
                    set(existing["affected_rules"]) | set(f["affected_rules"])
                )
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                if sev_order.get(f["severity"], 4) < sev_order.get(existing["severity"], 4):
                    existing["severity"] = f["severity"]
                if f["description"] not in existing["description"]:
                    existing["description"] += f"\n\n{f['description']}"
                existing["confidence"] = max(existing["confidence"], f["confidence"])
                matched = True
                break
        if not matched:
            merged.append(dict(f))  # copy

    return merged


def _cross_reference_findings(
    llm_findings: list[dict],
    det_findings: list[DeterministicFinding],
    name_to_rule_id: dict[str, str],
) -> list[dict]:
    """Cross-reference LLM and deterministic findings.

    - LLM findings that match a deterministic finding → source="verified"
    - LLM-only findings → source="llm"
    - Deterministic findings with no LLM match → added as source="deterministic"
    """
    # Build a set of (category, frozenset(rule_names)) for each LLM finding
    # to check for overlap
    det_matched: set[int] = set()  # indices of det findings matched to LLM

    for lf in llm_findings:
        lf.setdefault("source", "llm")
        lf_rules = set(lf.get("affected_rules", []))

        for di, df in enumerate(det_findings):
            if df.category != lf["category"]:
                continue
            df_rules = set(df.affected_rules)
            if lf_rules & df_rules:
                # Both engines agree on the same rules + category → verified
                lf["source"] = "verified"
                lf["confidence"] = 1.0  # deterministic confirmation
                det_matched.add(di)
                break

    # Add deterministic-only findings that the LLM missed
    for di, df in enumerate(det_findings):
        if di in det_matched:
            continue
        llm_dict = {
            "severity": df.severity,
            "category": df.category,
            "title": f"[Auto] {df.title}",
            "description": df.description,
            "recommendation": df.recommendation,
            "confidence": df.confidence,
            "affected_rules": df.affected_rules,
            "source": "deterministic",
        }
        llm_findings.append(llm_dict)

    return llm_findings


class AuditPipeline:
    """Orchestrates the full audit: chunk -> LLM analyze -> deduplicate -> score -> store."""

    def __init__(self, db: AsyncSession, llm: ClaudeClient) -> None:
        self.db = db
        self.llm = llm
        self.chunker = RuleSetChunker()

    async def _update_status(self, audit_id: str, status: str, **kwargs) -> None:
        """Update audit report status and optional extra fields."""
        report = await self.db.get(AuditReport, audit_id)
        if report:
            report.status = status
            for key, value in kwargs.items():
                setattr(report, key, value)
            await self.db.commit()

    async def run(self, audit_id: str, ruleset_id: str) -> None:
        """Full audit pipeline: load rules -> chunk -> analyze -> risk score -> store findings."""
        try:
            # 1. Update status to "auditing"
            await self._update_status(audit_id, "auditing")

            # 2. Load rules from DB
            ruleset = await self.db.get(RuleSet, ruleset_id)
            if not ruleset:
                raise ValueError(f"RuleSet {ruleset_id} not found")

            result = await self.db.execute(
                select(Rule).where(Rule.ruleset_id == ruleset_id)
            )
            db_rules = result.scalars().all()
            if not db_rules:
                raise ValueError("No rules found in ruleset")

            # Attach ruleset ref for vendor lookup
            for r in db_rules:
                r.ruleset = ruleset

            # Convert to NormalizedRule
            normalized = [_db_rule_to_normalized(r) for r in db_rules]
            vendor = ruleset.vendor

            # Build a name -> rule_id mapping for linking findings back to DB rules
            name_to_rule_id: dict[str, str] = {r.name: r.id for r in db_rules}

            # 3. Chunk rules
            chunks = self.chunker.chunk(normalized)

            # 4. Analyze each chunk
            all_findings: list[dict] = []
            for chunk in chunks:
                rules_json = json.dumps(
                    [r.to_llm_summary() for r in chunk.rules], indent=2
                )
                overlap_note = ""
                if not chunk.is_first:
                    overlap_note = (
                        f"Note: The first {self.chunker.overlap} rules overlap with "
                        f"the previous chunk for context continuity."
                    )

                user_prompt = USER_AUDIT_TEMPLATE.format(
                    vendor=vendor,
                    chunk_index=chunk.index,
                    total_chunks=chunk.total_chunks,
                    rules_json=rules_json,
                    overlap_note=overlap_note,
                )

                raw_response = await self.llm.analyze(
                    system=SYSTEM_AUDIT, user=user_prompt
                )
                chunk_findings = parse_audit_response(raw_response)
                all_findings.extend(chunk_findings)

            # 5. Merge & deduplicate
            all_findings = _deduplicate_findings(all_findings)

            # 5b. Run deterministic checks and cross-reference with LLM findings
            det_findings = run_deterministic_checks(normalized)
            all_findings = _cross_reference_findings(all_findings, det_findings, name_to_rule_id)

            # 6. Risk scoring pass (second Claude call)
            await self._update_status(audit_id, "scoring")

            findings_json = json.dumps(all_findings, indent=2)
            risk_prompt = USER_RISK_SCORE_TEMPLATE.format(
                vendor=vendor,
                rule_count=len(normalized),
                findings_json=findings_json,
            )
            risk_raw = await self.llm.analyze(
                system=SYSTEM_RISK_SCORE, user=risk_prompt
            )
            risk_data = parse_risk_response(risk_raw)
            executive_summary = risk_data["executive_summary"]

            # 7. Store findings in DB
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            for f in all_findings:
                sev = f["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

                # Resolve affected rule names to DB rule IDs
                affected_rule_ids = []
                primary_rule_id = None
                for rule_name in f.get("affected_rules", []):
                    rid = name_to_rule_id.get(rule_name)
                    if rid:
                        affected_rule_ids.append(rid)
                        if primary_rule_id is None:
                            primary_rule_id = rid

                finding = AuditFinding(
                    id=str(uuid.uuid4()),
                    audit_id=audit_id,
                    rule_id=primary_rule_id,
                    related_rule_ids=json.dumps(affected_rule_ids) if affected_rule_ids else None,
                    severity=sev,
                    category=f["category"],
                    title=f["title"],
                    description=f["description"],
                    recommendation=f.get("recommendation"),
                    confidence=f.get("confidence"),
                    source=f.get("source", "llm"),
                )
                self.db.add(finding)

            # 8. Run compliance checks
            compliance_engine = get_compliance_engine()
            compliance_results = compliance_engine.run(normalized)
            for cr in compliance_results:
                check = ComplianceCheck(
                    audit_id=audit_id,
                    framework=cr.framework,
                    control_id=cr.control_id,
                    control_title=cr.control_title,
                    status=cr.status,
                    evidence=cr.evidence,
                    affected_rule_ids=json.dumps(cr.affected_rule_ids) if cr.affected_rule_ids else None,
                )
                self.db.add(check)

            logger.info(
                "Audit %s: %d compliance checks (%d failed)",
                audit_id,
                len(compliance_results),
                sum(1 for cr in compliance_results if cr.status == "fail"),
            )

            # 9. Update audit status to "completed" with summary and counts
            await self._update_status(
                audit_id,
                "completed",
                summary=executive_summary,
                total_findings=len(all_findings),
                critical_count=severity_counts["critical"],
                high_count=severity_counts["high"],
                medium_count=severity_counts["medium"],
                low_count=severity_counts["low"],
                completed_at=datetime.now(timezone.utc),
            )

            logger.info(
                "Audit %s completed: %d findings (%d critical, %d high)",
                audit_id,
                len(all_findings),
                severity_counts["critical"],
                severity_counts["high"],
            )

        except Exception as e:
            logger.exception("Audit pipeline failed for audit_id=%s", audit_id)
            try:
                await self._update_status(
                    audit_id, "failed", error_message=str(e)
                )
            except Exception:
                logger.exception("Failed to update audit status to 'failed'")
            raise
