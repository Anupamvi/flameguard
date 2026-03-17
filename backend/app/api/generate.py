"""POST /generate -- natural-language to firewall rule."""

from fastapi import APIRouter, HTTPException

from app.schemas.generate import RuleGenRequest, RuleGenResponse
from app.services.generate_service import generate_rule

router = APIRouter()


@router.post("/generate", response_model=RuleGenResponse)
async def generate_rule_endpoint(request: RuleGenRequest) -> RuleGenResponse:
    """Generate a firewall rule from a natural-language intent."""
    try:
        result = await generate_rule(
            intent=request.intent,
            vendor=request.vendor,
            context=request.context,
        )
    except RuntimeError as exc:
        # No API key configured
        raise HTTPException(status_code=503, detail=str(exc))
    except ValueError as exc:
        # Bad vendor or unparseable LLM response
        raise HTTPException(status_code=400, detail=str(exc))

    return RuleGenResponse(
        config=result["config"],
        explanation=result["explanation"],
        warnings=result["warnings"],
        is_valid=result["is_valid"],
    )
