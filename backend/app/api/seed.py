"""POST /seed-demo — populate the database with a demo audit."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.seed_demo import seed_demo

router = APIRouter()


@router.post("/seed-demo")
async def seed_demo_endpoint(db: AsyncSession = Depends(get_db)):
    """Seed the database with realistic demo Azure NSG data. Idempotent."""
    result = await seed_demo(db)
    return result
