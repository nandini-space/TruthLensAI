"""HTTP boundary for the existing Module 2 investigation orchestrator."""

import json

from fastapi import APIRouter, HTTPException

from backend.models.schemas import ScanResult
from backend.module2.orchestrator import Module2Result, run_module2_investigation


router = APIRouter(prefix="/api/module2", tags=["module2"])


@router.post(
    "/investigate",
    response_model=Module2Result,
    summary="Investigate a canonical scan result",
    description=(
        "Run the Module 2 threat-intelligence, investigation, forensic, STIX, "
        "and dry-run response pipeline for a canonical ScanResult."
    ),
)
async def investigate(scan_result: ScanResult) -> Module2Result:
    """Validate a scan and delegate all investigation work to Module 2."""

    try:
        result = run_module2_investigation(scan_result)
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=422,
            detail="Module 2 investigation could not be completed.",
        ) from error
    return result.model_copy(
        update={"stix_bundle": json.loads(result.stix_bundle.serialize())}
    )
