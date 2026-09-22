"""HTTP boundary for the existing Module 2 investigation orchestrator."""

import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from backend.config import Settings
from backend.models.schemas import ScanResult
from backend.module2.orchestrator import Module2Result, run_module2_investigation
from backend.module2.repository import (
    DuplicateInvestigationError,
    DEFAULT_INVESTIGATION_PAGE_LIMIT,
    MAX_INVESTIGATION_PAGE_LIMIT,
    Module2InvestigationRepository,
    Module2RepositoryError,
    SupabaseModule2Repository,
)


router = APIRouter(prefix="/api/module2", tags=["module2"])


class Module2InvestigationPage(BaseModel):
    """Read-only, bounded page of existing Module 2 results."""

    items: list[Module2Result]
    limit: int = Field(ge=1, le=MAX_INVESTIGATION_PAGE_LIMIT)
    offset: int = Field(ge=0)
    count: int = Field(ge=0)


def get_module2_repository() -> Module2InvestigationRepository | None:
    """Provide configured production persistence without making it a default."""

    try:
        settings = Settings.from_environment()
        configured_values = (settings.supabase_url, settings.supabase_service_role_key)
        if configured_values == (None, None):
            return None
        if not all(configured_values):
            raise Module2RepositoryError("Supabase persistence configuration is incomplete")
        return SupabaseModule2Repository.from_environment()
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Module 2 persistence is currently unavailable.",
        ) from error


def _module2_response(result: Module2Result) -> Module2Result:
    """Return an HTTP-safe view without changing the repository snapshot."""

    return result.model_copy(
        update={"stix_bundle": json.loads(result.stix_bundle.serialize())}
    )


def _module2_page_response(
    results: list[Module2Result], *, limit: int, offset: int
) -> Module2InvestigationPage:
    """Serialize retrieved snapshots without modifying their repository copies."""

    return Module2InvestigationPage(
        items=[_module2_response(result) for result in results],
        limit=limit,
        offset=offset,
        count=len(results),
    )


def _validated_retrieved_result(
    result: object, *, expected_scan_id: UUID | None = None
) -> Module2Result:
    """Reject malformed repository values before they cross the HTTP boundary."""

    if not isinstance(result, Module2Result):
        raise Module2RepositoryError("repository returned an invalid investigation")
    scan_id = result.scan_result.scan_id
    evidence = result.evidence_pack
    incident = result.incident
    report = result.forensic_report
    if (
        (expected_scan_id is not None and scan_id != expected_scan_id)
        or result.enriched_threat_result.scan_id != scan_id
        or evidence.scan_id != scan_id
        or evidence.scan_result.scan_id != scan_id
        or incident.scan_id != scan_id
        or report.scan_id != scan_id
        or report.incident_id != incident.incident_id
        or report.evidence_pack.evidence_id != evidence.evidence_id
        or report.incident.incident_id != incident.incident_id
        or any(
            decision.scan_id != scan_id or decision.evidence_id != evidence.evidence_id
            for decision in result.response_decisions
        )
        or any(record.scan_id != scan_id for record in result.action_records)
    ):
        raise Module2RepositoryError("repository returned an inconsistent investigation")
    return result


@router.post(
    "/investigate",
    response_model=Module2Result,
    responses={
        409: {"description": "An investigation already exists for this scan."},
        500: {"description": "The investigation could not be completed."},
        503: {"description": "Module 2 persistence is unavailable."},
    },
    summary="Investigate a canonical scan result",
    description=(
        "Run the Module 2 threat-intelligence, investigation, forensic, STIX, "
        "and dry-run response pipeline for a canonical ScanResult."
    ),
)
async def investigate(
    scan_result: ScanResult,
    repository: Annotated[
        Module2InvestigationRepository | None, Depends(get_module2_repository)
    ],
) -> Module2Result:
    """Validate a scan and delegate all investigation work to Module 2."""

    try:
        result = run_module2_investigation(scan_result, repository=repository)
    except DuplicateInvestigationError as error:
        raise HTTPException(
            status_code=409,
            detail="An investigation already exists for this scan.",
        ) from error
    except Module2RepositoryError as error:
        raise HTTPException(
            status_code=503,
            detail="Module 2 persistence is currently unavailable.",
        ) from error
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=422,
            detail="Module 2 investigation could not be completed.",
        ) from error
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Module 2 investigation could not be completed.",
        ) from error
    try:
        return _module2_response(result)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Module 2 investigation could not be completed.",
        ) from error


@router.get(
    "/investigations",
    response_model=Module2InvestigationPage,
    responses={503: {"description": "Module 2 persistence is unavailable."}},
    summary="List persisted Module 2 investigations",
    description=(
        "Retrieve a bounded, read-only page of existing Module2Result snapshots. "
        "Results are ordered newest collected investigation first."
    ),
)
async def list_investigations(
    repository: Annotated[
        Module2InvestigationRepository | None, Depends(get_module2_repository)
    ],
    limit: Annotated[
        int, Query(ge=1, le=MAX_INVESTIGATION_PAGE_LIMIT)
    ] = DEFAULT_INVESTIGATION_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Module2InvestigationPage:
    """List persisted investigations without invoking Module 2 business logic."""

    if repository is None:
        raise HTTPException(
            status_code=503,
            detail="Module 2 persistence is currently unavailable.",
        )
    try:
        results = repository.list_investigations(limit=limit, offset=offset)
        if not isinstance(results, list):
            raise Module2RepositoryError("repository returned an invalid investigation page")
        validated = [_validated_retrieved_result(result) for result in results]
        return _module2_page_response(validated, limit=limit, offset=offset)
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Module 2 persistence is currently unavailable.",
        ) from error

@router.get(
    "/investigations/{scan_id}",
    response_model=Module2Result,
    responses={
        404: {"description": "No investigation exists for the canonical scan ID."},
        503: {"description": "Module 2 persistence is unavailable."},
    },
    summary="Retrieve a persisted Module 2 investigation",
    description=(
        "Retrieve an existing persisted Module2Result by its canonical scan ID. "
        "This endpoint does not run the Module 2 investigation pipeline."
    ),
)
async def get_investigation(
    scan_id: UUID,
    repository: Annotated[
        Module2InvestigationRepository | None, Depends(get_module2_repository)
    ],
) -> Module2Result:
    """Retrieve one completed investigation without performing any pipeline work."""

    if repository is None:
        raise HTTPException(
            status_code=503,
            detail="Module 2 persistence is currently unavailable.",
        )
    try:
        result = repository.get_by_scan_id(scan_id)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail="Module 2 investigation was not found.",
            )
        return _module2_response(
            _validated_retrieved_result(result, expected_scan_id=scan_id)
        )
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Module 2 persistence is currently unavailable.",
        ) from error
