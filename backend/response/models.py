"""Validated contracts for the non-destructive IOC response boundary."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import Field, model_validator

from backend.intelligence.models import Indicator, IndicatorType, Reputation
from backend.models.schemas import ContractModel


class ResponseAction(str, Enum):
    """Actions that the response policy may approve."""

    NO_ACTION = "no_action"
    BLOCK = "block"


class ExecutionMode(str, Enum):
    """Execution mode for Task 11 response adapters."""

    DRY_RUN = "dry_run"
    REAL = "real"


class ResponseDecision(ContractModel):
    """A policy decision made before any response adapter is invoked."""

    indicator_id: UUID
    indicator_type: IndicatorType
    indicator_value: Annotated[str, Field(min_length=1)]
    indicator: Indicator
    action: ResponseAction
    reason: Annotated[str, Field(min_length=1)]
    reputation: Reputation | None = None
    evidence_id: UUID
    scan_id: UUID
    incident_id: UUID | None = None
    mode: ExecutionMode = ExecutionMode.DRY_RUN

    @model_validator(mode="after")
    def indicator_identity_matches_decision(self) -> ResponseDecision:
        if self.indicator_id != self.indicator.indicator_id:
            raise ValueError("indicator_id must match indicator.indicator_id")
        if self.indicator_type is not self.indicator.type:
            raise ValueError("indicator_type must match indicator.type")
        if self.indicator_value != self.indicator.value:
            raise ValueError("indicator_value must match indicator.value")
        return self


class BlockResult(ContractModel):
    """An explicit result from the dry-run-only blocking adapter."""

    indicator_id: UUID
    indicator_type: IndicatorType
    indicator_value: Annotated[str, Field(min_length=1)]
    requested_action: ResponseAction
    mode: ExecutionMode
    would_block: bool
    executed: bool
    reason: Annotated[str, Field(min_length=1)]
    occurred_at: datetime

    @model_validator(mode="after")
    def dry_run_never_executes(self) -> BlockResult:
        if self.mode is ExecutionMode.DRY_RUN and self.executed:
            raise ValueError("dry-run block results cannot be marked as executed")
        if self.requested_action is ResponseAction.NO_ACTION and self.would_block:
            raise ValueError("no-action results cannot be marked as would_block")
        return self
