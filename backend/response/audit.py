"""In-memory, immutable-style action records for Task 11 response decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from backend.incidents.models import Incident
from backend.intelligence.models import Indicator
from backend.models.schemas import ContractModel
from backend.response.models import BlockResult, ExecutionMode, ResponseAction, ResponseDecision


class ActionRecordStatus(str, Enum):
    """The in-memory audit state of a response action."""

    PLANNED = "planned"
    SKIPPED = "skipped"
    NOT_EXECUTED = "not_executed"


class ActionRecord(ContractModel):
    """A non-persistent record of one planned or skipped response action."""

    action_id: UUID
    incident_id: UUID | None = None
    scan_id: UUID
    indicator: Indicator
    action: ResponseAction
    reason: str = Field(min_length=1)
    mode: ExecutionMode
    would_execute: bool
    executed: bool = False
    status: ActionRecordStatus
    timestamp: datetime

    @model_validator(mode="after")
    def record_is_safe_and_consistent(self) -> ActionRecord:
        if self.executed:
            raise ValueError("Task 12 action records cannot be marked as executed")
        if self.action is ResponseAction.NO_ACTION and self.would_execute:
            raise ValueError("no-action records cannot be marked as would_execute")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return self


def build_action_record(
    decision: ResponseDecision,
    *,
    incident: Incident | None = None,
    block_result: BlockResult | None = None,
    recorded_at: datetime | None = None,
) -> ActionRecord:
    """Create a deep-copied, non-executed record from an existing decision."""

    decision_snapshot = _validated_decision_snapshot(decision)
    incident_snapshot = _validated_incident_snapshot(incident) if incident else None
    _validate_incident_relationship(decision_snapshot, incident_snapshot)
    result_snapshot = _validated_result_snapshot(block_result) if block_result else None
    _validate_result_relationship(decision_snapshot, result_snapshot)
    would_execute = (
        result_snapshot.would_block
        if result_snapshot is not None
        else decision_snapshot.action is ResponseAction.BLOCK
    )
    return ActionRecord(
        action_id=uuid4(),
        incident_id=(
            incident_snapshot.incident_id
            if incident_snapshot is not None
            else decision_snapshot.incident_id
        ),
        scan_id=decision_snapshot.scan_id,
        indicator=decision_snapshot.indicator.model_copy(deep=True),
        action=decision_snapshot.action,
        reason=decision_snapshot.reason,
        mode=decision_snapshot.mode,
        would_execute=would_execute,
        executed=False,
        status=(
            ActionRecordStatus.NOT_EXECUTED
            if decision_snapshot.action is ResponseAction.BLOCK
            else ActionRecordStatus.SKIPPED
        ),
        timestamp=_utc_timestamp(recorded_at),
    )


def build_action_records(
    decisions: list[ResponseDecision],
    *,
    incident: Incident | None = None,
    recorded_at: datetime | None = None,
) -> list[ActionRecord]:
    """Build one record per decision, retaining the caller's order."""

    timestamp = _utc_timestamp(recorded_at)
    return [
        build_action_record(decision, incident=incident, recorded_at=timestamp)
        for decision in decisions
    ]


def _validated_decision_snapshot(decision: ResponseDecision) -> ResponseDecision:
    if not isinstance(decision, ResponseDecision):
        raise TypeError("decision must be a ResponseDecision")
    return ResponseDecision.model_validate(decision.model_dump()).model_copy(deep=True)


def _validated_incident_snapshot(incident: Incident) -> Incident:
    if not isinstance(incident, Incident):
        raise TypeError("incident must be an Incident")
    return Incident.model_validate(incident.model_dump()).model_copy(deep=True)


def _validated_result_snapshot(result: BlockResult) -> BlockResult:
    if not isinstance(result, BlockResult):
        raise TypeError("block_result must be a BlockResult")
    return BlockResult.model_validate(result.model_dump()).model_copy(deep=True)


def _validate_incident_relationship(
    decision: ResponseDecision, incident: Incident | None
) -> None:
    if incident is None:
        return
    if incident.scan_id != decision.scan_id:
        raise ValueError("incident.scan_id must match decision.scan_id")
    if decision.incident_id is not None and decision.incident_id != incident.incident_id:
        raise ValueError("decision.incident_id must match incident.incident_id")


def _validate_result_relationship(
    decision: ResponseDecision, result: BlockResult | None
) -> None:
    if result is None:
        return
    if result.indicator_id != decision.indicator_id:
        raise ValueError("block_result.indicator_id must match decision.indicator_id")
    if result.requested_action is not decision.action:
        raise ValueError("block_result.requested_action must match decision.action")
    if result.mode is not decision.mode:
        raise ValueError("block_result.mode must match decision.mode")
    if result.would_block != (decision.action is ResponseAction.BLOCK):
        raise ValueError("block_result.would_block must match the decision action")


def _utc_timestamp(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("recorded_at must be timezone-aware")
    return value.astimezone(timezone.utc)
