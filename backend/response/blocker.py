"""Dry-run-only IOC blocking adapter; it never changes external systems."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from backend.response.models import BlockResult, ExecutionMode, ResponseAction, ResponseDecision


class IOCBlocker(Protocol):
    """Boundary for future response adapters that receive policy decisions only."""

    def block(self, decision: ResponseDecision) -> BlockResult:
        """Handle an already-approved response decision."""


class DryRunIOCBlocker:
    """Describe an approved block without making any system or network change."""

    def block(self, decision: ResponseDecision) -> BlockResult:
        if not isinstance(decision, ResponseDecision):
            raise TypeError("decision must be a ResponseDecision")
        would_block = decision.action is ResponseAction.BLOCK
        reason = (
            f"Dry run: would block {decision.indicator_type.value} indicator."
            if would_block
            else "Dry run: no blocking action was approved by the response decision."
        )
        return BlockResult(
            indicator_id=decision.indicator_id,
            indicator_type=decision.indicator_type,
            indicator_value=decision.indicator_value,
            requested_action=decision.action,
            mode=ExecutionMode.DRY_RUN,
            would_block=would_block,
            executed=False,
            reason=reason,
            occurred_at=datetime.now(timezone.utc),
        )
