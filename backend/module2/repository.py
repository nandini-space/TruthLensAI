"""Provider-neutral persistence boundary for completed Module 2 investigations."""

from __future__ import annotations

from copy import deepcopy
import json
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from backend.config import Settings
if TYPE_CHECKING:
    from backend.module2.orchestrator import Module2Result


_DEFAULT_SUPABASE_TABLE = "module2_investigations"
DEFAULT_INVESTIGATION_PAGE_LIMIT = 20
MAX_INVESTIGATION_PAGE_LIMIT = 100


class DuplicateInvestigationError(ValueError):
    """Raised when an investigation for a scan has already been saved."""


class Module2RepositoryError(RuntimeError):
    """Raised when a repository cannot complete a persistence operation."""


class MalformedStoredInvestigationError(Module2RepositoryError):
    """Raised when a stored investigation cannot be reconstructed safely."""


class Module2InvestigationRepository(Protocol):
    """Persistence contract for complete, already-generated investigations.

    ``save`` rejects duplicate scan IDs and returns an independent snapshot.
    Retrieval returns an independent snapshot, or ``None`` if no result exists.
    Implementations must preserve canonical identities and never mutate supplied
    results or expose their stored instances.
    """

    def save(self, result: Module2Result) -> Module2Result:
        """Save one completed result, rejecting an existing canonical scan ID."""

    def get_by_scan_id(self, scan_id: UUID) -> Module2Result | None:
        """Return a snapshot for a scan, or ``None`` when it is not stored."""

    def get_by_incident_id(self, incident_id: UUID) -> Module2Result | None:
        """Return a snapshot for an incident, or ``None`` when it is not stored."""

    def list_investigations(
        self,
        *,
        limit: int = DEFAULT_INVESTIGATION_PAGE_LIMIT,
        offset: int = 0,
    ) -> list[Module2Result]:
        """Return a deterministically ordered page of independent snapshots."""


class InMemoryModule2Repository:
    """Deterministic test implementation with no external persistence or I/O."""

    def __init__(self) -> None:
        self._by_scan_id: dict[UUID, Module2Result] = {}
        self._scan_id_by_incident_id: dict[UUID, UUID] = {}

    def save(self, result: Module2Result) -> Module2Result:
        """Validate and retain an independent snapshot of a completed result."""

        snapshot = _validated_snapshot(result)
        scan_id = snapshot.scan_result.scan_id
        if scan_id in self._by_scan_id:
            raise DuplicateInvestigationError(
                f"an investigation is already stored for scan_id {scan_id}"
            )
        self._by_scan_id[scan_id] = snapshot
        self._scan_id_by_incident_id[snapshot.incident.incident_id] = scan_id
        return _copy_result(snapshot)

    def get_by_scan_id(self, scan_id: UUID) -> Module2Result | None:
        """Return an independent result snapshot, if one exists for ``scan_id``."""

        if not isinstance(scan_id, UUID):
            raise TypeError("scan_id must be a UUID")
        result = self._by_scan_id.get(scan_id)
        return _copy_result(result) if result is not None else None

    def get_by_incident_id(self, incident_id: UUID) -> Module2Result | None:
        """Return an independent result snapshot, if one exists for ``incident_id``."""

        if not isinstance(incident_id, UUID):
            raise TypeError("incident_id must be a UUID")
        scan_id = self._scan_id_by_incident_id.get(incident_id)
        return self.get_by_scan_id(scan_id) if scan_id is not None else None

    def list_investigations(
        self,
        *,
        limit: int = DEFAULT_INVESTIGATION_PAGE_LIMIT,
        offset: int = 0,
    ) -> list[Module2Result]:
        """List snapshots by collected time descending, then scan ID descending."""

        _validate_pagination(limit=limit, offset=offset)
        ordered = sorted(
            self._by_scan_id.values(),
            key=lambda result: (result.evidence_pack.collected_at, str(result.scan_result.scan_id)),
            reverse=True,
        )
        return [_copy_result(result) for result in ordered[offset : offset + limit]]


class SupabaseModule2Repository:
    """Supabase JSONB implementation of the Module 2 repository contract.

    The client is injected for testability. :meth:`from_environment` creates the
    production client only when explicitly requested, using the existing service
    role configuration and no API request data.
    """

    def __init__(self, client: Any, *, table_name: str = _DEFAULT_SUPABASE_TABLE) -> None:
        if not table_name or not table_name.replace("_", "").isalnum():
            raise ValueError("table_name must contain only letters, numbers, and underscores")
        self._client = client
        self._table_name = table_name

    @classmethod
    def from_environment(cls, *, table_name: str = _DEFAULT_SUPABASE_TABLE) -> SupabaseModule2Repository:
        """Build a repository from configured Supabase service credentials."""

        settings = Settings.from_environment()
        if not settings.supabase_url or not settings.supabase_service_role_key:
            raise Module2RepositoryError("Supabase persistence configuration is required")
        try:
            from supabase import create_client
        except ImportError as error:
            raise Module2RepositoryError("Supabase client dependency is unavailable") from error
        try:
            client = create_client(settings.supabase_url, settings.supabase_service_role_key)
        except Exception as error:
            raise Module2RepositoryError("Supabase client could not be initialized") from error
        return cls(client, table_name=table_name)

    def save(self, result: Module2Result) -> Module2Result:
        """Serialize and insert one result, preserving Task 16 duplicate semantics."""

        snapshot = _validated_snapshot(result)
        record = {
            "scan_id": str(snapshot.scan_result.scan_id),
            "incident_id": str(snapshot.incident.incident_id),
            "collected_at": snapshot.evidence_pack.collected_at.isoformat(),
            "payload": _serialize_result(snapshot),
        }
        try:
            self._client.table(self._table_name).insert(record).execute()
        except Exception as error:
            if _is_duplicate_error(error):
                raise DuplicateInvestigationError(
                    f"an investigation is already stored for scan_id {snapshot.scan_result.scan_id}"
                ) from error
            raise Module2RepositoryError("Supabase investigation save failed") from error
        return _copy_result(snapshot)

    def get_by_scan_id(self, scan_id: UUID) -> Module2Result | None:
        """Retrieve one result by its canonical scan identity."""

        if not isinstance(scan_id, UUID):
            raise TypeError("scan_id must be a UUID")
        return self._get_one("scan_id", scan_id)

    def get_by_incident_id(self, incident_id: UUID) -> Module2Result | None:
        """Retrieve one result by its existing incident identity."""

        if not isinstance(incident_id, UUID):
            raise TypeError("incident_id must be a UUID")
        return self._get_one("incident_id", incident_id)

    def list_investigations(
        self,
        *,
        limit: int = DEFAULT_INVESTIGATION_PAGE_LIMIT,
        offset: int = 0,
    ) -> list[Module2Result]:
        """Retrieve one ordered page without loading the full table."""

        _validate_pagination(limit=limit, offset=offset)
        try:
            response = (
                self._client.table(self._table_name)
                .select("payload")
                .order("collected_at", desc=True)
                .order("scan_id", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )
        except Exception as error:
            raise Module2RepositoryError("Supabase investigation listing failed") from error
        rows = getattr(response, "data", None)
        if rows is None:
            raise MalformedStoredInvestigationError("Supabase response did not contain investigation data")
        if not isinstance(rows, list):
            raise MalformedStoredInvestigationError("Supabase investigation list is malformed")
        results: list[Module2Result] = []
        for row in rows:
            if not isinstance(row, dict) or "payload" not in row:
                raise MalformedStoredInvestigationError("stored investigation record is malformed")
            results.append(_deserialize_result(row["payload"]))
        return results

    def _get_one(self, column: str, identifier: UUID) -> Module2Result | None:
        try:
            response = (
                self._client.table(self._table_name)
                .select("payload")
                .eq(column, str(identifier))
                .limit(1)
                .execute()
            )
        except Exception as error:
            raise Module2RepositoryError("Supabase investigation retrieval failed") from error
        rows = getattr(response, "data", None)
        if rows is None:
            raise MalformedStoredInvestigationError("Supabase response did not contain investigation data")
        if not rows:
            return None
        if not isinstance(rows[0], dict) or "payload" not in rows[0]:
            raise MalformedStoredInvestigationError("stored investigation record is malformed")
        return _deserialize_result(rows[0]["payload"])


def _validated_snapshot(result: Module2Result) -> Module2Result:
    if not isinstance(result, _module2_result_type()):
        raise TypeError("result must be a Module2Result")
    snapshot = _copy_result(result)
    scan_id = snapshot.scan_result.scan_id
    evidence = snapshot.evidence_pack
    incident = snapshot.incident
    report = snapshot.forensic_report

    if snapshot.enriched_threat_result.scan_id != scan_id:
        raise ValueError("enriched_threat_result.scan_id must match scan_result.scan_id")
    if evidence.scan_id != scan_id:
        raise ValueError("evidence_pack.scan_id must match scan_result.scan_id")
    if evidence.scan_result.scan_id != scan_id:
        raise ValueError("evidence_pack.scan_result.scan_id must match scan_result.scan_id")
    if incident.scan_id != scan_id:
        raise ValueError("incident.scan_id must match scan_result.scan_id")
    if report.scan_id != scan_id:
        raise ValueError("forensic_report.scan_id must match scan_result.scan_id")
    if report.incident_id != incident.incident_id:
        raise ValueError("forensic_report.incident_id must match incident.incident_id")
    if report.evidence_pack.evidence_id != evidence.evidence_id:
        raise ValueError("forensic_report.evidence_pack must match evidence_pack")
    if report.incident.incident_id != incident.incident_id:
        raise ValueError("forensic_report.incident must match incident")
    if incident.evidence_pack is not None and incident.evidence_pack.evidence_id != evidence.evidence_id:
        raise ValueError("incident.evidence_pack must match evidence_pack")
    if incident.evidence_reference is not None and incident.evidence_reference != str(evidence.evidence_id):
        raise ValueError("incident.evidence_reference must match evidence_pack.evidence_id")
    for decision in snapshot.response_decisions:
        if decision.scan_id != scan_id or decision.evidence_id != evidence.evidence_id:
            raise ValueError("response decision identities must match the investigation")
        if decision.incident_id is not None and decision.incident_id != incident.incident_id:
            raise ValueError("response decision incident_id must match incident.incident_id")
    for record in snapshot.action_records:
        if record.scan_id != scan_id:
            raise ValueError("action record scan_id must match scan_result.scan_id")
        if record.incident_id is not None and record.incident_id != incident.incident_id:
            raise ValueError("action record incident_id must match incident.incident_id")
    return snapshot


def _copy_result(result: Module2Result) -> Module2Result:
    """Copy all nested contracts and the opaque STIX bundle without rewriting IDs."""

    return deepcopy(result)


def _validate_pagination(*, limit: int, offset: int) -> None:
    """Keep repository callers from issuing unbounded or invalid list queries."""

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_INVESTIGATION_PAGE_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_INVESTIGATION_PAGE_LIMIT}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be greater than or equal to 0")


def _serialize_result(result: Module2Result) -> dict[str, Any]:
    """Produce JSON-compatible data without changing the caller-owned result."""

    payload = result.model_dump(mode="json", exclude={"stix_bundle"})
    try:
        payload["stix_bundle"] = json.loads(result.stix_bundle.serialize())
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("Module2Result.stix_bundle is not safely serializable") from error
    return payload


def _deserialize_result(payload: object) -> Module2Result:
    """Rebuild the complete result, including the existing STIX bundle object."""

    if not isinstance(payload, dict):
        raise MalformedStoredInvestigationError("stored investigation payload must be an object")
    data = deepcopy(payload)
    stix_payload = data.get("stix_bundle")
    if not isinstance(stix_payload, dict):
        raise MalformedStoredInvestigationError("stored STIX bundle is malformed")
    try:
        from stix2 import parse

        data["stix_bundle"] = parse(json.dumps(stix_payload))
        result = _module2_result_type().model_validate(data)
        return _validated_snapshot(result)
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as error:
        raise MalformedStoredInvestigationError("stored investigation payload is invalid") from error


def _is_duplicate_error(error: Exception) -> bool:
    """Recognize PostgreSQL's unique-constraint signal without exposing it."""

    return getattr(error, "code", None) == "23505" or "duplicate key" in str(error).lower()


def _module2_result_type():
    """Resolve the result contract lazily to keep the repository boundary acyclic."""

    from backend.module2.orchestrator import Module2Result

    return Module2Result
