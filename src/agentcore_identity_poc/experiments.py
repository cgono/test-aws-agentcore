"""Token-safe isolation experiment runners for the AgentCore Identity POC."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

PolicyMode = Literal["broad", "scoped"]
Outcome = Literal["pass", "denied", "fail", "authorization_required"]
_RECOVERY_COMMAND = (
    ".venv/bin/python scripts/provision_agentcore.py --apply"
)
_DRIVE_MARKER_PATTERN = re.compile(r"[0-9a-f]{64}")
_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")
_JWT_SHAPED_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_EXPIRY_KINDS = frozenset({"inbound_jwt", "workload_token", "obo_token", "google_token"})


class ExperimentConfigurationError(ValueError):
    """An experiment could not establish evidence with the required controls."""


class ExperimentTimeout(RuntimeError):
    """IAM policy changes did not converge during the bounded observation window."""


class MeasurementConfigurationError(ValueError):
    """A measurement would create invalid or unsafe local evidence."""


class RetryableMeasurementError(RuntimeError):
    """An operation may be retried after a bounded backoff."""


class PolicyRestorationError(RuntimeError):
    """The deliberate broad policy could not be restored to the final scoped policy."""

    def __init__(self) -> None:
        super().__init__(
            f"could not restore the scoped IAM policy; recover with: {_RECOVERY_COMMAND}"
        )


@dataclass(frozen=True)
class MatrixRow:
    """One immutable, sanitized H4a/H4b experiment observation."""

    principal_alias: str
    asserted_workload: str
    user_alias: str
    policy_mode: PolicyMode
    provider: str
    outcome: Outcome
    aws_error_category: str | None
    connection_marker: str | None = None

    def as_details(self) -> dict[str, str | None]:
        """Return only aliases and result metadata suitable for evidence output."""
        details = {
            "principal_alias": self.principal_alias,
            "asserted_workload": self.asserted_workload,
            "user_alias": self.user_alias,
            "policy_mode": self.policy_mode,
            "provider": self.provider,
            "aws_error_category": self.aws_error_category,
        }
        if self.connection_marker is not None:
            details["connection_marker"] = self.connection_marker
        return details


@dataclass(frozen=True)
class WorkloadAttempt:
    """The sanitized outcome of one provider reachability attempt."""

    outcome: Outcome
    aws_error_category: str | None = None
    connection_marker: str | None = None


@dataclass(frozen=True)
class LatencySample:
    """One sanitized timing result, labeled to expose cold versus warm behavior."""

    cold: bool
    latency_ms: int


@dataclass(frozen=True)
class LatencyReport:
    """A bounded latency sample set and its nearest-rank percentiles."""

    samples: tuple[LatencySample, ...]
    p50_ms: int
    p95_ms: int


@dataclass(frozen=True)
class ConcurrencyReport:
    """Outcome summary for a bounded concurrent operation."""

    completed: int
    maximum_workers: int


@dataclass(frozen=True)
class ExpiryObservation:
    """An in-memory token lifecycle observation; the token is never persisted."""

    kind: str
    token: str
    issued_at: float
    expires_at: float | None
    drive_metadata_observed: bool = False

    @property
    def expiry_known(self) -> bool:
        """Whether a supported claim or response supplied an expiry timestamp."""
        return self.expires_at is not None


@dataclass(frozen=True)
class StoredExpiryObservation:
    """A token-safe persisted lifecycle observation."""

    kind: str
    issued_at: float
    expires_at: float | None
    expiry_known: bool
    fingerprint: str


@dataclass(frozen=True)
class ExpiryComparison:
    """Token-safe comparison of one resumed token type to its original observation."""

    kind: str
    previous_fingerprint: str
    new_fingerprint: str
    fingerprint_changed: bool
    prior_expiry_known: bool
    prior_expires_at: float | None


def measure_latency(
    *,
    samples: int,
    operation: Callable[[bool], object],
    clock: Callable[[], float] = time.monotonic,
) -> LatencyReport:
    """Measure one cold call then bounded warm calls without retaining operation results."""
    if samples < 2 or samples > 100:
        raise MeasurementConfigurationError("latency samples must be between 2 and 100")
    results: list[LatencySample] = []
    for index in range(samples):
        started_at = clock()
        operation(index == 0)
        results.append(LatencySample(cold=index == 0, latency_ms=_elapsed_ms(clock() - started_at)))
    latencies = sorted(sample.latency_ms for sample in results)
    return LatencyReport(
        samples=tuple(results),
        p50_ms=_nearest_rank(latencies, 0.50),
        p95_ms=_nearest_rank(latencies, 0.95),
    )


def measure_bounded_concurrency(
    *, workers: int, requests: int, request: Callable[[int], object]
) -> ConcurrencyReport:
    """Execute a fixed number of requests while capping executor parallelism."""
    if workers < 1 or workers > 20:
        raise MeasurementConfigurationError("workers must be between 1 and 20")
    if requests < 1 or requests > 200:
        raise MeasurementConfigurationError("requests must be between 1 and 200")
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(request, index) for index in range(requests)]
        for future in futures:
            future.result()
    return ConcurrencyReport(completed=requests, maximum_workers=min(workers, requests))


def retry_with_backoff[T](
    operation: Callable[[], T],
    *,
    sleep: Callable[[float], None] = time.sleep,
    random_unit: Callable[[], float] | None = None,
    max_attempts: int = 4,
    on_retry: Callable[[float], None] | None = None,
) -> T:
    """Retry only explicit throttling failures using jittered exponential delays."""
    if max_attempts < 1 or max_attempts > 5:
        raise MeasurementConfigurationError("max attempts must be between 1 and 5")
    random = random_unit or secrets.SystemRandom().random
    for attempt in range(max_attempts):
        try:
            return operation()
        except RetryableMeasurementError as error:
            if attempt == max_attempts - 1:
                raise
            jitter = random()
            if jitter < 0 or jitter > 1:
                raise MeasurementConfigurationError(
                    "retry jitter must be between zero and one"
                ) from error
            delay = 0.1 * (2**attempt) * (1 + jitter / 2)
            if on_retry is not None:
                on_retry(delay)
            sleep(delay)
    raise AssertionError("retry loop must either return or raise")


def token_fingerprint(token: str, *, run_salt: str) -> str:
    """Return an opaque per-run SHA-256 fingerprint suitable for evidence."""
    if not token or not run_salt:
        raise MeasurementConfigurationError("tokens and run salt must be non-empty")
    return hashlib.sha256(f"{run_salt}:{token}".encode()).hexdigest()


def record_expiry_state(
    path: Path,
    *,
    project_id: str,
    entries: Sequence[ExpiryObservation],
    run_salt: str | None = None,
) -> float | None:
    """Persist only token fingerprints and timestamps, then return the next resume time."""
    if not project_id:
        raise MeasurementConfigurationError("project ID must be non-empty")
    if {entry.kind for entry in entries} != _EXPIRY_KINDS or len(entries) != len(_EXPIRY_KINDS):
        raise MeasurementConfigurationError(
            "expiry evidence requires one entry for each token kind"
        )
    if any(
        not entry.token or (entry.expires_at is not None and entry.expires_at < entry.issued_at)
        for entry in entries
    ):
        raise MeasurementConfigurationError("expiry observations must have valid token timestamps")
    salt = run_salt or secrets.token_urlsafe(32)
    stored_entries = [
        {
            "kind": entry.kind,
            "issued_at": entry.issued_at,
            "expires_at": entry.expires_at,
            "expiry_known": entry.expiry_known,
            "fingerprint": token_fingerprint(entry.token, run_salt=salt),
        }
        for entry in entries
    ]
    _write_private_json(path, {"project_id": project_id, "entries": stored_entries})
    known_expiries = [entry.expires_at for entry in entries if entry.expires_at is not None]
    return min(known_expiries) if known_expiries else None


def load_expiry_resume_state(path: Path, *, project_id: str) -> tuple[StoredExpiryObservation, ...]:
    """Load an expiry resume state only when it is private and structurally token-safe."""
    try:
        if os.stat(path).st_mode & 0o777 != 0o600:
            raise MeasurementConfigurationError("expiry resume state must use mode 0600")
        state = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise MeasurementConfigurationError("could not read expiry resume state") from error
    except json.JSONDecodeError as error:
        raise MeasurementConfigurationError("expiry resume state must be JSON") from error
    if _contains_jwt_shaped_value(state):
        raise MeasurementConfigurationError("expiry resume state contains JWT-shaped values")
    if not isinstance(state, Mapping) or state.get("project_id") != project_id:
        raise MeasurementConfigurationError(
            "expiry resume state does not belong to current project"
        )
    entries = state.get("entries")
    if not isinstance(entries, list) or len(entries) != len(_EXPIRY_KINDS):
        raise MeasurementConfigurationError("expiry resume state entries are invalid")
    results: list[StoredExpiryObservation] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise MeasurementConfigurationError("expiry resume state entries are invalid")
        kind = entry.get("kind")
        issued_at = entry.get("issued_at")
        expires_at = entry.get("expires_at")
        expiry_known = entry.get("expiry_known")
        fingerprint = entry.get("fingerprint")
        if (
            kind not in _EXPIRY_KINDS
            or not isinstance(issued_at, int | float)
            or not isinstance(expiry_known, bool)
            or (expiry_known and not isinstance(expires_at, int | float))
            or (not expiry_known and expires_at is not None)
            or not isinstance(fingerprint, str)
            or not _FINGERPRINT_PATTERN.fullmatch(fingerprint)
            or (isinstance(expires_at, int | float) and expires_at < issued_at)
        ):
            raise MeasurementConfigurationError(
                "expiry resume state contains JWT-shaped or invalid values"
            )
        results.append(
            StoredExpiryObservation(
                kind,
                float(issued_at),
                float(expires_at) if isinstance(expires_at, int | float) else None,
                expiry_known,
                fingerprint,
            )
        )
    if {entry.kind for entry in results} != _EXPIRY_KINDS:
        raise MeasurementConfigurationError("expiry resume state token kinds are invalid")
    return tuple(results)


def compare_expiry_observations(
    previous: Sequence[StoredExpiryObservation],
    fresh: Sequence[ExpiryObservation],
    *,
    prior_run_salt: str,
) -> tuple[ExpiryComparison, ...]:
    """Compare fresh tokens with the prior lifecycle run using the prior opaque salt."""
    prior_by_kind = {entry.kind: entry for entry in previous}
    if set(prior_by_kind) != _EXPIRY_KINDS or {entry.kind for entry in fresh} != _EXPIRY_KINDS:
        raise MeasurementConfigurationError("expiry comparison requires every token kind")
    return tuple(
        ExpiryComparison(
            kind=entry.kind,
            previous_fingerprint=prior_by_kind[entry.kind].fingerprint,
            new_fingerprint=token_fingerprint(entry.token, run_salt=prior_run_salt),
            fingerprint_changed=(
                prior_by_kind[entry.kind].fingerprint
                != token_fingerprint(entry.token, run_salt=prior_run_salt)
            ),
            prior_expiry_known=prior_by_kind[entry.kind].expiry_known,
            prior_expires_at=prior_by_kind[entry.kind].expires_at,
        )
        for entry in fresh
    )


def _nearest_rank(values: Sequence[int], percentile: float) -> int:
    if not values:
        raise MeasurementConfigurationError("cannot calculate percentiles without samples")
    return values[max(0, math.ceil(percentile * len(values)) - 1)]


def _elapsed_ms(seconds: float) -> int:
    return max(0, round(seconds * 1_000))


def _write_private_json(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
        temporary_path.replace(path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _contains_jwt_shaped_value(value: object) -> bool:
    if isinstance(value, str):
        return _JWT_SHAPED_PATTERN.fullmatch(value) is not None
    if isinstance(value, Mapping):
        return any(
            _contains_jwt_shaped_value(key) or _contains_jwt_shaped_value(item)
            for key, item in value.items()
        )
    if isinstance(value, list | tuple):
        return any(_contains_jwt_shaped_value(item) for item in value)
    return False


class WorkloadPolicyManager(Protocol):
    """The minimum IAM surface required for the deliberate H4b policy transition."""

    def caller_identity(self) -> str: ...

    def apply_broad_policy(self) -> None: ...

    def apply_scoped_policy(self) -> None: ...


def run_user_isolation(
    *,
    principal_alias: str,
    workload_name: str,
    provider: str,
    users: Sequence[tuple[str, str]],
    expected_connection_markers: Mapping[str, str],
    validate_user: Callable[[str, str], str],
    get_workload_token: Callable[[str, str], str],
    observe_connection: Callable[[str, str], WorkloadAttempt],
    on_verified_subject_count: Callable[[int], None] | None = None,
) -> tuple[MatrixRow, ...]:
    """Validate two distinct users and record their independent vault observations."""
    if len(users) != 2 or len({alias for alias, _ in users}) != 2:
        raise ExperimentConfigurationError("H4a requires exactly two distinct validated users")
    user_aliases = {alias for alias, _ in users}
    if (
        set(expected_connection_markers) != user_aliases
        or len(set(expected_connection_markers.values())) != len(user_aliases)
        or not all(
            _DRIVE_MARKER_PATTERN.fullmatch(marker)
            for marker in expected_connection_markers.values()
        )
    ):
        raise ExperimentConfigurationError(
            "H4a requires one sanitized expected Drive marker for each user alias"
        )

    validated_users = tuple(
        (user_alias, inbound_token, validate_user(user_alias, inbound_token))
        for user_alias, inbound_token in users
    )
    if len({subject for _, _, subject in validated_users}) != 2:
        raise ExperimentConfigurationError("H4a requires two distinct verified Entra subjects")
    if on_verified_subject_count is not None:
        on_verified_subject_count(2)

    rows: list[MatrixRow] = []
    for user_alias, inbound_token, _ in validated_users:
        workload_token = get_workload_token(user_alias, inbound_token)
        attempt = observe_connection(user_alias, workload_token)
        expected_marker = expected_connection_markers[user_alias]
        connection_matches = attempt.connection_marker == expected_marker
        rows.append(
            MatrixRow(
                principal_alias=principal_alias,
                asserted_workload=workload_name,
                user_alias=user_alias,
                policy_mode="scoped",
                provider=provider,
                outcome=(
                    attempt.outcome
                    if attempt.outcome != "pass"
                    else "pass" if connection_matches else "fail"
                ),
                aws_error_category=_empty_to_none(attempt.aws_error_category),
                connection_marker=attempt.connection_marker,
            )
        )
    return tuple(rows)


def assert_same_aws_principal(rows: Sequence[MatrixRow]) -> str:
    """Reject H4b evidence unless every row came from the same AWS caller."""
    principals = {row.principal_alias for row in rows}
    if len(principals) != 1:
        raise ExperimentConfigurationError("H4b requires every result under the same AWS principal")
    return next(iter(principals))


def run_workload_isolation(
    *,
    policy_manager: WorkloadPolicyManager,
    workload_names: Sequence[str],
    user_alias: str,
    provider: str,
    acknowledge_broad_policy: bool,
    attempt_provider: Callable[[str], WorkloadAttempt],
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    propagation_timeout_seconds: float = 60,
    record_row: Callable[[MatrixRow], None] | None = None,
) -> tuple[MatrixRow, ...]:
    """Measure broad and scoped IAM reachability under one AWS principal.

    Every provider call is returned as a matrix row.  The policy transition is
    considered converged only after broad policy permits both workloads and the
    scoped policy permits only the approved (first) workload.
    """
    if not acknowledge_broad_policy:
        raise ExperimentConfigurationError("--acknowledge-broad-policy is required")
    if len(workload_names) != 2 or workload_names[0] == workload_names[1]:
        raise ExperimentConfigurationError("H4b requires exactly two distinct workload names")
    if propagation_timeout_seconds <= 0 or propagation_timeout_seconds > 60:
        raise ExperimentConfigurationError(
            "IAM propagation timeout must be greater than zero and at most 60"
        )

    rows: list[MatrixRow] = []
    expected_principal_alias: list[str] = []
    broad_applied = False
    restoration_failed = False
    try:
        policy_manager.apply_broad_policy()
        broad_applied = True
        _observe_until_converged(
            rows=rows,
            policy_manager=policy_manager,
            expected_principal_alias=expected_principal_alias,
            workload_names=workload_names,
            user_alias=user_alias,
            provider=provider,
            policy_mode="broad",
            attempt_provider=attempt_provider,
            expected_outcomes=("pass", "pass"),
            clock=clock,
            sleep=sleep,
            propagation_timeout_seconds=propagation_timeout_seconds,
            record_row=record_row,
        )

        try:
            policy_manager.apply_scoped_policy()
        except Exception:
            restoration_failed = True
            raise
        _observe_until_converged(
            rows=rows,
            policy_manager=policy_manager,
            expected_principal_alias=expected_principal_alias,
            workload_names=workload_names,
            user_alias=user_alias,
            provider=provider,
            policy_mode="scoped",
            attempt_provider=attempt_provider,
            expected_outcomes=("pass", "denied"),
            clock=clock,
            sleep=sleep,
            propagation_timeout_seconds=propagation_timeout_seconds,
            record_row=record_row,
        )
    finally:
        if broad_applied:
            try:
                policy_manager.apply_scoped_policy()
            except Exception:
                restoration_failed = True
        if restoration_failed:
            raise PolicyRestorationError()

    assert_same_aws_principal(rows)
    return tuple(rows)


def _observe_until_converged(
    *,
    rows: list[MatrixRow],
    policy_manager: WorkloadPolicyManager,
    expected_principal_alias: list[str],
    workload_names: Sequence[str],
    user_alias: str,
    provider: str,
    policy_mode: PolicyMode,
    attempt_provider: Callable[[str], WorkloadAttempt],
    expected_outcomes: tuple[Outcome, Outcome],
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    propagation_timeout_seconds: float,
    record_row: Callable[[MatrixRow], None] | None,
) -> None:
    deadline = clock() + propagation_timeout_seconds
    while True:
        attempts: list[WorkloadAttempt] = []
        matrix_rows: list[MatrixRow] = []
        for workload_name in workload_names:
            _verify_current_principal(policy_manager, expected_principal_alias)
            attempt = attempt_provider(workload_name)
            confirmed_principal_alias = _verify_current_principal(
                policy_manager, expected_principal_alias
            )
            attempts.append(attempt)
            matrix_rows.append(
                MatrixRow(
                    principal_alias=confirmed_principal_alias,
                    asserted_workload=workload_name,
                    user_alias=user_alias,
                    policy_mode=policy_mode,
                    provider=provider,
                    outcome=attempt.outcome,
                    aws_error_category=_empty_to_none(attempt.aws_error_category),
                )
            )
        matrix_rows_tuple = tuple(matrix_rows)
        rows.extend(matrix_rows)
        if record_row is not None:
            for row in matrix_rows_tuple:
                record_row(row)
        if tuple(attempt.outcome for attempt in attempts) == expected_outcomes:
            return
        if clock() >= deadline:
            raise ExperimentTimeout(f"IAM {policy_mode} policy did not converge within 60 seconds")
        sleep(min(1.0, max(0.0, deadline - clock())))


def _empty_to_none(value: str | None) -> str | None:
    return value or None


def _verify_current_principal(
    policy_manager: WorkloadPolicyManager, expected_principal_alias: list[str]
) -> str:
    principal_alias = policy_manager.caller_identity()
    if not principal_alias:
        raise ExperimentConfigurationError("H4b requires a non-empty AWS principal alias")
    if expected_principal_alias and principal_alias != expected_principal_alias[0]:
        raise ExperimentConfigurationError("H4b requires every result under the same AWS principal")
    if not expected_principal_alias:
        expected_principal_alias.append(principal_alias)
    return principal_alias
