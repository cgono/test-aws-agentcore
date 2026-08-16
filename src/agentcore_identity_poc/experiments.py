"""Token-safe isolation experiment runners for the AgentCore Identity POC."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

PolicyMode = Literal["broad", "scoped"]
Outcome = Literal["pass", "denied", "fail", "authorization_required"]
_RECOVERY_COMMAND = (
    ".venv/bin/python scripts/provision_agentcore.py --apply"
)


class ExperimentConfigurationError(ValueError):
    """An experiment could not establish evidence with the required controls."""


class ExperimentTimeout(RuntimeError):
    """IAM policy changes did not converge during the bounded observation window."""


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

    def as_details(self) -> dict[str, str | None]:
        """Return only aliases and result metadata suitable for evidence output."""
        return {
            "principal_alias": self.principal_alias,
            "asserted_workload": self.asserted_workload,
            "user_alias": self.user_alias,
            "policy_mode": self.policy_mode,
            "provider": self.provider,
            "aws_error_category": self.aws_error_category,
        }


@dataclass(frozen=True)
class WorkloadAttempt:
    """The sanitized outcome of one provider reachability attempt."""

    outcome: Outcome
    aws_error_category: str | None = None


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
    validate_user: Callable[[str, str], str],
    get_workload_token: Callable[[str, str], str],
    observe_connection: Callable[[str, str], WorkloadAttempt],
    on_verified_subject_count: Callable[[int], None] | None = None,
) -> tuple[MatrixRow, ...]:
    """Validate two distinct users and record their independent vault observations."""
    if len(users) != 2 or len({alias for alias, _ in users}) != 2:
        raise ExperimentConfigurationError("H4a requires exactly two distinct validated users")

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
        rows.append(
            MatrixRow(
                principal_alias=principal_alias,
                asserted_workload=workload_name,
                user_alias=user_alias,
                policy_mode="scoped",
                provider=provider,
                outcome=attempt.outcome,
                aws_error_category=_empty_to_none(attempt.aws_error_category),
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

    principal_alias = policy_manager.caller_identity()
    if not principal_alias:
        raise ExperimentConfigurationError("H4b requires a non-empty AWS principal alias")

    rows: list[MatrixRow] = []
    broad_applied = False
    restoration_failed = False
    try:
        policy_manager.apply_broad_policy()
        broad_applied = True
        _observe_until_converged(
            rows=rows,
            principal_alias=principal_alias,
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
            principal_alias=principal_alias,
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
    principal_alias: str,
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
        attempts = tuple(attempt_provider(workload_name) for workload_name in workload_names)
        matrix_rows = tuple(
            MatrixRow(
                principal_alias=principal_alias,
                asserted_workload=workload_name,
                user_alias=user_alias,
                policy_mode=policy_mode,
                provider=provider,
                outcome=attempt.outcome,
                aws_error_category=_empty_to_none(attempt.aws_error_category),
            )
            for workload_name, attempt in zip(workload_names, attempts, strict=True)
        )
        rows.extend(matrix_rows)
        if record_row is not None:
            for row in matrix_rows:
                record_row(row)
        if tuple(attempt.outcome for attempt in attempts) == expected_outcomes:
            return
        if clock() >= deadline:
            raise ExperimentTimeout(f"IAM {policy_mode} policy did not converge within 60 seconds")
        sleep(min(1.0, max(0.0, deadline - clock())))


def _empty_to_none(value: str | None) -> str | None:
    return value or None
