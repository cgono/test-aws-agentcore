"""Deterministic suitability assessment from sanitized POC evidence."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Never

from agentcore_identity_poc.redaction import UnsafeEvidenceError, assert_safe_evidence

REQUIRED_HYPOTHESES: Final = ("H1", "H2", "H3", "H4a", "H4b", "H5", "H6", "H7", "H8")
MANDATORY_HYPOTHESES: Final = ("H1", "H2", "H3", "H4a", "H6", "H7", "H8")
TERMINAL_OUTCOMES: Final = frozenset({"pass", "fail"})
_TERMINAL_OPERATION: Final = "assessment_terminal"
_MILLISECOND_FIELDS: Final = frozenset({"backoff_ms", "latency_ms", "p50_ms", "p95_ms"})
_COUNT_FIELDS: Final = frozenset(
    {
        "actual_probe_concurrency",
        "cold_sample_count",
        "documented_quota",
        "eligible_event_count",
        "lookback_minutes",
        "requests",
        "retry_attempts",
        "sample_count",
        "temporal_target",
        "throttle_count",
        "warm_sample_count",
        "workers",
    }
)
_RAW_SECRET_TEXT_PATTERN: Final = re.compile(
    r"(?:access_token|refresh_token|client_secret|authorization)\s*[\"':=]",
    re.IGNORECASE,
)
_CAMEL_CASE_BOUNDARY: Final = re.compile(r"([a-z0-9])([A-Z])")
_ACRONYM_BOUNDARY: Final = re.compile(r"([A-Z]+)([A-Z][a-z])")
_FIELD_SEPARATOR: Final = re.compile(r"[^A-Za-z0-9]+")
_RAW_RESPONSE_FIELDS: Final = frozenset(
    {"provider_response", "raw_response", "raw_provider_response", "response_body"}
)
_STAGE_NAMES: Final = frozenset({"workload", "google", "drive"})
_STAGE_TIMING_FIELDS: Final = frozenset(
    {"cold_p50_ms", "cold_p95_ms", "warm_p50_ms", "warm_p95_ms"}
)
_SOURCE_OPERATIONS: Final = {
    "H1": frozenset({"acquire_inbound_token", "validate_inbound_token", "workload_token"}),
    "H2": frozenset({"obo_token"}),
    "H3": frozenset(
        {"google_vault_token", "provider_expiry_unavailable", "fresh_token_comparison"}
    ),
    "H4a": frozenset({"user_isolation"}),
    "H4b": frozenset({"workload_isolation"}),
    "H6": frozenset(
        {"synthetic_resource", "google_drive_metadata", "measure_latency", "measure_concurrency"}
    ),
    "H7": frozenset(
        {
            "measure_latency",
            "measure_concurrency",
            "expiry_issue",
            "fresh_token_comparison",
            "obo_after_inbound_expiry",
            "audit_attribution",
        }
    ),
    "H8": frozenset({"google_revocation_probe", "offboard_google"}),
}


class AssessmentError(ValueError):
    """Raised when evidence cannot support a deterministic assessment."""


def load_terminal_results(evidence_path: Path) -> dict[str, str]:
    """Load exactly one explicit terminal observation for every hypothesis."""

    terminal: dict[str, list[str]] = {hypothesis: [] for hypothesis in REQUIRED_HYPOTHESES}
    for row in load_sanitized_observations(evidence_path):
        if _is_terminal(row):
            hypothesis = row["hypothesis"]
            outcome = row["outcome"]
            if isinstance(hypothesis, str) and isinstance(outcome, str) and hypothesis in terminal:
                terminal[hypothesis].append(outcome)

    missing = [hypothesis for hypothesis, outcomes in terminal.items() if not outcomes]
    ambiguous = [hypothesis for hypothesis, outcomes in terminal.items() if len(outcomes) != 1]
    if missing or ambiguous:
        parts: list[str] = []
        if missing:
            parts.append("missing terminal evidence for " + ", ".join(missing))
        if ambiguous:
            parts.append("expected exactly one terminal result for " + ", ".join(ambiguous))
        raise AssessmentError("; ".join(parts))
    return {hypothesis: outcomes[0] for hypothesis, outcomes in terminal.items()}


def load_sanitized_observations(evidence_path: Path) -> tuple[dict[str, object], ...]:
    """Load safe observations without retaining unvalidated provider responses."""

    try:
        lines = Path(evidence_path).read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise AssessmentError("sanitized evidence is unavailable") from error

    observations: list[dict[str, object]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise AssessmentError(f"sanitized evidence has an empty row at line {line_number}")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise AssessmentError(
                f"sanitized evidence has invalid JSON at line {line_number}"
            ) from error
        _validate_row(row, line_number)
        if not isinstance(row, dict):
            raise AssessmentError(f"sanitized evidence row {line_number} is not an object")
        observations.append(row)
    return tuple(observations)


def finalize_terminal_evidence(
    evidence_path: Path,
    result_selections: Sequence[str],
    output_path: Path,
    *,
    h5_compatibility_reviewed: bool,
    allow_deferred_failures: bool,
) -> None:
    """Write minimal terminal evidence selected against actual sanitized observations."""

    selected_results = _parse_result_selections(result_selections)
    observations = load_sanitized_observations(evidence_path)
    if any(_is_terminal(row) for row in observations):
        raise AssessmentError("terminal evidence must be finalized from nonterminal observations")
    observed_evidence = {
        (hypothesis, operation, outcome)
        for row in observations
        for hypothesis, operation, outcome in [
            (row["hypothesis"], row["operation"], row["outcome"])
        ]
        if isinstance(hypothesis, str) and isinstance(operation, str) and isinstance(outcome, str)
    }
    for hypothesis in REQUIRED_HYPOTHESES:
        if hypothesis == "H5":
            if not h5_compatibility_reviewed:
                raise AssessmentError("H5 requires explicit compatibility review")
            continue
        source_outcomes = {
            outcome
            for observed_hypothesis, operation, outcome in observed_evidence
            if observed_hypothesis == hypothesis and operation in _SOURCE_OPERATIONS[hypothesis]
        }
        if selected_results[hypothesis] == "pass" and "pass" not in source_outcomes:
            raise AssessmentError(
                f"passing terminal result lacks passing source evidence for {hypothesis}"
            )
        if (
            selected_results[hypothesis] == "fail"
            and not any(outcome != "pass" for outcome in source_outcomes)
            and not allow_deferred_failures
        ):
            raise AssessmentError(
                f"failing terminal result requires non-pass evidence for {hypothesis}"
            )

    rows = [
        {
            "hypothesis": hypothesis,
            "operation": _TERMINAL_OPERATION,
            "outcome": selected_results[hypothesis],
            "details": {"terminal": True},
        }
        for hypothesis in REQUIRED_HYPOTHESES
    ]
    encoded = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)
    atomic_write_text(output_path, encoded)


def atomic_write_text(output_path: Path, content: str) -> None:
    """Replace an assessment artifact atomically without weakening its file permissions."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as temporary_file:
            temporary_file.write(content)
        os.chmod(temporary_path, 0o600)
        temporary_path.replace(output_path)
    except OSError:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def decide(
    results: Mapping[str, str],
    *,
    iam_acceptable: bool,
    custom_provider_plausible: bool,
    audit_acceptable: bool = True,
    latency_acceptable: bool = True,
    quota_acceptable: bool = True,
) -> str:
    """Apply the design decision rule without inferring unobserved success."""

    del custom_provider_plausible  # H5 rejects only the custom-provider production path.
    if any(results.get(hypothesis) != "pass" for hypothesis in MANDATORY_HYPOTHESES):
        return "reject_or_defer"
    if results.get("H4b") != "pass" or not iam_acceptable:
        return "reject_or_defer"
    if not audit_acceptable or not latency_acceptable or not quota_acceptable:
        return "reject_or_defer"
    return "adopt_with_caveats"


def render_markdown(
    results: Mapping[str, str],
    decision: str,
    *,
    custom_provider_plausible: bool = True,
) -> str:
    """Render status-only Markdown; provider responses are deliberately never copied."""

    custom_provider_status = "plausible_but_unproven" if custom_provider_plausible else "rejected"
    rows = "\n".join(
        _markdown_row(hypothesis, results[hypothesis]) for hypothesis in REQUIRED_HYPOTHESES
    )
    return (
        "# AgentCore Identity Suitability Assessment\n\n"
        "## Evidence Status\n\n"
        "| Hypothesis | Terminal result | Assessment note |\n"
        "| --- | --- | --- |\n"
        f"{rows}\n\n"
        "## Decision\n\n"
        f"**{decision}**\n\n"
        f"Custom-provider production path: **{custom_provider_status}**. "
        "This status does not change the general AgentCore decision; it determines only whether "
        "the intended custom-provider path may proceed.\n\n"
        "This report intentionally contains terminal statuses and assessment conclusions only. "
        "It does not reproduce provider responses, tokens, client credentials, authorization URLs, "
        "or other evidence details.\n"
    )


def _validate_row(row: object, line_number: int) -> None:
    if not isinstance(row, Mapping):
        raise AssessmentError(f"sanitized evidence row {line_number} is not an object")
    if _contains_raw_response_alias(row):
        raise AssessmentError(f"sanitized evidence row {line_number} is unsafe")
    try:
        assert_safe_evidence(row)
    except UnsafeEvidenceError as error:
        raise AssessmentError(f"sanitized evidence row {line_number} is unsafe") from error
    if _contains_raw_secret_text(row):
        raise AssessmentError(f"sanitized evidence row {line_number} is unsafe")
    hypothesis = row.get("hypothesis")
    operation = row.get("operation")
    outcome = row.get("outcome")
    details = row.get("details")
    if (
        not isinstance(hypothesis, str)
        or not isinstance(operation, str)
        or not isinstance(outcome, str)
        or not isinstance(details, Mapping)
    ):
        raise AssessmentError(
            f"sanitized evidence row {line_number} has an invalid observation shape"
        )
    if _is_terminal(row) and outcome not in TERMINAL_OUTCOMES:
        raise AssessmentError(
            f"sanitized evidence row {line_number} has an invalid terminal outcome"
        )
    _validate_measurements(details, line_number)


def _is_terminal(row: Mapping[str, object] | Mapping[object, object]) -> bool:
    details = row.get("details")
    return (
        row.get("operation") == _TERMINAL_OPERATION
        and isinstance(details, Mapping)
        and details.get("terminal") is True
    )


def _validate_measurements(value: Mapping[object, object], line_number: int) -> None:
    for key, item in value.items():
        if not isinstance(key, str):
            raise AssessmentError(
                f"sanitized evidence row {line_number} has an invalid measurement key"
            )
        if key in _MILLISECOND_FIELDS or key in _COUNT_FIELDS:
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise AssessmentError(
                    f"sanitized evidence row {line_number} has an invalid measurement unit "
                    f"for {key}"
                )
        elif key == "stage_latency_ms":
            _validate_stage_latency(item, line_number)
        elif isinstance(item, Mapping):
            _validate_measurements(item, line_number)


def _contains_raw_secret_text(value: object) -> bool:
    if isinstance(value, str):
        return bool(_RAW_SECRET_TEXT_PATTERN.search(value))
    if isinstance(value, Mapping):
        return any(_contains_raw_secret_text(item) for item in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_raw_secret_text(item) for item in value)
    return False


def _contains_raw_response_alias(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and _normalize_field_name(key) in _RAW_RESPONSE_FIELDS:
                return True
            if _contains_raw_response_alias(item):
                return True
    if isinstance(value, list | tuple):
        return any(_contains_raw_response_alias(item) for item in value)
    return False


def _normalize_field_name(key: str) -> str:
    snake_case = _ACRONYM_BOUNDARY.sub(r"\1_\2", key)
    snake_case = _CAMEL_CASE_BOUNDARY.sub(r"\1_\2", snake_case)
    return _FIELD_SEPARATOR.sub("_", snake_case).strip("_").casefold()


def _parse_result_selections(result_selections: Sequence[str]) -> dict[str, str]:
    selected: dict[str, str] = {}
    for selection in result_selections:
        hypothesis, separator, outcome = selection.partition("=")
        if (
            separator != "="
            or hypothesis not in REQUIRED_HYPOTHESES
            or outcome not in TERMINAL_OUTCOMES
        ):
            raise AssessmentError("results must use HYPOTHESIS=pass or HYPOTHESIS=fail")
        if hypothesis in selected:
            raise AssessmentError(f"duplicate terminal result for {hypothesis}")
        selected[hypothesis] = outcome
    missing = [hypothesis for hypothesis in REQUIRED_HYPOTHESES if hypothesis not in selected]
    if missing:
        raise AssessmentError("missing terminal results for " + ", ".join(missing))
    return selected


def _validate_stage_latency(value: object, line_number: int) -> None:
    if not isinstance(value, Mapping) or set(value) != _STAGE_NAMES:
        _raise_invalid_measurement(line_number, "stage_latency_ms")
    for stage_name in _STAGE_NAMES:
        stage = value.get(stage_name)
        if not isinstance(stage, Mapping) or set(stage) != _STAGE_TIMING_FIELDS:
            _raise_invalid_measurement(line_number, "stage_latency_ms")
        for timing_name in _STAGE_TIMING_FIELDS:
            timing = stage.get(timing_name)
            if timing is not None and (
                isinstance(timing, bool) or not isinstance(timing, int) or timing < 0
            ):
                _raise_invalid_measurement(line_number, "stage_latency_ms")


def _raise_invalid_measurement(line_number: int, field: str) -> Never:
    raise AssessmentError(
        f"sanitized evidence row {line_number} has an invalid measurement unit for {field}"
    )


def _hypothesis_note(hypothesis: str, outcome: str) -> str:
    if hypothesis == "H3":
        return (
            "Current API limitation: provider-token expiry is not available without retaining "
            "a raw provider token."
        )
    if hypothesis == "H5" and outcome != "pass":
        return "This rejects only the custom-provider production path."
    return "Terminal evidence recorded."


def _markdown_row(hypothesis: str, outcome: str) -> str:
    return f"| {hypothesis} | {outcome} | {_hypothesis_note(hypothesis, outcome)} |"
