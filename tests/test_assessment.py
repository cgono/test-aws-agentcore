import json

import pytest
from typer.testing import CliRunner

from agentcore_identity_poc import cli
from agentcore_identity_poc.assessment import (
    AssessmentError,
    decide,
    finalize_terminal_evidence,
    load_sanitized_observations,
    load_terminal_results,
    render_markdown,
)
from agentcore_identity_poc.cli import app


def passing_results() -> dict[str, str]:
    return {
        "H1": "pass",
        "H2": "pass",
        "H3": "pass",
        "H4a": "pass",
        "H4b": "pass",
        "H5": "pass",
        "H6": "pass",
        "H7": "pass",
        "H8": "pass",
    }


def terminal_row(hypothesis: str, outcome: str = "pass", **details: object) -> dict[str, object]:
    return {
        "hypothesis": hypothesis,
        "operation": "assessment_terminal",
        "outcome": outcome,
        "details": {"terminal": True, **details},
    }


def write_evidence(tmp_path, rows: list[dict[str, object]]):
    path = tmp_path / "sanitized.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_rejects_when_mandatory_hypothesis_fails() -> None:
    results = passing_results() | {"H7": "fail"}
    assert decide(results, iam_acceptable=True, custom_provider_plausible=True) == "reject_or_defer"


def test_adopts_with_caveats_for_accepted_iam_dependency() -> None:
    assert decide(passing_results(), iam_acceptable=True, custom_provider_plausible=True) == (
        "adopt_with_caveats"
    )


def test_rejects_when_a_required_terminal_result_is_missing(tmp_path) -> None:
    evidence = write_evidence(
        tmp_path,
        [terminal_row(hypothesis) for hypothesis in passing_results() if hypothesis != "H8"],
    )

    with pytest.raises(AssessmentError, match="terminal evidence"):
        load_terminal_results(evidence)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("\n", "empty row"),
        ("not-json\n", "invalid JSON"),
        ("[]\n", "not an object"),
    ],
)
def test_sanitized_observation_loader_rejects_malformed_rows(
    tmp_path, content: str, message: str
) -> None:
    evidence = tmp_path / "sanitized.jsonl"
    evidence.write_text(content, encoding="utf-8")

    with pytest.raises(AssessmentError, match=message):
        load_sanitized_observations(evidence)


def test_sanitized_observation_loader_hides_missing_file_details(tmp_path) -> None:
    with pytest.raises(AssessmentError, match="sanitized evidence is unavailable"):
        load_sanitized_observations(tmp_path / "missing.jsonl")


def test_finalization_rejects_preexisting_terminal_evidence(tmp_path) -> None:
    evidence = write_evidence(tmp_path, [terminal_row("H1")])

    with pytest.raises(AssessmentError, match="terminal evidence"):
        finalize_terminal_evidence(
            evidence,
            [f"{hypothesis}=pass" for hypothesis in passing_results()],
            tmp_path / "terminal.jsonl",
            h5_compatibility_reviewed=True,
            allow_deferred_failures=False,
        )


def test_terminalization_requires_h5_compatibility_acknowledgement(tmp_path) -> None:
    evidence = write_evidence(tmp_path, _all_supported_nonterminal_rows())

    result = CliRunner().invoke(
        app,
        [
            "assessment-finalize",
            "--evidence",
            str(evidence),
            "--output",
            str(tmp_path / "terminal.jsonl"),
            *_result_arguments(),
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == '{"status":"blocked","category":"assessment_incomplete"}\n'


def test_rejects_ambiguous_terminal_results(tmp_path) -> None:
    evidence = write_evidence(
        tmp_path,
        [terminal_row(hypothesis) for hypothesis in passing_results()] + [terminal_row("H1")],
    )

    with pytest.raises(AssessmentError, match="exactly one"):
        load_terminal_results(evidence)


def test_rejects_markdown_terminal_outcome_before_report_rendering(tmp_path) -> None:
    rows = [terminal_row(hypothesis) for hypothesis in passing_results()]
    rows[0]["outcome"] = "pass | [injected](https://example.test)"
    evidence = write_evidence(tmp_path, rows)
    output = tmp_path / "assessment.md"

    result = CliRunner().invoke(
        app,
        ["report", "--evidence", str(evidence), "--output", str(output)],
    )

    assert result.exit_code == 2
    assert not output.exists()


def test_rejects_unsafe_raw_evidence_before_assessing(tmp_path) -> None:
    rows = [terminal_row(hypothesis) for hypothesis in passing_results()]
    rows[0]["details"] = {"terminal": True, "token": "secret-value"}
    evidence = write_evidence(tmp_path, rows)

    with pytest.raises(AssessmentError, match="sanitized"):
        load_terminal_results(evidence)


def test_rejects_raw_secret_looking_text_nested_in_an_ordinary_safe_field(tmp_path) -> None:
    rows = [terminal_row(hypothesis) for hypothesis in passing_results()]
    rows[0]["details"] = {
        "terminal": True,
        "provider_summary": '{"access_token":"not-a-jwt"}',
    }
    evidence = write_evidence(tmp_path, rows)

    with pytest.raises(AssessmentError, match="sanitized"):
        load_terminal_results(evidence)


def test_rejects_invalid_measurement_units(tmp_path) -> None:
    rows = [terminal_row(hypothesis) for hypothesis in passing_results()]
    rows[0]["details"] = {"terminal": True, "p95_ms": "100ms"}
    evidence = write_evidence(tmp_path, rows)

    with pytest.raises(AssessmentError, match="measurement"):
        load_terminal_results(evidence)


def test_accepts_real_emitted_stage_latency_shape(tmp_path) -> None:
    rows = [terminal_row(hypothesis) for hypothesis in passing_results()]
    rows[0]["details"] = {
        "terminal": True,
        "stage_latency_ms": {
            "workload": {
                "cold_p50_ms": 10,
                "cold_p95_ms": 12,
                "warm_p50_ms": 4,
                "warm_p95_ms": 5,
            },
            "google": {
                "cold_p50_ms": None,
                "cold_p95_ms": None,
                "warm_p50_ms": 9,
                "warm_p95_ms": 11,
            },
            "drive": {
                "cold_p50_ms": 3,
                "cold_p95_ms": 4,
                "warm_p50_ms": None,
                "warm_p95_ms": None,
            },
        },
    }

    assert load_terminal_results(write_evidence(tmp_path, rows)) == passing_results()


@pytest.mark.parametrize(
    "stage_latency",
    [
        {"workload": {"cold_p50_ms": 1}},
        {
            "workload": {"cold_p50_ms": 1, "cold_p95_ms": 1, "warm_p50_ms": 1, "warm_p95_ms": 1},
            "google": {"cold_p50_ms": 1, "cold_p95_ms": 1, "warm_p50_ms": 1, "warm_p95_ms": 1},
            "drive": {"cold_p50_ms": True, "cold_p95_ms": 1, "warm_p50_ms": 1, "warm_p95_ms": 1},
        },
    ],
)
def test_rejects_malformed_stage_latency_shape(tmp_path, stage_latency: object) -> None:
    rows = [terminal_row(hypothesis) for hypothesis in passing_results()]
    rows[0]["details"] = {"terminal": True, "stage_latency_ms": stage_latency}

    with pytest.raises(AssessmentError, match="measurement"):
        load_terminal_results(write_evidence(tmp_path, rows))


def test_rejects_unacceptable_iam_dependency() -> None:
    assert decide(passing_results(), iam_acceptable=False, custom_provider_plausible=True) == (
        "reject_or_defer"
    )


def test_custom_provider_incompatibility_only_rejects_that_path() -> None:
    assert decide(passing_results(), iam_acceptable=True, custom_provider_plausible=False) == (
        "adopt_with_caveats"
    )


@pytest.mark.parametrize("condition", ["audit", "latency", "quota"])
def test_rejects_unacceptable_operational_measurements(condition: str) -> None:
    acceptable = {"audit_acceptable": True, "latency_acceptable": True, "quota_acceptable": True}
    acceptable[f"{condition}_acceptable"] = False

    assert decide(
        passing_results(), iam_acceptable=True, custom_provider_plausible=True, **acceptable
    ) == ("reject_or_defer")


def test_report_command_writes_sanitized_summary_without_detail_values(tmp_path) -> None:
    evidence = write_evidence(
        tmp_path,
        [
            terminal_row(hypothesis, provider_summary="this-must-not-be-rendered")
            for hypothesis in passing_results()
        ],
    )
    output = tmp_path / "assessment.md"

    result = CliRunner().invoke(
        app,
        [
            "report",
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--iam-acceptable",
            "--audit-acceptable",
            "--latency-acceptable",
            "--quota-acceptable",
        ],
    )

    assert result.exit_code == 0
    rendered = output.read_text(encoding="utf-8")
    assert "this-must-not-be-rendered" not in rendered
    assert "adopt_with_caveats" in rendered


def test_report_command_rejects_raw_provider_response_field(tmp_path) -> None:
    rows = [terminal_row(hypothesis) for hypothesis in passing_results()]
    rows[0]["details"] = {"terminal": True, "provider_response": "safe-looking-content"}
    evidence = write_evidence(tmp_path, rows)
    output = tmp_path / "assessment.md"

    result = CliRunner().invoke(
        app,
        ["report", "--evidence", str(evidence), "--output", str(output)],
    )

    assert result.exit_code == 2
    assert not output.exists()


def test_rejects_nested_response_body_field_alias(tmp_path) -> None:
    rows = [terminal_row(hypothesis) for hypothesis in passing_results()]
    rows[0]["details"] = {"terminal": True, "metadata": {"responseBody": "safe-looking"}}

    with pytest.raises(AssessmentError, match="sanitized"):
        load_terminal_results(write_evidence(tmp_path, rows))


def test_rendered_report_marks_h3_api_limitation_when_it_fails() -> None:
    report = render_markdown(passing_results() | {"H3": "fail"}, "reject_or_defer")

    assert "H3" in report
    assert "Current API limitation" in report


def test_report_rejects_only_the_custom_provider_path_when_h5_fails(tmp_path) -> None:
    evidence = write_evidence(
        tmp_path,
        [
            terminal_row(hypothesis, "fail" if hypothesis == "H5" else "pass")
            for hypothesis in passing_results()
        ],
    )
    output = tmp_path / "assessment.md"

    result = CliRunner().invoke(
        app,
        [
            "report",
            "--evidence",
            str(evidence),
            "--output",
            str(output),
            "--iam-acceptable",
            "--audit-acceptable",
            "--latency-acceptable",
            "--quota-acceptable",
        ],
    )

    assert result.exit_code == 0
    rendered = output.read_text(encoding="utf-8")
    assert "**adopt_with_caveats**" in rendered
    assert "Custom-provider production path: **rejected**" in rendered


def _nonterminal_rows() -> list[dict[str, object]]:
    return [
        {"hypothesis": "H1", "operation": "workload_token", "outcome": "pass", "details": {}},
        {"hypothesis": "H2", "operation": "obo_token", "outcome": "pass", "details": {}},
        {
            "hypothesis": "H3",
            "operation": "provider_expiry_unavailable",
            "outcome": "fail",
            "details": {},
        },
        {"hypothesis": "H4a", "operation": "user_isolation", "outcome": "pass", "details": {}},
        {
            "hypothesis": "H4b",
            "operation": "workload_isolation",
            "outcome": "pass",
            "details": {},
        },
        {
            "hypothesis": "H6",
            "operation": "synthetic_resource",
            "outcome": "pass",
            "details": {},
        },
        {
            "hypothesis": "H7",
            "operation": "expiry_issue",
            "outcome": "pass",
            "details": {},
        },
        {"hypothesis": "H8", "operation": "offboard_google", "outcome": "pass", "details": {}},
    ]


def _result_arguments(h3_outcome: str = "pass", h8_outcome: str = "pass") -> list[str]:
    arguments: list[str] = []
    for hypothesis in passing_results():
        outcome = h3_outcome if hypothesis == "H3" else h8_outcome if hypothesis == "H8" else "pass"
        arguments.extend(["--result", f"{hypothesis}={outcome}"])
    return arguments


def _all_supported_nonterminal_rows() -> list[dict[str, object]]:
    rows = _nonterminal_rows()
    rows[2] = {
        "hypothesis": "H3",
        "operation": "google_vault_token",
        "outcome": "pass",
        "details": {},
    }
    return rows


def test_terminalization_preserves_h3_failure_and_report_rejects(tmp_path) -> None:
    evidence = write_evidence(tmp_path, _nonterminal_rows())
    terminal = tmp_path / "terminal.jsonl"
    assessment = tmp_path / "assessment.md"

    finalize = CliRunner().invoke(
        app,
        [
            "assessment-finalize",
            "--evidence",
            str(evidence),
            "--output",
            str(terminal),
            "--h5-compatibility-reviewed",
            *_result_arguments(h3_outcome="fail"),
        ],
    )
    report = CliRunner().invoke(
        app,
        [
            "report",
            "--evidence",
            str(terminal),
            "--output",
            str(assessment),
            "--iam-acceptable",
            "--audit-acceptable",
            "--latency-acceptable",
            "--quota-acceptable",
        ],
    )

    assert finalize.exit_code == 0
    assert report.exit_code == 0
    terminal_rows = [json.loads(line) for line in terminal.read_text(encoding="utf-8").splitlines()]
    assert [row["hypothesis"] for row in terminal_rows] == list(passing_results())
    assert all(row["operation"] == "assessment_terminal" for row in terminal_rows)
    assert all(row["details"] == {"terminal": True} for row in terminal_rows)
    assert terminal_rows[2]["outcome"] == "fail"
    assert "**reject_or_defer**" in assessment.read_text(encoding="utf-8")


def test_terminalization_creates_adoptable_report_with_passing_source_evidence(tmp_path) -> None:
    evidence = write_evidence(tmp_path, _all_supported_nonterminal_rows())
    terminal = tmp_path / "terminal.jsonl"
    assessment = tmp_path / "assessment.md"

    finalize = CliRunner().invoke(
        app,
        [
            "assessment-finalize",
            "--evidence",
            str(evidence),
            "--output",
            str(terminal),
            "--h5-compatibility-reviewed",
            *_result_arguments(),
        ],
    )
    report = CliRunner().invoke(
        app,
        [
            "report",
            "--evidence",
            str(terminal),
            "--output",
            str(assessment),
            "--iam-acceptable",
            "--audit-acceptable",
            "--latency-acceptable",
            "--quota-acceptable",
        ],
    )

    assert finalize.exit_code == 0
    assert report.exit_code == 0
    assert "**adopt_with_caveats**" in assessment.read_text(encoding="utf-8")


def test_terminalization_rejects_h3_failure_selected_as_pass(tmp_path) -> None:
    evidence = write_evidence(tmp_path, _nonterminal_rows())
    terminal = tmp_path / "terminal.jsonl"

    result = CliRunner().invoke(
        app,
        [
            "assessment-finalize",
            "--evidence",
            str(evidence),
            "--output",
            str(terminal),
            "--h5-compatibility-reviewed",
            *_result_arguments(),
        ],
    )

    assert result.exit_code == 2
    assert not terminal.exists()


def test_terminalization_requires_explicit_acknowledgement_for_deferred_failure(tmp_path) -> None:
    evidence = write_evidence(tmp_path, _all_supported_nonterminal_rows())
    terminal = tmp_path / "terminal.jsonl"
    command = [
        "assessment-finalize",
        "--evidence",
        str(evidence),
        "--output",
        str(terminal),
        "--h5-compatibility-reviewed",
        *_result_arguments(h8_outcome="fail"),
    ]

    blocked = CliRunner().invoke(app, command)
    deferred = CliRunner().invoke(app, [*command, "--allow-deferred-failures"])

    assert blocked.exit_code == 2
    assert deferred.exit_code == 0
    rows = [json.loads(line) for line in terminal.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["outcome"] == "fail"


@pytest.mark.parametrize(
    "result_arguments",
    [
        _result_arguments()[:-2],
        _result_arguments() + ["--result", "H1=fail"],
        [*(_result_arguments()[:-2]), "--result", "H8=unproven"],
    ],
)
def test_terminalization_rejects_missing_duplicate_or_noncanonical_results(
    tmp_path, result_arguments: list[str]
) -> None:
    evidence = write_evidence(tmp_path, _nonterminal_rows())
    terminal = tmp_path / "terminal.jsonl"

    result = CliRunner().invoke(
        app,
        [
            "assessment-finalize",
            "--evidence",
            str(evidence),
            "--output",
            str(terminal),
            "--h5-compatibility-reviewed",
            *result_arguments,
        ],
    )

    assert result.exit_code == 2
    assert not terminal.exists()


def test_terminalization_rejects_evidence_from_the_wrong_hypothesis_operation(tmp_path) -> None:
    rows = _nonterminal_rows()
    rows[0]["operation"] = "synthetic_resource"
    evidence = write_evidence(tmp_path, rows)
    terminal = tmp_path / "terminal.jsonl"

    result = CliRunner().invoke(
        app,
        [
            "assessment-finalize",
            "--evidence",
            str(evidence),
            "--output",
            str(terminal),
            "--h5-compatibility-reviewed",
            *_result_arguments(),
        ],
    )

    assert result.exit_code == 2
    assert not terminal.exists()


def test_report_failure_preserves_existing_output_and_redacts_filesystem_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    evidence = write_evidence(
        tmp_path,
        [terminal_row(hypothesis) for hypothesis in passing_results()],
    )
    output = tmp_path / "assessment.md"
    output.write_text("known-good", encoding="utf-8")

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise OSError("do not disclose this path")

    monkeypatch.setattr(cli, "atomic_write_text", fail_write)
    result = CliRunner().invoke(
        app,
        ["report", "--evidence", str(evidence), "--output", str(output)],
    )

    assert result.exit_code == 2
    assert output.read_text(encoding="utf-8") == "known-good"
    assert result.stdout == '{"status":"blocked","category":"assessment_output_unavailable"}\n'
