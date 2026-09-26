from __future__ import annotations

import pytest

from agentcore_code_interpreter_poc.results import parse_tool_result


def _stream(*results: dict[str, object]) -> dict[str, object]:
    return {"stream": [{"result": result} for result in results]}


def test_structured_content_is_extracted() -> None:
    parsed = parse_tool_result(
        _stream(
            {
                "structuredContent": {"stdout": "42\n", "stderr": "", "exitCode": 0},
                "content": [{"type": "text", "text": "42\n"}],
                "isError": False,
            }
        )
    )

    assert parsed.stdout == "42\n"
    assert parsed.exit_code == 0
    assert parsed.is_error is False
    assert parsed.failed is False
    assert "42" in parsed.output
    assert parsed.shape == ("content", "isError", "structuredContent")


def test_text_only_content_is_collected() -> None:
    parsed = parse_tool_result(_stream({"content": [{"type": "text", "text": "hello"}]}))

    assert parsed.stdout == ""
    assert parsed.text == "hello"
    assert parsed.output == "hello"


def test_error_flag_marks_failure() -> None:
    parsed = parse_tool_result(
        _stream({"content": [{"type": "text", "text": "SyntaxError"}], "isError": True})
    )

    assert parsed.is_error is True
    assert parsed.failed is True


def test_non_zero_exit_code_marks_failure() -> None:
    parsed = parse_tool_result(_stream({"structuredContent": {"stdout": "", "exitCode": 2}}))

    assert parsed.failed is True


@pytest.mark.parametrize("status", ["failed", "canceled"])
def test_terminal_failure_task_status_marks_failure(status: str) -> None:
    parsed = parse_tool_result(_stream({"structuredContent": {"taskStatus": status}}))

    assert parsed.is_error is True
    assert parsed.failed is True


def test_completed_task_status_is_not_a_failure() -> None:
    parsed = parse_tool_result(
        _stream({"structuredContent": {"taskStatus": "completed", "exitCode": 0}})
    )

    assert parsed.failed is False


def test_exception_event_is_an_error_and_recorded_in_shape() -> None:
    parsed = parse_tool_result({"stream": [{"accessDeniedException": {"message": "no"}}]})

    assert parsed.is_error is True
    assert parsed.shape == ("event:accessDeniedException",)


def test_empty_response_is_empty() -> None:
    parsed = parse_tool_result({})

    assert parsed.output == ""
    assert parsed.exit_code is None
    assert parsed.failed is False


def test_boolean_exit_code_is_ignored() -> None:
    parsed = parse_tool_result(_stream({"structuredContent": {"exitCode": True}}))

    assert parsed.exit_code is None
