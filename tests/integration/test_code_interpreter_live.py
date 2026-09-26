"""Opt-in Phase 1 live gate. OPERATOR-RUN in an interactive terminal after terraform apply."""

from __future__ import annotations

import functools
import os
from importlib.metadata import version
from pathlib import Path

import pytest

from agentcore_code_interpreter_poc import probes
from agentcore_code_interpreter_poc.observations import Observation, append_observations
from agentcore_code_interpreter_poc.sessions import assume_role_session, open_session
from scripts.terraform_outputs import load_terraform_outputs

pytestmark = pytest.mark.integration

OBSERVATIONS = Path("evidence/raw/code-interpreter-observations.jsonl")
TERRAFORM_ROOT = Path("infra/terraform/poc")


@pytest.fixture(scope="module")
def outputs() -> dict[str, str]:
    if "AGENTCORE_POC_LIVE" not in os.environ:
        pytest.skip("set AGENTCORE_POC_LIVE=1 after aws sso login and terraform apply")
    return load_terraform_outputs(TERRAFORM_ROOT)


def _config(outputs: dict[str, str], identifier: str, caller: str = "sso") -> dict[str, str]:
    return {
        "region": outputs["aws_region"],
        "identifier": identifier,
        "caller": caller,
        "bedrock_agentcore_sdk": version("bedrock-agentcore"),
    }


def _factory(
    outputs: dict[str, str], identifier: str, boto_session: object = None
) -> probes.SessionFactory:
    return functools.partial(
        open_session, outputs["aws_region"], identifier=identifier, boto_session=boto_session
    )


def _record(observations: list[Observation]) -> None:
    append_observations(OBSERVATIONS, observations)
    for observation in observations:
        print(observation.as_dict())
    failed = [observation.as_dict() for observation in observations if observation.status != "pass"]
    assert not failed, failed


def test_q1_1_state_persistence(outputs: dict[str, str]) -> None:
    builtin = outputs["builtin_code_interpreter_id"]
    _record(probes.probe_state_persistence(_factory(outputs, builtin), _config(outputs, builtin)))


def test_q1_2_languages(outputs: dict[str, str]) -> None:
    builtin = outputs["builtin_code_interpreter_id"]
    _record(probes.probe_languages(_factory(outputs, builtin), _config(outputs, builtin)))


def test_q1_3_files(outputs: dict[str, str]) -> None:
    builtin = outputs["builtin_code_interpreter_id"]
    _record(probes.probe_files(_factory(outputs, builtin), _config(outputs, builtin)))


def test_q1_4_egress_builtin_interpreter(outputs: dict[str, str]) -> None:
    builtin = outputs["builtin_code_interpreter_id"]
    _record(
        probes.probe_egress(
            _factory(outputs, builtin), _config(outputs, builtin), expected_reachable=False
        )
    )


def test_q1_4_egress_custom_public_interpreter(outputs: dict[str, str]) -> None:
    custom = outputs["public_code_interpreter_id"]
    _record(
        probes.probe_egress(
            _factory(outputs, custom), _config(outputs, custom), expected_reachable=True
        )
    )


def test_q1_5_failure_modes(outputs: dict[str, str]) -> None:
    builtin = outputs["builtin_code_interpreter_id"]
    _record(probes.probe_failure_modes(_factory(outputs, builtin), _config(outputs, builtin)))


def test_q1_5_session_ttl(outputs: dict[str, str]) -> None:
    if "AGENTCORE_POC_SLOW" not in os.environ:
        pytest.skip("set AGENTCORE_POC_SLOW=1 to run the ~3 minute TTL probe")
    builtin = outputs["builtin_code_interpreter_id"]
    region = outputs["aws_region"]
    _record(
        probes.probe_session_ttl(
            lambda ttl: open_session(
                region, identifier=builtin, timeout_seconds=ttl, tolerate_stop_errors=True
            ),
            _config(outputs, builtin),
        )
    )


def test_q1_5_execution_limit(outputs: dict[str, str]) -> None:
    if "AGENTCORE_POC_SLOW" not in os.environ:
        pytest.skip("set AGENTCORE_POC_SLOW=1 to run the ~10 minute execution-limit probe")
    builtin = outputs["builtin_code_interpreter_id"]
    factory = functools.partial(
        open_session,
        outputs["aws_region"],
        identifier=builtin,
        timeout_seconds=900,
        tolerate_stop_errors=True,
    )
    _record(probes.probe_execution_limit(factory, _config(outputs, builtin)))


@pytest.mark.parametrize(
    "interpreter_output", ["builtin_code_interpreter_id", "public_code_interpreter_id"]
)
def test_q1_6_scoped_caller(outputs: dict[str, str], interpreter_output: str) -> None:
    identifier = outputs[interpreter_output]
    role = outputs["ci_caller_role_arn"]
    region = outputs["aws_region"]
    allowed = assume_role_session(role, region)
    denied = assume_role_session(role, region, session_policy=probes.INVOKE_EXCLUDED_SESSION_POLICY)
    _record(
        probes.probe_scoped_caller(
            _factory(outputs, identifier, allowed),
            _factory(outputs, identifier, denied),
            _config(outputs, identifier, caller="ci_caller_role"),
        )
    )
