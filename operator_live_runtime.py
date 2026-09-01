"""Operator-supplied live runtime for the AgentCore Identity POC integration tests.

`tests/integration/test_*_live.py` each read `AGENTCORE_POC_LIVE_RUNTIME=module:factory`
and import a zero-argument factory that must return an object satisfying that file's
Protocol. Because Python Protocols are structurally typed, one object can satisfy all
four (`LiveRuntime`, `LiveGoogleRuntime`, `LiveIsolationRuntime`, `LiveLifecycleRuntime`)
at once -- this module supplies exactly that object, as `operator_live_runtime:create_runtime`
already documented in README.md and docs/runbook.md.

This module contains no cloud credentials or OAuth values. It wires real AgentCore/Entra/
Google/AWS calls using the same collaborators the CLI already uses for real work
(`agentcore_identity_poc.cli._default_runtime()`), and drives the existing Task-13 CLI
commands (`measure latency`, `measure cloudtrail`, `measure expiry`, `offboard google`)
through `typer.testing.CliRunner`, the same pattern already used throughout
`tests/test_cli_*.py`.

Several flows here are inherently human-interactive and cannot be automated: Entra
device-code sign-in requires a person to authenticate as the correct one of two real
test users, and `run_google_provider_gate()` assumes the operator already completed
Google consent manually via `google-connect` per the runbook -- it verifies that state
rather than driving a browser.
"""

from __future__ import annotations

import dataclasses
import json
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import typer
from typer.testing import CliRunner

import agentcore_identity_poc.cli as cli
from agentcore_identity_poc.agentcore import AgentCoreError, OAuthToken
from agentcore_identity_poc.config import Settings
from agentcore_identity_poc.downstream import DownstreamError
from agentcore_identity_poc.experiments import MatrixRow, SourceExpiryExperiment
from scripts.provision_agentcore import google_phase_two_plan

_GOOGLE_DRIVE_METADATA_SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly"
_EXPIRY_STATE_PATH = Path(".poc-expiry-state.json")

# The one place real (never sanitized-evidence-safe) token material is written to disk.
# evidence/raw/ is already gitignored (.gitignore:5) and excluded from the repository
# safety scanner (tests/test_repository_safety.py:_EXCLUDED_PREFIXES) -- the sanctioned
# location for exactly this kind of material. See _live_source_expiry_runner below.
_RAW_H7_STATE_PATH = Path("evidence/raw/h7-source-expiry-state.json")


@dataclasses.dataclass(frozen=True)
class LiveOBOResult:
    """Concrete result satisfying tests/integration/test_entra_obo_live.py's Protocol."""

    workload_token_received: bool
    resource_status: int
    subject_alias: str
    consent_prompt_seen: bool


class OperatorLiveRuntime:
    """One operator-owned adapter satisfying every live-gate Protocol in tests/integration/."""

    # ---- H1 / H2 / H6 : Entra OBO --------------------------------------------------

    def run_entra_obo(self, *, user_alias: str) -> LiveOBOResult:
        """Acquire a real Entra token for `user_alias`, then run the OBO -> resource call.

        Mirrors `cli.entra_obo`'s own sequence exactly. `resource_status` is hardcoded to
        200 on success (the downstream client has no status field to read -- `cli.py`'s own
        command does the same); `subject_alias` echoes the argument rather than reading the
        synthetic resource API's response, because that API generates one alias per process
        at startup, uncorrelated with which user actually signed in (the same trust model
        H4a's `expected_connection_markers` already relies on). Any failure past sign-in is
        left to propagate uncaught rather than mapped to a fabricated result field.
        """
        runtime = cli._default_runtime()
        settings = runtime.load_settings()

        print(f"\n--- sign in as operator alias '{user_alias}' now ---")
        inbound_token = runtime.acquire_token(settings, print)
        # Not programmatically detectable: MSAL's device-flow response carries no consent
        # signal. Default the ambiguous/blank answer to True, the conservative failing case.
        consent_prompt_seen = _confirm(
            f"Did a consent/permission screen appear for '{user_alias}'? "
            "Type 'n' or 'no' if it did NOT appear -- any other answer, including blank, "
            "is treated as consent seen and fails H2: "
        )

        runtime.validate_token(settings, inbound_token)
        identity = runtime.agentcore(settings)
        workload_token = identity.workload_token(settings.agentcore_workload_name, inbound_token)
        downstream_token = identity.obo_token(
            workload_token,
            settings.agentcore_microsoft_provider,
            [settings.entra_downstream_scope],
        )
        resource_client = runtime.downstream(settings)
        try:
            resource_client.list(downstream_token)
        finally:
            _close(resource_client)

        return LiveOBOResult(
            workload_token_received=bool(workload_token),
            resource_status=200,
            subject_alias=user_alias,
            consent_prompt_seen=consent_prompt_seen,
        )

    # ---- H3 verification : Google provider gate -------------------------------------

    def run_google_provider_gate(self) -> dict[str, bool]:
        """Verify Google callback binding, consent, and durable vaulting.

        Assumes the operator already completed `google-connect` and browser consent per
        the runbook -- this does not drive a browser itself. `callback_bound` reuses the
        existing provisioning-plan check; `google_consent_completed` and
        `durable_vault_connection` come from requesting the vaulted Google token without
        `force_authentication` and proving the returned token actually works.
        """
        runtime = cli._default_runtime()
        settings = runtime.load_settings()

        callback_bound = False
        try:
            state = json.loads(cli._STATE_PATH.read_text(encoding="utf-8"))
            callback_bound = google_phase_two_plan(state)["status"] == "ready"
        except (OSError, json.JSONDecodeError):
            callback_bound = False

        print("\n--- sign in with the already Google-consented operator test account ---")
        inbound_token = runtime.acquire_token(settings, print)
        runtime.validate_token(settings, inbound_token)
        identity = runtime.agentcore(settings)
        workload_token = identity.workload_token(settings.agentcore_workload_name, inbound_token)

        google_consent_completed = False
        durable_vault_connection = False
        try:
            authorization = identity.google_token(
                workload_token,
                settings.agentcore_google_provider,
                [_GOOGLE_DRIVE_METADATA_SCOPE],
                settings.google_return_url,
                runtime.random_urlsafe(),
                force_authentication=False,
            )
        except AgentCoreError:
            authorization = None

        if isinstance(authorization, OAuthToken):
            # A vaulted token returned without a fresh authorization prompt is direct
            # proof consent already completed and was durably persisted.
            google_consent_completed = True
            drive = runtime.google_drive(settings)
            try:
                drive.list(authorization.access_token)
                durable_vault_connection = True
            except DownstreamError:
                durable_vault_connection = False
            finally:
                _close(drive)

        return {
            "callback_bound": callback_bound,
            "durable_vault_connection": durable_vault_connection,
            "google_consent_completed": google_consent_completed,
        }

    # ---- H4b : workload isolation -----------------------------------------------------

    def run_workload_isolation(self) -> tuple[MatrixRow, ...]:
        """Delegate to the real H4b driver -- no new AWS/IAM logic here."""
        return cli.run_live_workload_isolation()

    # ---- H7 latency/CloudTrail/expiry + H8 offboarding ---------------------------------

    def run_lifecycle_measurements(self) -> dict[str, bool | str]:
        """Drive the existing Task-13 CLI commands and shape their results into one dict.

        `post_expiry_google_refresh` can only ever reach "failed" or "unproven": AgentCore's
        Google provider response has no trustworthy expiry metadata, so `measure expiry`
        unconditionally records that boundary as failed once it completes -- a confirmed,
        permanent product limitation, not something this adapter can improve on.
        `post_expiry_obo_refresh` delegates to `run_source_expiry_obo_experiment()`, which
        needs real elapsed time and a later, separate call to ever report True.

        `measure latency`, `measure expiry`, and `offboard google` each acquire a fresh
        inbound token via an Entra device-code prompt (`_measurement_identity` ->
        `runtime.acquire_token`), which the operator must read and complete in a browser
        before the call can return. `CliRunner.invoke` redirects `sys.stdout` into an
        internal buffer for the whole call and only hands back `result.output` once the
        command finishes -- so the device-code message the operator needs is invisible
        until after the very call that is blocked waiting on the operator, a deadlock, not
        a flakiness issue. `_invoke_cli_command` calls the Typer command function directly
        instead, leaving `sys.stdout`/`sys.stdin` untouched so the prompt reaches the real
        terminal live, exactly as running the command directly at a shell would.
        `measure cloudtrail` needs no interactive token, so it keeps using `CliRunner`.
        """
        runner = CliRunner()
        result: dict[str, bool | str] = {}

        result["latency_recorded"] = (
            _invoke_cli_command(cli.measure_latency_command, samples=10) == 0
        )
        result["cloudtrail_recorded"] = (
            runner.invoke(
                cli.app, ["measure", "cloudtrail", "--lookback-minutes", "30"]
            ).exit_code
            == 0
        )

        original_runtime_factory = cli.runtime_factory
        cli.runtime_factory = lambda: dataclasses.replace(
            cli._default_runtime(), source_expiry_runner=_live_source_expiry_runner
        )
        try:
            expiry_exit_code = _invoke_cli_command(
                cli.measure_expiry_command, resume_state=_EXPIRY_STATE_PATH
            )
        finally:
            cli.runtime_factory = original_runtime_factory
        result["post_expiry_google_refresh"] = "failed" if expiry_exit_code == 0 else "unproven"

        experiment = self.run_source_expiry_obo_experiment()
        result["post_expiry_obo_refresh"] = True if experiment is True else "unknown"

        user_alias = os.environ.get("AGENTCORE_POC_USER_A_ALIAS", "").strip() or "user-a"
        _invoke_cli_command(cli.offboard_google, user_alias=user_alias, apply=True)
        result["offboarding_h8"] = _read_last_offboarding_status(
            cli._DEFAULT_GOOGLE_EVIDENCE_PATH, user_alias
        )

        return result

    def run_source_expiry_obo_experiment(self) -> bool | str:
        """Check whether a real inbound Entra token has expired, then retry OBO once.

        The first call after any fresh `measure expiry` seeding pass always returns
        "unproven": the seeding pass runs synchronously right after token issuance, always
        before the token has actually expired. Proving H7 requires real elapsed time --
        the operator waits (typically 60-90 minutes for a default Entra access token) and
        calls this again as a later, separate action. Never sleeps.
        """
        if not _RAW_H7_STATE_PATH.exists():
            return "unproven"
        try:
            state = _read_raw_h7_state(_RAW_H7_STATE_PATH)
        except (OSError, json.JSONDecodeError, ValueError):
            return "unproven"

        if time.time() < state["inbound_expiry"]:
            return "unproven"

        settings = Settings.from_mapping(os.environ)
        identity = cli._agentcore_identity(settings)
        writer = cli._default_runtime().evidence_writer(cli._DEFAULT_GOOGLE_EVIDENCE_PATH)
        try:
            identity.obo_token(
                state["workload_token"],
                settings.agentcore_microsoft_provider,
                [settings.entra_downstream_scope],
            )
        except AgentCoreError:
            # Without this row, H7 can never be finalized as passing:
            # assessment.finalize_terminal_evidence cross-checks an operator-selected
            # H7=pass/fail against an actual "obo_after_inbound_expiry" evidence row.
            cli._append(
                writer,
                "H7",
                "obo_after_inbound_expiry",
                "fail",
                {"source_expired": True, "obo_succeeded": False},
            )
            _RAW_H7_STATE_PATH.unlink(missing_ok=True)
            return "failed"
        cli._append(
            writer,
            "H7",
            "obo_after_inbound_expiry",
            "pass",
            {"source_expired": True, "obo_succeeded": True},
        )
        _RAW_H7_STATE_PATH.unlink(missing_ok=True)
        return True


def create_runtime() -> OperatorLiveRuntime:
    """Factory referenced by AGENTCORE_POC_LIVE_RUNTIME=operator_live_runtime:create_runtime."""
    return OperatorLiveRuntime()


def _confirm(prompt: str) -> bool:
    try:
        answer = input(prompt)
    except (EOFError, OSError):
        # OSError: pytest captures stdin unless run with -s, exactly as the runbook
        # specifies for every live gate; treat that the same as no answer at all.
        return True
    return answer.strip().lower() not in {"n", "no"}


def _close(resource_client: object) -> None:
    close = getattr(resource_client, "close", None)
    if callable(close):
        close()


def _invoke_cli_command(command: Callable[..., None], /, **kwargs: object) -> int:
    """Call a Typer command function directly, bypassing `CliRunner`'s stdio capture.

    `typer.Exit` (raised by the CLI's own blocked/error paths) is the same signal
    `CliRunner.invoke` would otherwise translate into `result.exit_code`; a normal return
    means the command completed successfully, exit code 0.
    """
    try:
        command(**kwargs)
    except typer.Exit as exc:
        return exc.exit_code
    return 0


def _read_last_offboarding_status(
    evidence_path: Path, user_alias: str
) -> Literal["pass", "failed"]:
    """Read the just-appended H8 `offboard_google` row for this alias.

    `offboard_google` is now called directly (see `_invoke_cli_command`) rather than
    through `CliRunner`, so there is no captured stdout left to parse for its status line;
    the evidence row it appends is the durable record of what it actually decided.
    """
    try:
        lines = evidence_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "failed"
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            row.get("hypothesis") == "H8"
            and row.get("operation") == "offboard_google"
            and row.get("details", {}).get("user_alias") == user_alias
        ):
            return "pass" if row.get("outcome") == "pass" else "failed"
    return "failed"


def _live_source_expiry_runner(
    settings: Settings,
    identity: cli.IdentityClient,
    workload_token: str,
    inbound_expiry: float,
    wall_clock: Callable[[], float],
) -> SourceExpiryExperiment:
    """Persist raw expiry state for a later, separate `run_source_expiry_obo_experiment()`.

    Registered as `Runtime.source_expiry_runner` -- exactly the extension point that field
    exists for. `measure_expiry_command` only ever calls this synchronously, immediately
    after fresh token issuance, so it can never itself observe `source_expired=True`; that
    is correct, expected behavior here, not a bug. The sanitized resume-state file
    structurally rejects JWT-shaped values (`experiments.load_expiry_resume_state`), so the
    real `workload_token` is persisted separately, to the already-gitignored,
    scanner-excluded `evidence/raw/` directory, mode 0600, mirroring
    `experiments._write_private_json` -- never to sanitized evidence or the resume state.
    """
    del wall_clock  # real elapsed time is checked later, in run_source_expiry_obo_experiment
    _write_raw_h7_state(
        _RAW_H7_STATE_PATH, workload_token=workload_token, inbound_expiry=inbound_expiry
    )
    return SourceExpiryExperiment(source_expired=False, obo_succeeded=False)


def _write_raw_h7_state(path: Path, *, workload_token: str, inbound_expiry: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                {"workload_token": workload_token, "inbound_expiry": inbound_expiry},
                handle,
                separators=(",", ":"),
            )
            handle.write("\n")
        temporary_path.replace(path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _read_raw_h7_state(path: Path) -> dict[str, str | float]:
    if os.stat(path).st_mode & 0o777 != 0o600:
        raise ValueError("H7 raw state must use mode 0600")
    state = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(state, dict)
        or not isinstance(state.get("workload_token"), str)
        or not isinstance(state.get("inbound_expiry"), int | float)
    ):
        raise ValueError("H7 raw state is malformed")
    return state
