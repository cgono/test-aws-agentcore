# Code Interpreter POC (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provision AgentCore Code Interpreter resources with Terraform and answer verification questions Q1.1–Q1.6 and TF.1–TF.2 with live, recorded observations.

**Architecture:** A reusable Terraform module (`agentcore_code_interpreter`) plus a POC root module (`infra/terraform/poc`) create a custom PUBLIC-network interpreter and a scoped caller IAM role. A new Python package (`agentcore_code_interpreter_poc`) holds small, unit-tested probe functions. An opt-in live pytest gate runs the probes against real AWS and appends observations to an ignored JSONL file. The operator then writes them up in `docs/code-interpreter-findings.md`.

**Tech Stack:** Python 3.13, `bedrock-agentcore==1.18.1` (`CodeInterpreter` client), `boto3==1.43.31`, pytest, Terraform 1.14.x, `hashicorp/aws` provider `6.66.0`, `terraform test` with `mock_provider`.

**Spec:** `docs/superpowers/specs/2026-09-25-code-interpreter-runtime-poc-design.md`

## Global Constraints

- **Task 0 is a hard gate.** If Code Interpreter is not available in the chosen region, stop and report to the user. Do not continue with other tasks.
- **Tasks marked "OPERATOR-RUN" need a human at an interactive terminal:** `aws sso login`, live pytest gates, `terraform apply`, and `terraform destroy`. A subagent must stop at these tasks and hand over. Backgrounded or piped runs of live gates hang.
- All AWS resources are created by Terraform. No boto3 provisioning scripts, no AgentCore CLI, no starter toolkit, no ECR, no CodeBuild.
- Terraform: `required_version = "~> 1.14.0"` in the root and `>= 1.9.0` in modules. The provider is `hashicorp/aws`, pinned `= 6.66.0` in the root and `>= 6.66.0` in modules. Commit the root `.terraform.lock.hcl` only.
- Code Interpreter names and runtime names must match `^[a-zA-Z][a-zA-Z0-9_]{0,47}$`, so use no hyphens.
- Build IAM policy JSON with `jsonencode()`, not `data "aws_iam_policy_document"`, so `terraform test` with `mock_provider` can assert on real policy content.
- No new Python dependencies. Import untyped libraries as the repo already does: `import boto3  # type: ignore[import-untyped]` and `from botocore.exceptions import ClientError  # type: ignore[import-untyped]`.
- Observations go only to `evidence/raw/` (gitignored). No tokens, secrets, or raw AWS error messages in observations; record error **codes** only.
- Tracked files must pass `tests/test_repository_safety.py`: no JWT-shaped strings, no bearer-header literals, no real tenant IDs, no email addresses. Use the example account ID `123456789012` in tests.
- Phase 0 gate (the full local check, updated in Task 6). Every command must exit 0 before any commit.
- The coverage floor is 90% of the combined total across all measured packages.
- Signed commits: use a plain `git commit`. If 1Password signing fails, stop and ask the user. Do not add `--no-gpg-sign` on your own.

---

### Task 0: Preflight and branch (OPERATOR-RUN, hard gate)

**Files:**
- Modify: `.env` (untracked; add `AWS_REGION`)

- [ ] **Step 1: Refresh AWS SSO**

Run: `aws sso login`
Expected: the browser sign-in completes. `aws sts get-caller-identity` then prints the account.

- [ ] **Step 2: Set the region in `.env`**

`.env` currently has no `AWS_REGION` line. Add:

```
AWS_REGION=ap-southeast-1
```

Keep `AWS_BUDGET_NAME` as it is. The Identity POC's budget is reused.

- [ ] **Step 3: Check service availability (read-only)**

```bash
set -a; source .env; set +a
aws bedrock-agentcore-control list-code-interpreters --region "$AWS_REGION" --max-results 5
aws budgets describe-budget --account-id "$(aws sts get-caller-identity --query Account --output text)" \
  --budget-name "$AWS_BUDGET_NAME" --query Budget.BudgetName --output text
```

Expected: the first command returns JSON (`codeInterpreterSummaries`, possibly empty) and not an endpoint or `UnknownOperation` error. The second prints the budget name.
**If the first command fails with an endpoint or not-available error: STOP. Report to the user that Code Interpreter is not available in this region. Do not continue.**

- [ ] **Step 4: Create the working branch in a worktree**

```bash
git worktree add .worktrees/agentcore-code-interpreter-runtime-poc -b feature/agentcore-code-interpreter-runtime-poc
cd .worktrees/agentcore-code-interpreter-runtime-poc
python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'
cp ../../.env .env
```

Run every later task from this worktree.

---

### Task 1: Terraform module `agentcore_code_interpreter` with tests

**Files:**
- Modify: `.gitignore`
- Create: `infra/terraform/modules/agentcore_code_interpreter/versions.tf`
- Create: `infra/terraform/modules/agentcore_code_interpreter/variables.tf`
- Create: `infra/terraform/modules/agentcore_code_interpreter/main.tf`
- Create: `infra/terraform/modules/agentcore_code_interpreter/outputs.tf`
- Test: `infra/terraform/modules/agentcore_code_interpreter/tests/module.tftest.hcl`

**Interfaces:**
- Produces: module inputs `name` (string), `description` (string, default null), `network_mode` (`PUBLIC|SANDBOX|VPC`), `execution_role_arn` (string, default null), `vpc_subnet_ids` (list(string), default []), `vpc_security_group_ids` (list(string), default []), `tags` (map(string), default {}). Outputs `code_interpreter_id` and `code_interpreter_arn`.

- [ ] **Step 1: Ignore Terraform working files**

Append to `.gitignore`:

```
.terraform/
*.tfstate
*.tfstate.*
*.tfplan
terraform.tfvars
infra/terraform/modules/**/.terraform.lock.hcl
```

- [ ] **Step 2: Write the failing module tests**

Create `infra/terraform/modules/agentcore_code_interpreter/tests/module.tftest.hcl`:

```hcl
mock_provider "aws" {}

variables {
  name         = "poc_ci_test"
  network_mode = "PUBLIC"
}

run "public_mode_has_no_vpc_config" {
  command = plan

  assert {
    condition     = aws_bedrockagentcore_code_interpreter.this.network_configuration[0].network_mode == "PUBLIC"
    error_message = "network_mode must pass through unchanged"
  }

  assert {
    condition     = length(aws_bedrockagentcore_code_interpreter.this.network_configuration[0].vpc_config) == 0
    error_message = "PUBLIC mode must not render a vpc_config block"
  }
}

run "vpc_mode_renders_vpc_config" {
  command = plan

  variables {
    network_mode           = "VPC"
    vpc_subnet_ids         = ["subnet-00000000000000001"]
    vpc_security_group_ids = ["sg-00000000000000001"]
  }

  assert {
    condition     = length(aws_bedrockagentcore_code_interpreter.this.network_configuration[0].vpc_config) == 1
    error_message = "VPC mode must render exactly one vpc_config block"
  }
}

run "sandbox_requires_execution_role" {
  command = plan

  variables {
    network_mode = "SANDBOX"
  }

  expect_failures = [var.execution_role_arn]
}

run "rejects_unknown_network_mode" {
  command = plan

  variables {
    network_mode = "OPEN"
  }

  expect_failures = [var.network_mode]
}

run "rejects_hyphenated_name" {
  command = plan

  variables {
    name = "poc-ci-test"
  }

  expect_failures = [var.name]
}

run "vpc_requires_subnets" {
  command = plan

  variables {
    network_mode           = "VPC"
    vpc_security_group_ids = ["sg-00000000000000001"]
  }

  expect_failures = [var.vpc_subnet_ids]
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

```bash
cd infra/terraform/modules/agentcore_code_interpreter
printf 'terraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n      version = ">= 6.66.0"\n    }\n  }\n}\n' > versions.tf
terraform init -backend=false -input=false
terraform test
```

Expected: FAIL, with errors that `aws_bedrockagentcore_code_interpreter.this` and the variables are not declared.

- [ ] **Step 4: Write the module**

`versions.tf` (replaces the stub):

```hcl
terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.66.0"
    }
  }
}
```

`variables.tf`:

```hcl
variable "name" {
  type        = string
  description = "Code Interpreter name: a letter, then letters, digits, or underscores (max 48)."

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{0,47}$", var.name))
    error_message = "name must match ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ (no hyphens)."
  }
}

variable "description" {
  type    = string
  default = null
}

variable "network_mode" {
  type        = string
  description = "PUBLIC, SANDBOX, or VPC."

  validation {
    condition     = contains(["PUBLIC", "SANDBOX", "VPC"], var.network_mode)
    error_message = "network_mode must be PUBLIC, SANDBOX, or VPC."
  }
}

variable "execution_role_arn" {
  type    = string
  default = null

  validation {
    condition     = var.network_mode != "SANDBOX" || var.execution_role_arn != null
    error_message = "execution_role_arn is required when network_mode is SANDBOX."
  }
}

variable "vpc_subnet_ids" {
  type    = list(string)
  default = []

  validation {
    condition     = var.network_mode != "VPC" || length(var.vpc_subnet_ids) > 0
    error_message = "vpc_subnet_ids is required when network_mode is VPC."
  }
}

variable "vpc_security_group_ids" {
  type    = list(string)
  default = []

  validation {
    condition     = var.network_mode != "VPC" || length(var.vpc_security_group_ids) > 0
    error_message = "vpc_security_group_ids is required when network_mode is VPC."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
```

`main.tf`:

```hcl
resource "aws_bedrockagentcore_code_interpreter" "this" {
  name               = var.name
  description        = var.description
  execution_role_arn = var.execution_role_arn
  tags               = var.tags

  network_configuration {
    network_mode = var.network_mode

    dynamic "vpc_config" {
      for_each = var.network_mode == "VPC" ? [1] : []

      content {
        security_groups = var.vpc_security_group_ids
        subnets         = var.vpc_subnet_ids
      }
    }
  }
}
```

`outputs.tf`:

```hcl
output "code_interpreter_id" {
  value = aws_bedrockagentcore_code_interpreter.this.code_interpreter_id
}

output "code_interpreter_arn" {
  value = aws_bedrockagentcore_code_interpreter.this.code_interpreter_arn
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

```bash
terraform fmt -check -recursive
terraform validate
terraform test
```

Expected: `fmt` prints nothing, `validate` prints `Success!`, and `terraform test` reports `6 passed, 0 failed`.

- [ ] **Step 6: Commit**

```bash
cd ../../../..
git add .gitignore infra/terraform/modules/agentcore_code_interpreter
git commit -m "feat: add agentcore_code_interpreter Terraform module with tests"
```

---

### Task 2: POC root module — budget guard, custom interpreter, scoped caller role

**Files:**
- Create: `infra/terraform/poc/versions.tf`
- Create: `infra/terraform/poc/providers.tf`
- Create: `infra/terraform/poc/variables.tf`
- Create: `infra/terraform/poc/main.tf`
- Create: `infra/terraform/poc/code_interpreter.tf`
- Create: `infra/terraform/poc/outputs.tf`
- Create: `infra/terraform/poc/.terraform.lock.hcl` (generated by `terraform init`)
- Test: `infra/terraform/poc/tests/code_interpreter.tftest.hcl`

**Interfaces:**
- Consumes: module `agentcore_code_interpreter` (Task 1).
- Produces: root variables `aws_region`, `aws_budget_name`, `name_prefix` (default `"ci_rt_poc"`). Locals `account_id` and `builtin_code_interpreter_arn`. Outputs (all strings): `aws_region`, `builtin_code_interpreter_id`, `public_code_interpreter_id`, `ci_caller_role_arn`. Phase 2 adds `runtime.tf` to this root.

- [ ] **Step 1: Write the failing root test**

Create `infra/terraform/poc/tests/code_interpreter.tftest.hcl`:

```hcl
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
}

variables {
  aws_region      = "ap-southeast-1"
  aws_budget_name = "example-budget"
}

run "caller_role_is_scoped_to_code_interpreter_sessions" {
  command = apply

  assert {
    condition = toset(jsondecode(aws_iam_role_policy.ci_caller.policy).Statement[0].Action) == toset([
      "bedrock-agentcore:StartCodeInterpreterSession",
      "bedrock-agentcore:InvokeCodeInterpreter",
      "bedrock-agentcore:StopCodeInterpreterSession",
      "bedrock-agentcore:GetCodeInterpreterSession",
    ])
    error_message = "caller policy must allow exactly the four session actions"
  }

  assert {
    condition = contains(
      jsondecode(aws_iam_role_policy.ci_caller.policy).Statement[0].Resource,
      "arn:aws:bedrock-agentcore:ap-southeast-1:aws:code-interpreter/aws.codeinterpreter.v1",
    )
    error_message = "caller policy must cover the built-in interpreter"
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.ci_caller.policy).Statement) == 1
    error_message = "caller policy must have a single statement"
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.ci_caller.assume_role_policy).Statement[0].Condition.ArnLike["aws:PrincipalArn"]
      == "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/*"
    )
    error_message = "only SSO roles in this account may assume the caller role"
  }
}

run "exposes_builtin_interpreter_id" {
  command = plan

  assert {
    condition     = output.builtin_code_interpreter_id == "aws.codeinterpreter.v1"
    error_message = "built-in interpreter id must be exposed"
  }
}
```

The module's own tests (Task 1) cover its network mode and name validation, so the root test does not repeat them.

- [ ] **Step 2: Run the test and confirm it fails**

```bash
mkdir -p infra/terraform/poc && cd infra/terraform/poc
printf 'terraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n      version = "= 6.66.0"\n    }\n  }\n}\n' > versions.tf
terraform init -backend=false -input=false
terraform test
```

Expected: FAIL, with undeclared resources, variables, and module.

- [ ] **Step 3: Write the root module**

`versions.tf` (replaces the stub):

```hcl
terraform {
  required_version = "~> 1.14.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.66.0"
    }
  }
}
```

`providers.tf`:

```hcl
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      project    = "agentcore-ci-runtime-poc"
      managed_by = "terraform"
    }
  }
}
```

`variables.tf`:

```hcl
variable "aws_region" {
  type = string

  validation {
    condition     = length(var.aws_region) > 0
    error_message = "aws_region must be set (TF_VAR_aws_region)."
  }
}

variable "aws_budget_name" {
  type = string

  validation {
    condition     = length(var.aws_budget_name) > 0
    error_message = "aws_budget_name must be set (TF_VAR_aws_budget_name)."
  }
}

variable "name_prefix" {
  type    = string
  default = "ci_rt_poc"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]{0,19}$", var.name_prefix))
    error_message = "name_prefix must match ^[a-z][a-z0-9_]{0,19}$."
  }
}
```

`main.tf`:

```hcl
data "aws_caller_identity" "current" {}

# Plan fails here when the named budget does not exist: the POC's cost guard.
data "aws_budgets_budget" "required" {
  name = var.aws_budget_name
}

locals {
  account_id                   = data.aws_caller_identity.current.account_id
  builtin_code_interpreter_id  = "aws.codeinterpreter.v1"
  builtin_code_interpreter_arn = "arn:aws:bedrock-agentcore:${var.aws_region}:aws:code-interpreter/${local.builtin_code_interpreter_id}"
}
```

`code_interpreter.tf`:

```hcl
module "public_code_interpreter" {
  source = "../modules/agentcore_code_interpreter"

  name         = "${var.name_prefix}_public_ci"
  description  = "POC custom interpreter with PUBLIC network mode (Q1.4)"
  network_mode = "PUBLIC"
}

resource "aws_iam_role" "ci_caller" {
  name                 = "${var.name_prefix}_ci_caller"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Condition = {
        ArnLike = {
          "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:role/aws-reserved/sso.amazonaws.com/*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ci_caller" {
  name = "code-interpreter-caller"
  role = aws_iam_role.ci_caller.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "UseCodeInterpreterSessions"
      Effect = "Allow"
      Action = [
        "bedrock-agentcore:StartCodeInterpreterSession",
        "bedrock-agentcore:InvokeCodeInterpreter",
        "bedrock-agentcore:StopCodeInterpreterSession",
        "bedrock-agentcore:GetCodeInterpreterSession",
      ]
      Resource = [
        local.builtin_code_interpreter_arn,
        module.public_code_interpreter.code_interpreter_arn,
      ]
    }]
  })
}
```

`outputs.tf`:

```hcl
output "aws_region" {
  value = var.aws_region
}

output "builtin_code_interpreter_id" {
  value = local.builtin_code_interpreter_id
}

output "public_code_interpreter_id" {
  value = module.public_code_interpreter.code_interpreter_id
}

output "ci_caller_role_arn" {
  value = aws_iam_role.ci_caller.arn
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
terraform init -backend=false -input=false
terraform fmt -check -recursive
terraform validate
terraform test
```

Expected: `validate` prints `Success!` and `terraform test` reports `2 passed, 0 failed`.

- [ ] **Step 5: Commit (including the lock file)**

```bash
cd ../../..
git add infra/terraform/poc
git commit -m "feat: add POC Terraform root with budget guard, custom interpreter, and scoped caller role"
```

---

### Task 3: Tool-result parser

**Files:**
- Create: `src/agentcore_code_interpreter_poc/__init__.py`
- Create: `src/agentcore_code_interpreter_poc/results.py`
- Test: `tests/test_code_interpreter_results.py`

**Interfaces:**
- Produces: `ToolResult` (frozen dataclass: `stdout: str`, `stderr: str`, `text: str`, `exit_code: int | None`, `is_error: bool`, `shape: tuple[str, ...]`; properties `output: str` and `failed: bool`) and `parse_tool_result(response: Mapping[str, Any]) -> ToolResult`.

- [ ] **Step 1: Write the failing tests**

`tests/test_code_interpreter_results.py`:

```python
from __future__ import annotations

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
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_code_interpreter_results.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agentcore_code_interpreter_poc'`.

- [ ] **Step 3: Implement**

`src/agentcore_code_interpreter_poc/__init__.py`:

```python
"""Phase 1 POC: verify AgentCore Code Interpreter behavior."""
```

`src/agentcore_code_interpreter_poc/results.py`:

```python
"""Flatten Code Interpreter tool responses into a small, testable shape."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ToolResult:
    stdout: str
    stderr: str
    text: str
    exit_code: int | None
    is_error: bool
    shape: tuple[str, ...]

    @property
    def output(self) -> str:
        return "\n".join(part for part in (self.stdout, self.stderr, self.text) if part)

    @property
    def failed(self) -> bool:
        return self.is_error or (self.exit_code is not None and self.exit_code != 0)


def parse_tool_result(response: Mapping[str, Any]) -> ToolResult:
    stdout: list[str] = []
    stderr: list[str] = []
    text: list[str] = []
    exit_code: int | None = None
    is_error = False
    shape: set[str] = set()

    for event in response.get("stream") or ():
        if not isinstance(event, Mapping):
            continue
        for key, value in event.items():
            if key != "result":
                shape.add(f"event:{key}")
                is_error = True
                continue
            if not isinstance(value, Mapping):
                continue
            shape.update(str(name) for name in value)
            is_error = is_error or bool(value.get("isError"))
            structured = value.get("structuredContent")
            if isinstance(structured, Mapping):
                stdout.append(str(structured.get("stdout") or ""))
                stderr.append(str(structured.get("stderr") or ""))
                code = structured.get("exitCode")
                if isinstance(code, int) and not isinstance(code, bool):
                    exit_code = code
            for item in value.get("content") or ():
                if isinstance(item, Mapping) and item.get("type") == "text":
                    text.append(str(item.get("text") or ""))

    return ToolResult(
        stdout="".join(stdout),
        stderr="".join(stderr),
        text="".join(text),
        exit_code=exit_code,
        is_error=is_error,
        shape=tuple(sorted(shape)),
    )
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `.venv/bin/python -m pytest tests/test_code_interpreter_results.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/agentcore_code_interpreter_poc tests/test_code_interpreter_results.py
git commit -m "feat: parse Code Interpreter tool responses"
```

---

### Task 4: Sessions, observations, and probes Q1.1–Q1.3

**Files:**
- Create: `src/agentcore_code_interpreter_poc/sessions.py`
- Create: `src/agentcore_code_interpreter_poc/observations.py`
- Create: `src/agentcore_code_interpreter_poc/probes.py`
- Test: `tests/test_code_interpreter_sessions.py`
- Test: `tests/test_code_interpreter_probes.py`
- Test support: `tests/code_interpreter_fakes.py`

**Interfaces:**
- Consumes: `parse_tool_result`, `ToolResult` (Task 3).
- Produces:
  - `sessions.BUILTIN_IDENTIFIER: str` (`"aws.codeinterpreter.v1"`)
  - `sessions.open_session(region: str, *, boto_session: Any = None, identifier: str = BUILTIN_IDENTIFIER, timeout_seconds: int = 900) -> ContextManager[CodeInterpreter]`
  - `sessions.assume_role_session(role_arn: str, region: str, *, session_policy: Mapping[str, Any] | None = None, base_session: Any = None) -> Any` (returns a `boto3.Session`)
  - `observations.Status = Literal["pass", "fail", "blocked"]`; `observations.Observation(question, check, status, expected, observed, config)` with `as_dict() -> dict[str, object]`; `observations.append_observations(path: Path, observations: Iterable[Observation]) -> None`
  - `probes.Session` (Protocol), `probes.SessionFactory = Callable[[], AbstractContextManager[Session]]`
  - `probes.probe_state_persistence(factory, config) -> list[Observation]`, `probes.probe_languages(factory, config)`, `probes.probe_files(factory, config)`. Task 5 adds more probes to the same module.

- [ ] **Step 1: Write the shared test fakes**

`tests/code_interpreter_fakes.py`:

```python
from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from typing import Any

Responder = Callable[["FakeSession", str, str], dict[str, Any]]


def ok(stdout: str) -> dict[str, Any]:
    return {
        "stream": [
            {"result": {"structuredContent": {"stdout": stdout, "stderr": "", "exitCode": 0}}}
        ]
    }


def err(stderr: str) -> dict[str, Any]:
    return {
        "stream": [
            {
                "result": {
                    "structuredContent": {"stdout": "", "stderr": stderr, "exitCode": 1},
                    "isError": True,
                }
            }
        ]
    }


class FakeSession:
    def __init__(self, responder: Responder) -> None:
        self.responder = responder
        self.files: dict[str, str | bytes] = {}
        self.calls: list[tuple[str, str]] = []

    def execute_code(
        self, code: str, language: str = "python", clear_context: bool = False
    ) -> dict[str, Any]:
        self.calls.append((language, code))
        return self.responder(self, language, code)

    def execute_command(self, command: str) -> dict[str, Any]:
        self.calls.append(("shell", command))
        return self.responder(self, "shell", command)

    def upload_file(self, path: str, content: str | bytes, description: str = "") -> dict[str, Any]:
        self.files[path] = content
        return {}

    def download_file(self, path: str) -> str | bytes:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]


def factory_of(
    *sessions: FakeSession,
) -> Callable[[], contextlib.AbstractContextManager[FakeSession]]:
    remaining: Iterator[FakeSession] = iter(sessions)

    def open_next() -> contextlib.AbstractContextManager[FakeSession]:
        return contextlib.nullcontext(next(remaining))

    return open_next
```

- [ ] **Step 2: Write the failing session tests**

`tests/test_code_interpreter_sessions.py`:

```python
from __future__ import annotations

import json
from typing import Any

import pytest
from botocore.exceptions import ClientError

from agentcore_code_interpreter_poc import sessions


class FakeInterpreter:
    instances: list[FakeInterpreter] = []

    def __init__(self, region: str, session: Any = None) -> None:
        self.region = region
        self.started: dict[str, object] = {}
        self.stopped = False
        self.stop_error: Exception | None = None
        FakeInterpreter.instances.append(self)

    def start(self, identifier: str, session_timeout_seconds: int) -> str:
        self.started = {"identifier": identifier, "timeout": session_timeout_seconds}
        return "session-1"

    def stop(self) -> bool:
        self.stopped = True
        if self.stop_error is not None:
            raise self.stop_error
        return True


@pytest.fixture(autouse=True)
def fake_interpreter(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeInterpreter.instances = []
    monkeypatch.setattr(sessions, "CodeInterpreter", FakeInterpreter)


def test_open_session_starts_with_identifier_and_timeout_and_stops() -> None:
    with sessions.open_session("ap-southeast-1", identifier="custom_ci", timeout_seconds=60):
        pass

    interpreter = FakeInterpreter.instances[0]
    assert interpreter.started == {"identifier": "custom_ci", "timeout": 60}
    assert interpreter.stopped is True


def test_open_session_stops_even_when_body_raises() -> None:
    with pytest.raises(RuntimeError), sessions.open_session("ap-southeast-1"):
        raise RuntimeError("probe failed")

    assert FakeInterpreter.instances[0].stopped is True


def test_stop_failure_after_ttl_is_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    gone = ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "gone"}},
        "StopCodeInterpreterSession",
    )

    with sessions.open_session("ap-southeast-1") as interpreter:
        interpreter.stop_error = gone

    assert FakeInterpreter.instances[0].stopped is True


def test_builtin_identifier_is_the_aws_default() -> None:
    assert sessions.BUILTIN_IDENTIFIER == "aws.codeinterpreter.v1"


class FakeSts:
    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.kwargs = kwargs
        return {
            "Credentials": {
                "AccessKeyId": "example-access-key",
                "SecretAccessKey": "example-secret",
                "SessionToken": "example-session",
            }
        }


class FakeBaseSession:
    def __init__(self, sts: FakeSts) -> None:
        self.sts = sts

    def client(self, name: str, region_name: str) -> FakeSts:
        assert name == "sts"
        return self.sts


def test_assume_role_session_passes_session_policy_as_json() -> None:
    sts = FakeSts()
    policy = {"Version": "2012-10-17", "Statement": []}

    session = sessions.assume_role_session(
        "arn:aws:iam::123456789012:role/example",
        "ap-southeast-1",
        session_policy=policy,
        base_session=FakeBaseSession(sts),
    )

    assert sts.kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/example"
    assert json.loads(sts.kwargs["Policy"]) == policy
    assert session.region_name == "ap-southeast-1"


def test_assume_role_session_omits_policy_when_not_given() -> None:
    sts = FakeSts()

    sessions.assume_role_session(
        "arn:aws:iam::123456789012:role/example",
        "ap-southeast-1",
        base_session=FakeBaseSession(sts),
    )

    assert "Policy" not in sts.kwargs
```

- [ ] **Step 3: Write the failing probe tests for Q1.1–Q1.3**

`tests/test_code_interpreter_probes.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from agentcore_code_interpreter_poc import probes
from agentcore_code_interpreter_poc.observations import Observation, append_observations
from tests.code_interpreter_fakes import FakeSession, err, factory_of, ok

CONFIG = {"identifier": "aws.codeinterpreter.v1"}


def _by_check(observations: list[Observation]) -> dict[str, Observation]:
    return {observation.check: observation for observation in observations}


def test_state_persists_within_and_not_across_sessions() -> None:
    def first(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("42\n") if "print" in code else ok("")

    def second(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return err("NameError: name 'poc_marker' is not defined")

    observations = _by_check(
        probes.probe_state_persistence(
            factory_of(FakeSession(first), FakeSession(second)), CONFIG
        )
    )

    assert observations["state_persists_within_session"].status == "pass"
    assert observations["state_isolated_across_sessions"].status == "pass"
    assert observations["state_isolated_across_sessions"].question == "Q1.1"


def test_state_leak_across_sessions_is_a_failure() -> None:
    def leaky(session: FakeSession, language: str, code: str) -> dict[str, object]:
        return ok("42\n") if "print" in code else ok("")

    observations = _by_check(
        probes.probe_state_persistence(factory_of(FakeSession(leaky), FakeSession(leaky)), CONFIG)
    )

    assert observations["state_isolated_across_sessions"].status == "fail"


def test_languages_probe_covers_js_ts_shell_and_switch_back() -> None:
    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if language == "shell":
            return ok("poc-shell-ok\naarch64\n")
        if language == "python":
            return ok("python-after-js\n")
        return ok("42\n")

    session = FakeSession(respond)
    observations = _by_check(probes.probe_languages(factory_of(session), CONFIG))

    assert {name: o.status for name, o in observations.items()} == {
        "javascript_executes": "pass",
        "typescript_executes": "pass",
        "shell_command_executes": "pass",
        "python_after_other_languages": "pass",
    }
    assert [language for language, _ in session.calls] == [
        "javascript",
        "typescript",
        "shell",
        "python",
    ]


def test_files_probe_covers_internal_caller_and_binary_paths() -> None:
    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if "poc_internal.txt" in code:
            session.files["poc_internal.txt"] = "internal-marker"
        if "poc_output.json" in code:
            session.files["poc_output.json"] = json.dumps({"sum_b": 6})
        return ok("written\n")

    observations = _by_check(
        probes.probe_files(factory_of(FakeSession(respond), FakeSession(respond)), CONFIG)
    )

    assert {name: o.status for name, o in observations.items()} == {
        "internal_file_persists_within_session": "pass",
        "internal_file_absent_in_new_session": "pass",
        "caller_upload_compute_download": "pass",
        "binary_round_trip": "pass",
    }
    assert all(o.question == "Q1.3" for o in observations.values())


def test_append_observations_writes_one_json_line_each(tmp_path: Path) -> None:
    path = tmp_path / "raw" / "observations.jsonl"
    observation = Observation("Q1.1", "check", "pass", "expected", "observed", {"k": "v"})

    append_observations(path, [observation, observation])

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {
        "check": "check",
        "config": {"k": "v"},
        "expected": "expected",
        "observed": "observed",
        "question": "Q1.1",
        "status": "pass",
    }


def test_long_observed_output_is_clipped() -> None:
    assert probes.clip("a" * 1000).endswith("...[1000 chars]")
    assert probes.clip("short") == "short"
```

- [ ] **Step 4: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_code_interpreter_sessions.py tests/test_code_interpreter_probes.py -v`
Expected: FAIL with `ImportError` (the modules do not exist yet).

- [ ] **Step 5: Implement `sessions.py`**

```python
"""Open Code Interpreter sessions with guaranteed cleanup, as an external caller."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator, Mapping
from typing import Any

import boto3  # type: ignore[import-untyped]
from bedrock_agentcore.tools.code_interpreter_client import DEFAULT_IDENTIFIER, CodeInterpreter
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

BUILTIN_IDENTIFIER: str = DEFAULT_IDENTIFIER


@contextlib.contextmanager
def open_session(
    region: str,
    *,
    boto_session: Any = None,
    identifier: str = BUILTIN_IDENTIFIER,
    timeout_seconds: int = 900,
) -> Iterator[CodeInterpreter]:
    client = CodeInterpreter(region, session=boto_session)
    client.start(identifier=identifier, session_timeout_seconds=timeout_seconds)
    try:
        yield client
    finally:
        # A session past its TTL is already gone; stopping it can fail with nothing left to clean.
        with contextlib.suppress(ClientError):
            client.stop()


def assume_role_session(
    role_arn: str,
    region: str,
    *,
    session_policy: Mapping[str, Any] | None = None,
    base_session: Any = None,
) -> Any:
    source = base_session if base_session is not None else boto3.Session(region_name=region)
    sts = source.client("sts", region_name=region)
    request: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "agentcore-ci-poc"}
    if session_policy is not None:
        request["Policy"] = json.dumps(session_policy)
    credentials = sts.assume_role(**request)["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )
```

- [ ] **Step 6: Implement `observations.py`**

```python
"""Structured, sanitized observations for the findings write-up."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Status = Literal["pass", "fail", "blocked"]


@dataclass(frozen=True)
class Observation:
    question: str
    check: str
    status: Status
    expected: str
    observed: str
    config: Mapping[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "question": self.question,
            "check": self.check,
            "status": self.status,
            "expected": self.expected,
            "observed": self.observed,
            "config": dict(self.config),
        }


def append_observations(path: Path, observations: Iterable[Observation]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for observation in observations:
            handle.write(json.dumps(observation.as_dict(), sort_keys=True))
            handle.write("\n")
```

- [ ] **Step 7: Implement `probes.py` (Q1.1–Q1.3)**

```python
"""Probe functions for Phase 1. Each returns observations; none raises on an expected outcome."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from typing import Any, Protocol

from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from agentcore_code_interpreter_poc.observations import Observation, Status
from agentcore_code_interpreter_poc.results import ToolResult, parse_tool_result


class Session(Protocol):
    def execute_code(
        self, code: str, language: str = ..., clear_context: bool = ...
    ) -> dict[str, Any]: ...

    def execute_command(self, command: str) -> dict[str, Any]: ...

    def upload_file(
        self, path: str, content: str | bytes, description: str = ...
    ) -> dict[str, Any]: ...

    def download_file(self, path: str) -> str | bytes: ...


SessionFactory = Callable[[], AbstractContextManager[Session]]
Config = Mapping[str, str]


def clip(value: str, limit: int = 300) -> str:
    return value if len(value) <= limit else f"{value[:limit]}...[{len(value)} chars]"


def error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        return str(error.response.get("Error", {}).get("Code", "ClientError"))
    return type(error).__name__


def _status(ok: bool) -> Status:
    return "pass" if ok else "fail"


def _run(session: Session, code: str, language: str = "python") -> ToolResult:
    return parse_tool_result(session.execute_code(code, language=language))


def _as_text(value: str | bytes) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def probe_state_persistence(factory: SessionFactory, config: Config) -> list[Observation]:
    with factory() as session:
        _run(session, "poc_marker = 41")
        same = _run(session, "print(poc_marker + 1)")
    with factory() as session:
        other = _run(session, "print(poc_marker)")
    return [
        Observation(
            "Q1.1",
            "state_persists_within_session",
            _status("42" in same.output and not same.failed),
            "a variable set in one call is readable in a later call of the same session",
            clip(same.output),
            config,
        ),
        Observation(
            "Q1.1",
            "state_isolated_across_sessions",
            _status(other.failed or "NameError" in other.output),
            "a new session cannot see the variable",
            clip(other.output),
            config,
        ),
    ]


def probe_languages(factory: SessionFactory, config: Config) -> list[Observation]:
    observations: list[Observation] = []
    snippets = (
        ("javascript", "console.log(6 * 7)"),
        ("typescript", "const n: number = 6 * 7;\nconsole.log(n);"),
    )
    with factory() as session:
        for language, code in snippets:
            result = _run(session, code, language)
            observations.append(
                Observation(
                    "Q1.2",
                    f"{language}_executes",
                    _status("42" in result.output and not result.failed),
                    "prints 42",
                    clip(result.output),
                    config,
                )
            )
        shell = parse_tool_result(session.execute_command("echo poc-shell-ok && uname -m"))
        observations.append(
            Observation(
                "Q1.2",
                "shell_command_executes",
                _status("poc-shell-ok" in shell.output and not shell.failed),
                "echo output is returned; uname -m shows the CPU architecture",
                clip(shell.output),
                config,
            )
        )
        back = _run(session, "print('python-after-js')")
        observations.append(
            Observation(
                "Q1.2",
                "python_after_other_languages",
                _status("python-after-js" in back.output and not back.failed),
                "switching back to Python in the same session works",
                clip(back.output),
                config,
            )
        )
    return observations


def probe_files(factory: SessionFactory, config: Config) -> list[Observation]:
    blob = bytes(range(256))
    with factory() as session:
        _run(session, "open('poc_internal.txt', 'w').write('internal-marker')")
        internal = _as_text(session.download_file("poc_internal.txt"))
        session.upload_file("poc_input.csv", "a,b\n1,2\n3,4\n")
        _run(
            session,
            "import csv, json\n"
            "rows = list(csv.DictReader(open('poc_input.csv')))\n"
            "json.dump({'sum_b': sum(int(r['b']) for r in rows)}, open('poc_output.json', 'w'))\n"
            "print('written')",
        )
        produced = _as_text(session.download_file("poc_output.json"))
        session.upload_file("poc_blob.bin", blob)
        blob_back = session.download_file("poc_blob.bin")
    with factory() as session:
        try:
            leaked: str = _as_text(session.download_file("poc_internal.txt"))
        except (FileNotFoundError, ClientError) as error:
            leaked = f"absent:{error_code(error)}"

    try:
        sum_b = json.loads(produced).get("sum_b")
    except (ValueError, AttributeError):
        sum_b = None

    return [
        Observation(
            "Q1.3",
            "internal_file_persists_within_session",
            _status(internal == "internal-marker"),
            "a file written by code is readable later in the same session",
            clip(internal),
            config,
        ),
        Observation(
            "Q1.3",
            "internal_file_absent_in_new_session",
            _status(leaked.startswith("absent:")),
            "a new session does not see the file",
            clip(leaked),
            config,
        ),
        Observation(
            "Q1.3",
            "caller_upload_compute_download",
            _status(sum_b == 6),
            "caller uploads a CSV, code writes JSON, caller downloads sum_b == 6",
            clip(produced),
            config,
        ),
        Observation(
            "Q1.3",
            "binary_round_trip",
            _status(blob_back == blob),
            "256 raw bytes survive upload then download unchanged",
            f"type={type(blob_back).__name__} length={len(blob_back)}",
            config,
        ),
    ]
```

- [ ] **Step 8: Run the tests and confirm they pass**

Run: `.venv/bin/python -m pytest tests/test_code_interpreter_sessions.py tests/test_code_interpreter_probes.py -v`
Expected: all pass (6 session tests, 6 probe tests).

If `from tests.code_interpreter_fakes import ...` fails with `ModuleNotFoundError: No module named 'tests'`, create an empty `tests/__init__.py`. Then run the full suite once to confirm that existing tests still collect.

- [ ] **Step 9: Lint, type-check, commit**

```bash
.venv/bin/ruff check src/agentcore_code_interpreter_poc tests/test_code_interpreter_*.py tests/code_interpreter_fakes.py
.venv/bin/mypy src/agentcore_code_interpreter_poc
git add src/agentcore_code_interpreter_poc tests/test_code_interpreter_sessions.py \
  tests/test_code_interpreter_probes.py tests/code_interpreter_fakes.py
git commit -m "feat: add Code Interpreter sessions, observations, and Q1.1-Q1.3 probes"
```

---

### Task 5: Probes Q1.4–Q1.6

**Files:**
- Modify: `src/agentcore_code_interpreter_poc/probes.py` (append)
- Test: `tests/test_code_interpreter_probes.py` (append)

**Interfaces:**
- Consumes: everything from Task 4.
- Produces:
  - `probes.probe_egress(factory: SessionFactory, config: Config, *, expected_reachable: bool) -> list[Observation]`
  - `probes.probe_failure_modes(factory: SessionFactory, config: Config, *, clock: Callable[[], float] = time.monotonic) -> list[Observation]`
  - `probes.probe_session_ttl(open_with_timeout: Callable[[int], AbstractContextManager[Session]], config: Config, *, ttl_seconds: int = 60, sleep: Callable[[float], None] = time.sleep) -> list[Observation]`
  - `probes.INVOKE_EXCLUDED_SESSION_POLICY: dict[str, Any]`
  - `probes.probe_scoped_caller(allowed: SessionFactory, denied: SessionFactory, config: Config) -> list[Observation]`

- [ ] **Step 1: Append the failing tests**

In `tests/test_code_interpreter_probes.py`, add these imports to the existing import block at the top of the file. Don't put them mid-file, because `ruff` rule E402 rejects that. Afterwards, run `.venv/bin/ruff check --fix tests/test_code_interpreter_probes.py` to sort the block (rule I001):

```python
import contextlib

import pytest
from botocore.exceptions import ClientError
```

Then append:

```python
def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "InvokeCodeInterpreter")


@pytest.mark.parametrize(
    ("stdout", "expected_reachable", "status"),
    [
        ("status 200\n", True, "pass"),
        ("blocked URLError\n", False, "pass"),
        ("status 200\n", False, "fail"),
    ],
)
def test_egress_compares_reachability_with_expectation(
    stdout: str, expected_reachable: bool, status: str
) -> None:
    session = FakeSession(lambda s, language, code: ok(stdout))

    [observation] = probes.probe_egress(
        factory_of(session), CONFIG, expected_reachable=expected_reachable
    )

    assert observation.question == "Q1.4"
    assert observation.status == status


def test_failure_modes_record_each_behavior() -> None:
    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if "def broken" in code:
            return err("SyntaxError: invalid syntax")
        if "poc-boom" in code:
            return err("ValueError: poc-boom")
        if "2_000_000" in code:
            return ok("a" * 1000)
        if "time.sleep" in code:
            return ok("slept\n")
        return ok("allocated 1073741824\n")

    ticks = iter([100.0, 161.5])
    observations = _by_check(
        probes.probe_failure_modes(
            factory_of(FakeSession(respond)), CONFIG, clock=lambda: next(ticks)
        )
    )

    assert observations["syntax_error_surfaces"].status == "pass"
    assert observations["exception_surfaces"].status == "pass"
    assert observations["large_output"].observed == "returned 1000 of 2000000 chars"
    assert observations["sixty_second_execution"].status == "pass"
    assert "61.5s" in observations["sixty_second_execution"].observed
    assert "allocated" in observations["one_gib_allocation"].observed
    assert all(o.question == "Q1.5" for o in observations.values())


def test_session_ttl_expires_when_idle_and_when_active() -> None:
    clock = {"now": 0.0}

    def respond(session: FakeSession, language: str, code: str) -> dict[str, object]:
        if clock["now"] > 60:
            raise _client_error("ResourceNotFoundException")
        return ok("alive\n")

    def open_with_timeout(ttl: int) -> contextlib.AbstractContextManager[FakeSession]:
        assert ttl == 60
        clock["now"] = 0.0
        return contextlib.nullcontext(FakeSession(respond))

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    observations = _by_check(probes.probe_session_ttl(open_with_timeout, CONFIG, sleep=sleep))

    assert observations["idle_session_ends_at_ttl"].status == "pass"
    assert observations["active_session_ends_at_ttl"].status == "pass"
    assert "ResourceNotFoundException" in observations["idle_session_ends_at_ttl"].observed


def test_session_ttl_extended_by_activity_is_reported_as_fail() -> None:
    def open_with_timeout(ttl: int) -> contextlib.AbstractContextManager[FakeSession]:
        return contextlib.nullcontext(FakeSession(lambda s, language, code: ok("alive\n")))

    observations = _by_check(
        probes.probe_session_ttl(open_with_timeout, CONFIG, sleep=lambda seconds: None)
    )

    assert observations["active_session_ends_at_ttl"].status == "fail"


def test_scoped_caller_allowed_runs_and_denied_invoke_is_access_denied() -> None:
    allowed = FakeSession(lambda s, language, code: ok("scoped-ok\n"))

    def deny(session: FakeSession, language: str, code: str) -> dict[str, object]:
        raise _client_error("AccessDeniedException")

    observations = _by_check(
        probes.probe_scoped_caller(factory_of(allowed), factory_of(FakeSession(deny)), CONFIG)
    )

    assert observations["scoped_role_can_execute"].status == "pass"
    assert observations["invoke_denied_without_permission"].status == "pass"
    assert observations["invoke_denied_without_permission"].observed == "AccessDeniedException"


def test_scoped_caller_denied_session_that_runs_is_a_failure() -> None:
    runs = FakeSession(lambda s, language, code: ok("should-not-run\n"))

    observations = _by_check(
        probes.probe_scoped_caller(factory_of(runs), factory_of(runs), CONFIG)
    )

    assert observations["invoke_denied_without_permission"].status == "fail"


def test_session_policy_excludes_invoke() -> None:
    actions = probes.INVOKE_EXCLUDED_SESSION_POLICY["Statement"][0]["Action"]

    assert "bedrock-agentcore:InvokeCodeInterpreter" not in actions
    assert "bedrock-agentcore:StartCodeInterpreterSession" in actions
```

Note: `test_scoped_caller_denied_session_that_runs_is_a_failure` hands the same `FakeSession` to both factories on purpose; `factory_of` builds two separate iterators.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_code_interpreter_probes.py -v`
Expected: the new tests FAIL with `AttributeError: module 'agentcore_code_interpreter_poc.probes' has no attribute 'probe_egress'`, and similar errors for the other new probes.

- [ ] **Step 3: Implement the probes**

Add `import time` to the imports at the top of `probes.py`. Then append:

```python
INVOKE_EXCLUDED_SESSION_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock-agentcore:StartCodeInterpreterSession",
                "bedrock-agentcore:StopCodeInterpreterSession",
                "bedrock-agentcore:GetCodeInterpreterSession",
            ],
            "Resource": "*",
        }
    ],
}

_EGRESS_CODE = (
    "import urllib.request\n"
    "try:\n"
    "    print('status', urllib.request.urlopen('https://aws.amazon.com', timeout=10).status)\n"
    "except Exception as error:\n"
    "    print('blocked', type(error).__name__)\n"
)


def probe_egress(
    factory: SessionFactory, config: Config, *, expected_reachable: bool
) -> list[Observation]:
    with factory() as session:
        result = _run(session, _EGRESS_CODE)
    reachable = "status 200" in result.output
    return [
        Observation(
            "Q1.4",
            "public_internet_egress",
            _status(reachable == expected_reachable),
            f"reachable={expected_reachable}",
            clip(result.output),
            config,
        )
    ]


def probe_failure_modes(
    factory: SessionFactory, config: Config, *, clock: Callable[[], float] = time.monotonic
) -> list[Observation]:
    with factory() as session:
        syntax = _run(session, "def broken(:\n    pass")
        raised = _run(session, "raise ValueError('poc-boom')")
        big = _run(session, "print('a' * 2_000_000)")
        started = clock()
        slow = _run(session, "import time\ntime.sleep(60)\nprint('slept')")
        slow_seconds = clock() - started
        memory = _run(
            session, "block = bytearray(1024 * 1024 * 1024)\nprint('allocated', len(block))"
        )
    returned = len(big.stdout or big.text)
    return [
        Observation(
            "Q1.5",
            "syntax_error_surfaces",
            _status(syntax.failed and "SyntaxError" in syntax.output),
            "a syntax error is reported as a failed execution",
            clip(syntax.output),
            config,
        ),
        Observation(
            "Q1.5",
            "exception_surfaces",
            _status(raised.failed and "poc-boom" in raised.output),
            "an uncaught exception is reported with its message",
            clip(raised.output),
            config,
        ),
        Observation(
            "Q1.5",
            "large_output",
            "pass",
            "the call returns; record whether 2,000,000 chars are truncated",
            f"returned {returned} of 2000000 chars",
            config,
        ),
        Observation(
            "Q1.5",
            "sixty_second_execution",
            _status("slept" in slow.output and not slow.failed),
            "a 60 s execution completes within the per-execution limit",
            f"{slow_seconds:.1f}s output={clip(slow.output, 80)}",
            config,
        ),
        Observation(
            "Q1.5",
            "one_gib_allocation",
            "pass",
            "record whether a 1 GiB allocation fits in the sandbox",
            clip(memory.output),
            config,
        ),
    ]


def _attempt(session: Session) -> str:
    try:
        result = _run(session, "print('alive')")
    except ClientError as error:
        return f"error:{error_code(error)}"
    if result.failed or "alive" not in result.output:
        return "error:" + (",".join(result.shape) or "unknown")
    return "ok"


def probe_session_ttl(
    open_with_timeout: Callable[[int], AbstractContextManager[Session]],
    config: Config,
    *,
    ttl_seconds: int = 60,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Observation]:
    wait = ttl_seconds + 20
    with open_with_timeout(ttl_seconds) as session:
        idle_before = _attempt(session)
        sleep(wait)
        idle_after = _attempt(session)
    with open_with_timeout(ttl_seconds) as session:
        for _ in range(wait // 15):
            _attempt(session)
            sleep(15)
        active_after = _attempt(session)
    return [
        Observation(
            "Q1.5",
            "idle_session_ends_at_ttl",
            _status(idle_before == "ok" and idle_after != "ok"),
            f"an idle session is gone {wait}s after start (TTL {ttl_seconds}s)",
            f"before={idle_before} after={idle_after}",
            config,
        ),
        Observation(
            "Q1.5",
            "active_session_ends_at_ttl",
            _status(active_after != "ok"),
            "sessionTimeoutSeconds is a fixed lifetime: activity does not extend it",
            f"after={active_after}",
            config,
        ),
    ]


def probe_scoped_caller(
    allowed: SessionFactory, denied: SessionFactory, config: Config
) -> list[Observation]:
    with allowed() as session:
        allowed_result = _run(session, "print('scoped-ok')")
    try:
        with denied() as session:
            _run(session, "print('should-not-run')")
        denied_outcome = "ran"
    except ClientError as error:
        denied_outcome = error_code(error)
    return [
        Observation(
            "Q1.6",
            "scoped_role_can_execute",
            _status("scoped-ok" in allowed_result.output and not allowed_result.failed),
            "the scoped caller role (4 session actions only) can start, execute, and stop",
            clip(allowed_result.output),
            config,
        ),
        Observation(
            "Q1.6",
            "invoke_denied_without_permission",
            _status("AccessDenied" in denied_outcome),
            "without InvokeCodeInterpreter, execution is denied",
            denied_outcome,
            config,
        ),
    ]
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `.venv/bin/python -m pytest tests/test_code_interpreter_probes.py -v`
Expected: all pass.

- [ ] **Step 5: Lint, type-check, commit**

```bash
.venv/bin/ruff check src/agentcore_code_interpreter_poc tests/test_code_interpreter_probes.py
.venv/bin/mypy src/agentcore_code_interpreter_poc
git add src/agentcore_code_interpreter_poc/probes.py tests/test_code_interpreter_probes.py
git commit -m "feat: add Code Interpreter probes for egress, failures, TTL, and scoped caller"
```

---

### Task 6: Terraform outputs helper, live gate, and Phase 0 gate updates

**Files:**
- Create: `scripts/terraform_outputs.py`
- Test: `tests/test_terraform_outputs.py`
- Create: `tests/integration/test_code_interpreter_live.py`
- Modify: `pyproject.toml` (`[tool.mypy] packages`)
- Modify: `README.md` (Phase 0 commands; a short Phase 1 section)
- Modify: `docs/runbook.md` (a new "Code Interpreter POC (Phase 1)" section at the end)

**Interfaces:**
- Consumes: probes, sessions, and observations (Tasks 4–5). Terraform outputs `aws_region`, `builtin_code_interpreter_id`, `public_code_interpreter_id`, `ci_caller_role_arn` (Task 2).
- Produces: `scripts.terraform_outputs.load_terraform_outputs(root: Path, run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> dict[str, str]`. This returns only non-sensitive string outputs. Phase 2 reuses it.

- [ ] **Step 1: Write the failing helper test**

`tests/test_terraform_outputs.py`:

```python
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from scripts.terraform_outputs import load_terraform_outputs


def test_returns_only_non_sensitive_string_outputs() -> None:
    seen: dict[str, Any] = {}

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        seen["kwargs"] = kwargs
        payload = {
            "aws_region": {"value": "ap-southeast-1", "sensitive": False},
            "secret_thing": {"value": "hidden", "sensitive": True},
            "a_list": {"value": ["x"], "sensitive": False},
        }
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload), stderr="")

    outputs = load_terraform_outputs(Path("infra/terraform/poc"), run=fake_run)

    assert outputs == {"aws_region": "ap-southeast-1"}
    assert seen["args"][1:] == ["-chdir=infra/terraform/poc", "output", "-json"]
    assert seen["args"][0].endswith("terraform")
    assert seen["kwargs"]["check"] is True
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `.venv/bin/python -m pytest tests/test_terraform_outputs.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.terraform_outputs'`.

- [ ] **Step 3: Implement the helper**

`scripts/terraform_outputs.py`:

```python
"""Read non-sensitive string outputs from a Terraform root module."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path


def load_terraform_outputs(
    root: Path,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, str]:
    terraform = shutil.which("terraform") or "terraform"
    completed = run(
        [terraform, f"-chdir={root}", "output", "-json"],
        check=True,
        capture_output=True,
        text=True,
    )
    raw = json.loads(completed.stdout)
    return {
        name: entry["value"]
        for name, entry in raw.items()
        if not entry.get("sensitive") and isinstance(entry.get("value"), str)
    }
```

If `ruff` flags `S603` on the `run(...)` call, add `# noqa: S603 - terraform is resolved from PATH; args are fixed.` on that line. This follows `tests/test_repository_safety.py:233`.

- [ ] **Step 4: Run the test and confirm it passes**

Run: `.venv/bin/python -m pytest tests/test_terraform_outputs.py -v`
Expected: 1 passed.

- [ ] **Step 5: Write the live gate**

`tests/integration/test_code_interpreter_live.py`:

```python
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
            lambda ttl: open_session(region, identifier=builtin, timeout_seconds=ttl),
            _config(outputs, builtin),
        )
    )


def test_q1_6_scoped_caller(outputs: dict[str, str]) -> None:
    builtin = outputs["builtin_code_interpreter_id"]
    role = outputs["ci_caller_role_arn"]
    region = outputs["aws_region"]
    allowed = assume_role_session(role, region)
    denied = assume_role_session(
        role, region, session_policy=probes.INVOKE_EXCLUDED_SESSION_POLICY
    )
    _record(
        probes.probe_scoped_caller(
            _factory(outputs, builtin, allowed),
            _factory(outputs, builtin, denied),
            _config(outputs, builtin, caller="ci_caller_role"),
        )
    )
```

- [ ] **Step 6: Confirm that the live gate skips cleanly without the flag**

Run: `.venv/bin/python -m pytest tests/integration/test_code_interpreter_live.py -v`
Expected: 8 skipped.

- [ ] **Step 7: Update the mypy config and the Phase 0 commands**

In `pyproject.toml`, change `packages = ["agentcore_identity_poc"]` to:

```toml
packages = ["agentcore_identity_poc", "agentcore_code_interpreter_poc"]
```

In `README.md` "1. Local Verification", replace the command block with:

```bash
.venv/bin/python -m pytest -m 'not integration' \
  --cov=agentcore_identity_poc --cov=agentcore_code_interpreter_poc \
  --cov-report=term-missing --cov-fail-under=90
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/python -m pytest tests/test_repository_safety.py -q
terraform fmt -check -recursive infra/terraform
(cd infra/terraform/modules/agentcore_code_interpreter && terraform init -backend=false -input=false >/dev/null && terraform test)
(cd infra/terraform/poc && terraform init -backend=false -input=false >/dev/null && terraform validate && terraform test)
git diff --check
```

(`mypy src` already covers every package under `src/`. The `packages` list change keeps the config accurate. The coverage floor applies to the combined total.)

Make the same change in `docs/runbook.md` "Phase 0: Local Verification".

- [ ] **Step 8: Add the Phase 1 runbook section**

Append to `docs/runbook.md`:

````markdown
## Code Interpreter POC (Phase 1)

Operator-run, interactive terminal, fresh `aws sso login`. Findings go in
`docs/code-interpreter-findings.md`.

```bash
set -a; source .env; set +a
export TF_VAR_aws_region="$AWS_REGION" TF_VAR_aws_budget_name="$AWS_BUDGET_NAME"
cd infra/terraform/poc
terraform init -input=false
terraform plan -out=phase1.tfplan          # TF.1: review; no ECR/CodeBuild resources
terraform apply phase1.tfplan
terraform plan -detailed-exitcode          # TF.2: exit code 0 = no drift
cd ../../..
AGENTCORE_POC_LIVE=1 .venv/bin/python -m pytest tests/integration/test_code_interpreter_live.py -m integration -v -s
AGENTCORE_POC_LIVE=1 AGENTCORE_POC_SLOW=1 .venv/bin/python -m pytest \
  tests/integration/test_code_interpreter_live.py -m integration -k ttl -v -s
```

Observations are appended to `evidence/raw/code-interpreter-observations.jsonl` (ignored).
A failing probe is a finding, not necessarily a bug: record it. Only fix code when the probe
itself is wrong. If `test_q1_6` fails the *allowed* check with `AccessDeniedException`, the
built-in interpreter ARN in `infra/terraform/poc/main.tf` is wrong for this account or region.
Record the ARN form that the service expects (from CloudTrail or the error) as a finding, fix
the local, and apply again.
````

- [ ] **Step 9: Run the full Phase 0 gate and commit**

Run every command from Step 7. Expected: all exit 0 and total coverage is at least 90%.

```bash
git add scripts/terraform_outputs.py tests/test_terraform_outputs.py \
  tests/integration/test_code_interpreter_live.py pyproject.toml README.md docs/runbook.md
git commit -m "feat: add Phase 1 live gate, Terraform outputs helper, and gate updates"
```

---

### Task 7: Apply and run the live gate (OPERATOR-RUN)

**Files:** none are tracked. Local only: Terraform state, and `evidence/raw/code-interpreter-observations.jsonl`.

- [ ] **Step 1: Apply with Terraform and record TF.1**

Follow the runbook section from Task 6, Step 8, up to and including `terraform apply`. Before applying, check that the plan lists only these resources: `module.public_code_interpreter.aws_bedrockagentcore_code_interpreter.this`, `aws_iam_role.ci_caller`, and `aws_iam_role_policy.ci_caller`. Nothing ECR- or CodeBuild-related may appear. Note the resource count for TF.1.

- [ ] **Step 2: Record TF.2 (no drift)**

Run: `terraform -chdir=infra/terraform/poc plan -detailed-exitcode`
Expected: exit code 0. If it exits 2, copy the attribute that shows a diff. That is a TF.2 finding (a perpetual diff to handle in the work module, for example with `lifecycle { ignore_changes }`).

- [ ] **Step 3: Run the live gate, then the slow TTL probe**

Run both pytest commands from the runbook.
Expected: every observation is printed and appended. Failing checks are findings. Record them; don't "fix" them unless the probe itself is wrong.

- [ ] **Step 4: Hand over**

Report the observation file path, the pass/fail counts, and any TF.2 diff to the person running the plan.

---

### Task 8: Findings write-up

**Files:**
- Create: `docs/code-interpreter-findings.md`

- [ ] **Step 1: Write the findings doc from the observations**

Use this structure. Fill every row from `evidence/raw/code-interpreter-observations.jsonl` and from Task 7's TF notes. Copy no raw error messages; use codes only.

```markdown
# Code Interpreter Findings (Phase 1)

**Date:** <run date> · **Region:** <region> · **SDK:** bedrock-agentcore <version> ·
**Terraform:** <version>, hashicorp/aws 6.66.0

## Summary

<3–5 sentences: what works for an external caller such as a Temporal worker, what doesn't, and
what the work Terraform modules must account for.>

## Results

| Q | Check | Procedure | Expected | Observed | Config | Status |
|---|---|---|---|---|---|---|
| Q1.1 | state_persists_within_session | set var, read in later call | ... | ... | built-in | pass |
| ... one row per observation ... |
| TF.1 | clean apply resource set | `terraform plan` before apply | only interpreter + role + policy | ... | poc root | ... |
| TF.2 | no drift after apply | `plan -detailed-exitcode` | exit 0 | ... | poc root | ... |

## Implications for the work Terraform modules

- <for example: the SANDBOX mode needs an execution role; the ARN form for the built-in
  interpreter in IAM policies; the minimal caller action set from Q1.6; any perpetual diff
  from TF.2>

## Limits of these results

- Egress results describe only the configurations tested (built-in, custom PUBLIC); VPC mode
  was not tested.
- Q1.6 proves the minimal caller policy for the built-in and one custom interpreter only.
```

- [ ] **Step 2: Safety check and commit**

```bash
.venv/bin/python -m pytest tests/test_repository_safety.py -q
git add docs/code-interpreter-findings.md
git commit -m "docs: record Code Interpreter Phase 1 findings"
```

- [ ] **Step 3: Decide whether to keep resources for Phase 2**

The Phase 1 resources cost nothing while idle (an interpreter definition and an IAM role). Keep them if Phase 2 starts within about a week. Phase 2 adds to the same root. Otherwise run `terraform -chdir=infra/terraform/poc destroy` now and apply again later.
