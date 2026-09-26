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
