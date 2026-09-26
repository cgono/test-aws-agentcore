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

output "name_prefix" {
  value = var.name_prefix
}

output "agent_runtime_arn" {
  value = try(module.agent_runtime[0].agent_runtime_arn, "")
}

output "agent_runtime_id" {
  value = try(module.agent_runtime[0].agent_runtime_id, "")
}

output "agent_runtime_version" {
  value = try(tostring(module.agent_runtime[0].agent_runtime_version), "")
}

output "gateway_secret_arn" {
  value = try(aws_secretsmanager_secret.gateway_caller[0].arn, "")
}

output "agent_code_bucket" {
  value = try(aws_s3_bucket.agent_code[0].id, "")
}

output "runtime_idle_session_timeout_seconds" {
  value = tostring(var.runtime_idle_session_timeout_seconds)
}

output "agent_environment" {
  value = local.agent_environment
}
