output "agent_runtime_arn" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_arn
}

output "agent_runtime_id" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_id
}

output "agent_runtime_version" {
  value = aws_bedrockagentcore_agent_runtime.this.agent_runtime_version
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}
