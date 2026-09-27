output "code_interpreter_id" {
  value = aws_bedrockagentcore_code_interpreter.this.code_interpreter_id
}

output "code_interpreter_arn" {
  value = aws_bedrockagentcore_code_interpreter.this.code_interpreter_arn
}

output "network_mode" {
  value = var.network_mode
}

output "execution_role_arn" {
  value = var.execution_role_arn
}
