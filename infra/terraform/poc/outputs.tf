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
