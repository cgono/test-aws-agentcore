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
