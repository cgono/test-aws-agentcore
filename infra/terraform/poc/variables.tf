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
