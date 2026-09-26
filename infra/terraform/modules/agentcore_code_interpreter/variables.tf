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
