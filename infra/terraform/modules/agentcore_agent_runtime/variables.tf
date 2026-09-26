variable "name" {
  type        = string
  description = "Runtime name: a letter, then letters, digits, or underscores (max 48)."

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{0,47}$", var.name))
    error_message = "name must match ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ (no hyphens)."
  }
}

variable "description" {
  type    = string
  default = null
}

variable "code_bucket_name" {
  type = string
}

variable "code_object_key" {
  type = string
}

variable "code_object_version_id" {
  type        = string
  default     = null
  description = "S3 object version of the zip. Pass it so that a new zip changes the runtime and redeploys it."
}

variable "python_runtime" {
  type    = string
  default = "PYTHON_3_13"

  validation {
    condition     = contains(["PYTHON_3_10", "PYTHON_3_11", "PYTHON_3_12", "PYTHON_3_13"], var.python_runtime)
    error_message = "python_runtime must be PYTHON_3_10 through PYTHON_3_13."
  }
}

variable "entry_point" {
  type    = list(string)
  default = ["main.py"]

  validation {
    condition     = length(var.entry_point) >= 1 && length(var.entry_point) <= 2
    error_message = "entry_point must have 1 or 2 elements."
  }
}

variable "environment_variables" {
  type    = map(string)
  default = {}
}

variable "secret_arns" {
  type    = list(string)
  default = []
}

variable "network_mode" {
  type    = string
  default = "PUBLIC"

  validation {
    condition     = contains(["PUBLIC", "VPC"], var.network_mode)
    error_message = "network_mode must be PUBLIC or VPC."
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

variable "idle_session_timeout_seconds" {
  type    = number
  default = 900

  validation {
    condition     = var.idle_session_timeout_seconds >= 60 && var.idle_session_timeout_seconds <= 28800
    error_message = "idle_session_timeout_seconds must be between 60 and 28800."
  }
}

variable "max_lifetime_seconds" {
  type    = number
  default = 28800

  validation {
    condition     = var.max_lifetime_seconds >= var.idle_session_timeout_seconds && var.max_lifetime_seconds <= 28800
    error_message = "max_lifetime_seconds must be at least idle_session_timeout_seconds and at most 28800."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
