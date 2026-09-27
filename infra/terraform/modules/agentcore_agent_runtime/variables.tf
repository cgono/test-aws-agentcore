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
  type        = string
  description = "Bootstrap artifact bucket, used when the runtime is created. Later code is CD-owned."
}

variable "code_object_key" {
  type        = string
  description = "Bootstrap artifact key, used when the runtime is created. Later code is CD-owned."
}

variable "code_object_version_id" {
  type        = string
  default     = null
  description = "Bootstrap S3 object version. The app CD pipeline owns later runtime code updates."
}

variable "python_runtime" {
  type        = string
  default     = "PYTHON_3_13"
  description = "Python runtime at create time; later artifact changes are owned by app CD."

  validation {
    condition     = contains(["PYTHON_3_10", "PYTHON_3_11", "PYTHON_3_12", "PYTHON_3_13"], var.python_runtime)
    error_message = "python_runtime must be PYTHON_3_10 through PYTHON_3_13."
  }
}

variable "entry_point" {
  type        = list(string)
  default     = ["main.py"]
  description = "Entry point at create time; later artifact changes are owned by app CD."

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

variable "authorizer" {
  type = object({
    discovery_url    = string
    allowed_audience = list(string)
    custom_claims = list(object({
      name       = string
      value_type = string
      operator   = string
      value      = optional(string)
      values     = optional(list(string))
    }))
  })
  default     = null
  description = "Inbound JWT authorizer. null keeps IAM (SigV4) invocation."

  validation {
    condition = var.authorizer == null ? true : (
      length(var.authorizer.allowed_audience) > 0 &&
      length(var.authorizer.custom_claims) > 0 && alltrue([
        for claim in var.authorizer.custom_claims :
        contains(["STRING", "STRING_ARRAY"], claim.value_type) &&
        contains(["EQUALS", "CONTAINS", "CONTAINS_ANY"], claim.operator) &&
        (claim.operator == "EQUALS" ? claim.value_type == "STRING" : claim.value_type == "STRING_ARRAY") &&
        (claim.operator == "CONTAINS_ANY"
          ? claim.values != null && try(length(claim.values), 0) > 0 && claim.value == null
        : claim.value != null && claim.value != "" && claim.values == null)
      ])
    )
    error_message = "authorizer needs at least one claim; each claim needs a supported type/operator and exactly one matching value."
  }
}

variable "request_header_allowlist" {
  type    = list(string)
  default = []
}

variable "readable_code_keys" {
  type        = list(string)
  default     = null
  description = "Additional S3 keys the execution role may read; the bootstrap code_object_key is always included."
}

variable "extra_policy_statements" {
  type        = any
  default     = []
  description = "Additional IAM statement objects for the execution role."

  validation {
    condition = try(alltrue([
      for statement in var.extra_policy_statements :
      statement.Effect != null && statement.Action != null && statement.Resource != null
    ]), false)
    error_message = "extra_policy_statements must be a list of objects with Effect, Action, and Resource."
  }
}
