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

variable "deploy_runtime" {
  type    = bool
  default = false
}

variable "entra_tenant_id" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.entra_tenant_id) > 0
    error_message = "entra_tenant_id is required when deploy_runtime is true."
  }
}

variable "gateway_app_client_id" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.gateway_app_client_id) > 0
    error_message = "gateway_app_client_id is required when deploy_runtime is true."
  }
}

variable "gateway_caller_client_id" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.gateway_caller_client_id) > 0
    error_message = "gateway_caller_client_id is required when deploy_runtime is true."
  }
}

variable "gateway_base_url" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || startswith(var.gateway_base_url, "https://")
    error_message = "gateway_base_url must be an https URL when deploy_runtime is true."
  }
}

variable "agent_openai_model" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.agent_openai_model) > 0
    error_message = "agent_openai_model is required when deploy_runtime is true."
  }
}

variable "agent_anthropic_model" {
  type    = string
  default = ""

  validation {
    condition     = !var.deploy_runtime || length(var.agent_anthropic_model) > 0
    error_message = "agent_anthropic_model is required when deploy_runtime is true."
  }
}

variable "agent_zip_path" {
  type    = string
  default = "../../../build/agent/agent.zip"
}

variable "runtime_idle_session_timeout_seconds" {
  type    = number
  default = 120
}

variable "runtime_max_lifetime_seconds" {
  type    = number
  default = 900
}
