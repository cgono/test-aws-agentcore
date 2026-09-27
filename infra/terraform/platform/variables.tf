variable "aws_region" { type = string }
variable "aws_budget_name" { type = string }

variable "name_prefix" {
  type    = string
  default = "poc3"
}

variable "tenant_id" { type = string }
variable "hub_app_id" { type = string }
variable "gateway_app_id" { type = string }
variable "runtime_app_id" { type = string }
variable "unified_api_client_id" { type = string }

variable "research_agent_client_id" {
  type      = string
  ephemeral = true
}

variable "research_agent_client_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "bench_agent_client_id" {
  type      = string
  ephemeral = true
}

variable "bench_agent_client_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "credentials_version" {
  type        = number
  default     = 1
  description = "Increment to push new write-only client credentials to AgentCore Identity."
}

variable "gateway_base_url" {
  type        = string
  description = "cloudflared tunnel URL of the gateway sim, without a trailing slash."
}

variable "agent_model" { type = string }

variable "allow_raw_user_token" {
  type    = bool
  default = false
}

variable "bootstrap_dir" {
  type        = string
  default     = "../../../build"
  description = "Folder with probe/probe.zip and resource-hub/resource-hub.zip for the one-time bootstrap objects."
}

variable "research_agent_client_id_plain" { type = string }
variable "bench_agent_client_id_plain" { type = string }
