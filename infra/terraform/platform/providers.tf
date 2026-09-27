provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      project    = "agentcore-platform-poc"
      managed_by = "terraform"
    }
  }
}
