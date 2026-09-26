provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      project    = "agentcore-ci-runtime-poc"
      managed_by = "terraform"
    }
  }
}
