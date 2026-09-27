resource "aws_s3_bucket" "code" {
  bucket        = local.code_bucket
  force_destroy = true # CD-owned release versions exist that Terraform does not manage.
}

resource "aws_s3_bucket_versioning" "code" {
  bucket = aws_s3_bucket.code.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket" "workspace" {
  bucket        = local.workspace_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "all" {
  for_each                = { code = aws_s3_bucket.code.id, workspace = aws_s3_bucket.workspace.id }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "all" {
  for_each = { code = aws_s3_bucket.code.id, workspace = aws_s3_bucket.workspace.id }
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# Terraform owns only the bootstrap keys, written once. Later builds never change them.
resource "aws_s3_object" "bootstrap" {
  for_each = {
    "bootstrap/research.zip"     = "${var.bootstrap_dir}/probe/probe.zip"
    "bootstrap/bench.zip"        = "${var.bootstrap_dir}/probe/probe.zip"
    "bootstrap/resource-hub.zip" = "${var.bootstrap_dir}/resource-hub/resource-hub.zip"
  }
  bucket     = aws_s3_bucket.code.id
  key        = each.key
  source     = each.value
  depends_on = [aws_s3_bucket_versioning.code]

  lifecycle {
    ignore_changes = [source, source_hash, etag]
  }
}
