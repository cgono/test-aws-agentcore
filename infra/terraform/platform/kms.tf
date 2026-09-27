# Only the unified API's signer role may kms:Sign. Account administrators retain
# PutKeyPolicy, so they can still change this boundary; that is a POC admin risk.
resource "aws_iam_role" "grant_signer" {
  name                 = "${var.name_prefix}_grant_signer"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Condition = { ArnLike = { "aws:PrincipalArn" = "arn:aws:iam::${local.account_id}:role/aws-reserved/sso.amazonaws.com/*" } }
    }]
  })
}

resource "aws_kms_key" "grant" {
  description              = "Phase 3a session-grant signing key (ES256)"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action = [
          "kms:CreateAlias", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
          "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource",
          "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
        ]
        Resource = "*"
      },
      {
        Sid       = "OnlyTheSignerRoleSigns"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.grant_signer.arn }
        Action    = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
        Resource  = "*"
      },
      {
        Sid       = "NoSigningOutsideSignerRole"
        Effect    = "Deny"
        Principal = "*"
        Action    = "kms:Sign"
        Resource  = "*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = aws_iam_role.grant_signer.arn } }
      },
      {
        Sid       = "NoSigningGrants"
        Effect    = "Deny"
        Principal = "*"
        Action    = "kms:CreateGrant"
        Resource  = "*"
      },
    ]
  })
}

data "aws_kms_public_key" "grant" {
  key_id = aws_kms_key.grant.key_id
}
