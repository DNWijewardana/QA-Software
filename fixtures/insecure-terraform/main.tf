# FIXTURE — intentionally insecure Terraform for the golden corpus (spec X.3). NOT for real use.
# Note: this comment mentions acl = "public-read" but must NOT be flagged (comment-stripping test).

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  # SEEDED: public bucket ACL (TF-S3-PUBLIC-001)
  acl = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    # SEEDED: open to the whole internet (TF-SG-OPEN-001)
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "vol" {
  # SEEDED: encryption disabled (TF-UNENCRYPTED-001)
  encrypted = false
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    # SEEDED: over-broad IAM (TF-IAM-WILDCARD-001)
    Statement = [{ Action = "*", Resource = "*" }]
  })
}

resource "aws_db_instance" "db" {
  # SEEDED: hardcoded secret (TF-SECRET-001)
  password = "hunter2secretpw"
}

resource "aws_instance" "vm" {
  # SEEDED: auto-assigns a public IP (TF-PUBLIC-IP-001)
  associate_public_ip_address = true
}
