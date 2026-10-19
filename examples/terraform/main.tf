# A small, realistic AWS stack to scan. It is never applied: the scan reads the
# code. Two things are deliberately wrong, the kind of drift a SOC 2 review
# finds: the exports bucket has no encryption or public access block, and the
# database accepts connections from anywhere.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_kms_key" "data" {
  description         = "Customer data"
  enable_key_rotation = true
}

# Customer data: encrypted with our own key, versioned, never public.
resource "aws_s3_bucket" "customer_data" {
  bucket = "example-customer-data"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Report exports, added later in a hurry.
resource "aws_s3_bucket" "exports" {
  bucket = "example-report-exports"
}

resource "aws_security_group" "db" {
  name        = "app-db"
  description = "Postgres for the app"

  ingress {
    description = "Postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app" {
  identifier              = "app"
  engine                  = "postgres"
  engine_version          = "17"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "app"
  password                = var.db_password
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.data.arn
  backup_retention_period = 7
  deletion_protection     = true
  publicly_accessible     = true
  vpc_security_group_ids  = [aws_security_group.db.id]
  skip_final_snapshot     = false
}
