terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket       = "verenox-tf-state-bm"
    key          = "w07/terraform.tfstate"
    region       = "us-west-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-west-1"
}

variable "bucket_name" {
  type    = string
  default = "verenox-quotes-demo-bm"
}

resource "aws_s3_bucket" "quotes" {
  bucket = var.bucket_name
  tags   = { Project = "Verenox", Environment = "lab" }
}

resource "aws_s3_bucket_public_access_block" "quotes" {
  bucket                  = aws_s3_bucket.quotes.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "bucket_arn" {
  value = aws_s3_bucket.quotes.arn
}