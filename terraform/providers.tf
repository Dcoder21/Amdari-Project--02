provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "sentinelpay"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  name          = "sentinelpay-${var.environment}"
  azs           = slice(data.aws_availability_zones.available.names, 0, 2)
  service_ports = { "payments-api" = 8001, "kyc-api" = 8002 }
  services      = toset(keys(local.service_ports))
}
