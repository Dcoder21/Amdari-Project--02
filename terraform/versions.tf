terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Local state until the AWS account exists. Once it does, run
  # bootstrap/ (creates the encrypted, versioned state bucket and lock
  # table), then uncomment this block and `terraform init -migrate-state`.
  #
  # backend "s3" {
  #   bucket         = "sentinelpay-tfstate-<account-id>"
  #   key            = "sentinelpay/terraform.tfstate"
  #   region         = "af-south-1"
  #   dynamodb_table = "sentinelpay-tfstate-lock"
  #   encrypt        = true
  # }
}
