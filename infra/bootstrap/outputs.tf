output "state_bucket_name" {
  description = "Name of the S3 bucket created for Terraform remote state."
  value       = aws_s3_bucket.terraform_state.bucket
}

output "state_bucket_arn" {
  description = "ARN of the S3 bucket created for Terraform remote state."
  value       = aws_s3_bucket.terraform_state.arn
}

output "state_bucket_region" {
  description = "AWS region where the Terraform state bucket was created."
  value       = var.aws_region
}

# output "backend_config_example" {
#   description = "Example backend configuration to use later in the dev environment."
#   value = <<EOT
# terraform {
#   backend "s3" {
#     bucket       = "${aws_s3_bucket.terraform_state.bucket}"
#     key          = "envs/dev/terraform.tfstate"
#     region       = "${var.aws_region}"
#     encrypt      = true
#     use_lockfile = true
#   }
# }
# EOT
# }