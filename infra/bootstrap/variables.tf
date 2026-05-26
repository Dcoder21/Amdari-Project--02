variable "project_name" {
  description = "Name of the project."
  type        = string
}

variable "environment" {
  description = "Deployment environment name, for example dev, staging, or prod."
  type        = string
}

variable "aws_region" {
  description = "AWS region where the Terraform state bucket will be created."
  type        = string
}

variable "state_bucket_name" {
  description = "Globally unique S3 bucket name for storing Terraform state."
  type        = string
}

variable "force_destroy_state_bucket" {
  description = "Whether to allow Terraform to delete the state bucket even if it contains objects. Keep false for safer environments."
  type        = bool
}