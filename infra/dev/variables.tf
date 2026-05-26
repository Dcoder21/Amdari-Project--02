variable "project_name" {
  description = "Project name."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "aws_region" {
  description = "AWS region."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
}

variable "availability_zones" {
  description = "Availability zones for subnets."
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDR blocks."
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDR blocks."
  type        = list(string)
}

variable "enable_nat_gateway" {
  description = "Whether to enable NAT Gateway."
  type        = bool
  default     = false
}

variable "github_owner" {
  description = "GitHub organisation or username."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name."
  type        = string
}

variable "github_branch" {
  description = "GitHub branch allowed to assume the deploy role."
  type        = string
}

variable "enable_rds" {
  description = "Whether to create the RDS PostgreSQL instance."
  type        = bool
}

variable "enable_elasticache" {
  description = "Whether to create the ElastiCache Redis cluster."
  type        = bool
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
}

variable "cache_node_type" {
  description = "ElastiCache node type."
  type        = string
}