variable "project_name" {
  description = "Project name used for naming resources."
  type        = string
}

variable "environment" {
  description = "Environment name, for example dev."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where data resources will be deployed."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR allowed to access private data services."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for RDS and ElastiCache subnet groups."
  type        = list(string)
}

variable "enable_rds" {
  description = "Whether to create the RDS PostgreSQL instance."
  type        = bool
  default     = false
}

variable "enable_elasticache" {
  description = "Whether to create the ElastiCache Redis cluster."
  type        = bool
  default     = false
}

variable "db_name" {
  description = "Initial PostgreSQL database name."
  type        = string
  default     = "sentinelpay"
}

variable "db_username" {
  description = "RDS master username."
  type        = string
  default     = "sentinel"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Allocated RDS storage in GB."
  type        = number
  default     = 20
}

variable "cache_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t4g.micro"
}