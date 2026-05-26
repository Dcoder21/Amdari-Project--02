output "vpc_id" {
  description = "Created VPC ID."
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "Created public subnet IDs."
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Created private subnet IDs."
  value       = module.network.private_subnet_ids
}

output "nat_gateway_id" {
  description = "NAT Gateway ID if enabled."
  value       = module.network.nat_gateway_id
}

output "ecs_task_execution_role_arn" {
  description = "ECS task execution role ARN."
  value       = module.identity.ecs_task_execution_role_arn
}

output "payments_task_role_arn" {
  description = "Payments API ECS task role ARN."
  value       = module.identity.payments_task_role_arn
}

output "kyc_task_role_arn" {
  description = "KYC API ECS task role ARN."
  value       = module.identity.kyc_task_role_arn
}

output "github_actions_deploy_role_arn" {
  description = "GitHub Actions deploy role ARN."
  value       = module.identity.github_actions_deploy_role_arn
}

output "kms_key_arn" {
  description = "Data KMS key ARN."
  value       = module.data.kms_key_arn
}

output "kyc_documents_bucket_name" {
  description = "Encrypted KYC documents bucket name."
  value       = module.data.kyc_documents_bucket_name
}

output "database_secret_arn" {
  description = "Database credentials secret ARN."
  value       = module.data.database_secret_arn
}

output "db_subnet_group_name" {
  description = "RDS subnet group name."
  value       = module.data.db_subnet_group_name
}

output "rds_security_group_id" {
  description = "RDS security group ID."
  value       = module.data.rds_security_group_id
}

output "rds_endpoint" {
  description = "RDS endpoint if enabled."
  value       = module.data.rds_endpoint
}

output "elasticache_subnet_group_name" {
  description = "ElastiCache subnet group name."
  value       = module.data.elasticache_subnet_group_name
}

output "elasticache_security_group_id" {
  description = "ElastiCache security group ID."
  value       = module.data.elasticache_security_group_id
}

output "redis_primary_endpoint" {
  description = "Redis primary endpoint if enabled."
  value       = module.data.redis_primary_endpoint
}