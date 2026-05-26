output "kms_key_arn" {
  description = "ARN of the KMS key used for data encryption."
  value       = aws_kms_key.data.arn
}

output "kyc_documents_bucket_name" {
  description = "Name of the encrypted KYC documents S3 bucket."
  value       = aws_s3_bucket.kyc_documents.bucket
}

output "database_secret_arn" {
  description = "ARN of the Secrets Manager database credentials secret."
  value       = aws_secretsmanager_secret.database_credentials.arn
}

output "db_subnet_group_name" {
  description = "Name of the RDS subnet group."
  value       = aws_db_subnet_group.main.name
}

output "rds_security_group_id" {
  description = "Security group ID for RDS."
  value       = aws_security_group.rds.id
}

output "rds_endpoint" {
  description = "RDS endpoint if RDS is enabled."
  value       = var.enable_rds ? aws_db_instance.postgres[0].endpoint : null
}

output "elasticache_subnet_group_name" {
  description = "Name of the ElastiCache subnet group."
  value       = aws_elasticache_subnet_group.main.name
}

output "elasticache_security_group_id" {
  description = "Security group ID for ElastiCache."
  value       = aws_security_group.elasticache.id
}

output "redis_primary_endpoint" {
  description = "Redis primary endpoint if ElastiCache is enabled."
  value       = var.enable_elasticache ? aws_elasticache_replication_group.redis[0].primary_endpoint_address : null
}