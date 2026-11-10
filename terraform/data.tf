# V-CLD-01: RDS lives in the isolated subnets, publicly_accessible = false,
# reachable only from the app security group. Redis likewise.

resource "aws_security_group" "app" {
  name_prefix = "${local.name}-app-"
  description = "Fargate tasks"
  vpc_id      = aws_vpc.this.id

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "db" {
  name_prefix = "${local.name}-db-"
  description = "RDS: Postgres from app tasks only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "Postgres from app"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "redis" {
  name_prefix = "${local.name}-redis-"
  description = "Redis from app tasks only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "Redis from app"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = aws_subnet.isolated[*].id
}

resource "aws_db_parameter_group" "this" {
  name_prefix = "${local.name}-"
  family      = "postgres15"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot" # static parameter
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_db_instance" "this" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = "15"
  instance_class = var.db_instance_class

  db_name  = "sentinelpay"
  username = "sentinel_admin"

  # RDS owns the master password in Secrets Manager (KMS-encrypted) and
  # rotates it; it never appears in Terraform state or in code.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.this["secrets"].arn

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.this["data"].arn

  multi_az               = var.db_multi_az
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.this.name

  backup_retention_period             = var.db_backup_retention_days
  copy_tags_to_snapshot               = true
  deletion_protection                 = var.deletion_protection
  skip_final_snapshot                 = !var.deletion_protection
  final_snapshot_identifier           = "${local.name}-final"
  auto_minor_version_upgrade          = true
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.this["data"].arn
}

# --- Redis ------------------------------------------------------------------

resource "aws_elasticache_subnet_group" "this" {
  name       = local.name
  subnet_ids = aws_subnet.isolated[*].id
}

resource "random_password" "redis" {
  length  = 48
  special = false # ElastiCache AUTH tokens forbid several special characters
}

resource "aws_secretsmanager_secret" "redis_auth" {
  name                    = "${local.name}/redis-auth-token"
  kms_key_id              = aws_kms_key.this["secrets"].arn
  recovery_window_in_days = var.deletion_protection ? 30 : 0
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id     = aws_secretsmanager_secret.redis_auth.id
  secret_string = random_password.redis.result
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = local.name
  description          = "${local.name} cache"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  port                 = 6379

  num_cache_clusters         = var.db_multi_az ? 2 : 1
  automatic_failover_enabled = var.db_multi_az

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.this["data"].arn
  transit_encryption_enabled = true
  auth_token                 = random_password.redis.result
  snapshot_retention_limit   = 7
}
