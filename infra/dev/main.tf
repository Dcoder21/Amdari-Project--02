module "network" {
  source = "../modules/network"

  project_name         = var.project_name
  environment          = var.environment
  vpc_cidr             = var.vpc_cidr
  availability_zones   = var.availability_zones
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  enable_nat_gateway   = var.enable_nat_gateway
}

module "identity" {
  source = "../modules/identity"

  project_name  = var.project_name
  environment   = var.environment
  github_owner  = var.github_owner
  github_repo   = var.github_repo
  github_branch = var.github_branch
}

module "data" {
  source = "../modules/data"

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.network.vpc_id
  vpc_cidr           = var.vpc_cidr
  private_subnet_ids = module.network.private_subnet_ids

  enable_rds         = var.enable_rds
  enable_elasticache = var.enable_elasticache

  db_instance_class = var.db_instance_class
  cache_node_type   = var.cache_node_type
}