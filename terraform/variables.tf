variable "region" {
  description = "AWS region. af-south-1 is opt-in: enable it on the account first."
  type        = string
  default     = "af-south-1"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "github_repo" {
  description = "GitHub repository (owner/name) allowed to assume the deploy role via OIDC."
  type        = string
  default     = "sadorect/Amdari-Project--02"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "nat_gateway_per_az" {
  description = "One NAT gateway per AZ (prod posture) or a single shared one (cheaper for dev)."
  type        = bool
  default     = false
}

variable "db_multi_az" {
  type    = bool
  default = false
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.micro"
}

variable "alert_email" {
  description = "Email subscribed to the security-findings SNS topic. Empty skips the subscription."
  type        = string
  default     = ""
}

variable "desired_count" {
  type    = number
  default = 1
}

variable "certificate_arn" {
  description = "ACM certificate for the ALB HTTPS listener. Empty falls back to HTTP only, which is NOT acceptable beyond a throwaway dev stack."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Image tag deployed to ECS. CI pushes :latest today; pin to a digest once the Week 3 pipeline lands."
  type        = string
  default     = "latest"
}
