output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "ecr_repository_urls" {
  value = { for k, r in aws_ecr_repository.this : k => r.repository_url }
}

output "github_deploy_role_arn" {
  description = "Set as AWS_DEPLOY_ROLE_ARN in .github/workflows/ci.yml."
  value       = aws_iam_role.github_deploy.arn
}

output "github_build_role_arn" {
  value = aws_iam_role.github_build.arn
}

output "ecr_registry" {
  description = "Set as ECR_REGISTRY in .github/workflows/ci.yml."
  value       = "${local.account_id}.dkr.ecr.${var.region}.amazonaws.com"
}

output "kyc_bucket" {
  value = aws_s3_bucket.kyc.id
}

output "security_findings_topic_arn" {
  value = aws_sns_topic.security.arn
}
