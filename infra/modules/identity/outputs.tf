output "ecs_task_execution_role_arn" {
  description = "ARN of the ECS task execution role."
  value       = aws_iam_role.ecs_task_execution.arn
}

output "payments_task_role_arn" {
  description = "ARN of the payments-api ECS task role."
  value       = aws_iam_role.payments_task.arn
}

output "kyc_task_role_arn" {
  description = "ARN of the kyc-api ECS task role."
  value       = aws_iam_role.kyc_task.arn
}

output "github_oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC provider."
  value       = aws_iam_openid_connect_provider.github.arn
}

output "github_actions_deploy_role_arn" {
  description = "ARN of the GitHub Actions deploy role."
  value       = aws_iam_role.github_actions_deploy.arn
}