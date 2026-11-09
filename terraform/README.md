# SentinelPay infrastructure (Week 2)

Single-environment Terraform for the target state in
`docs/ARCHITECTURE_NOTES.md`. Nothing here has been applied yet; it is
validated (`terraform validate`) and scanned (`trivy config`) offline.

| File | Covers |
|------|--------|
| `network.tf` | VPC, public / private / isolated tiers, VPC endpoints, flow logs (V-CLD-08) |
| `data.tf` | Private encrypted RDS (V-CLD-01), Redis with TLS + AUTH |
| `s3.tf` | KYC bucket SSE-KMS, no ACLs, public access blocked (V-CLD-02, V-CLD-03); Object Lock trail bucket |
| `detection.tf` | CloudTrail with validation + KMS (V-CLD-06), GuardDuty (V-CLD-07), Security Hub FSBP + CIS, high-severity alerts |
| `iam.tf` | Per-service task roles, GitHub OIDC build + deploy roles (V-CLD-05, V-PIP-03, V-CLD-04) |
| `ecs.tf`, `ecr.tf` | ALB, Fargate services, repositories |

## Applying

1. Configure credentials (default region `eu-west-2`; opt-in regions such as `af-south-1` must be enabled on the account first).
2. `terraform init && terraform plan`, review, `terraform apply`.
3. Populate the JWT secrets out of band (never through Terraform state):
   `aws secretsmanager put-secret-value --secret-id sentinelpay-dev/jwt-public-key-b64 ...`
4. Copy the `ecr_registry` and `github_deploy_role_arn` outputs into
   `.github/workflows/ci.yml` (placeholders already replaced with account `723799951407` / `eu-west-2`).
5. Move state to S3 (see the commented backend in `versions.tf`).

## Known gaps before this can serve traffic

- **App config.** The services read `DATABASE_URL` and `REDIS_URL`; the task
  definitions inject `DB_HOST/DB_USER/DB_PASSWORD/REDIS_HOST/REDIS_AUTH_TOKEN`
  from Secrets Manager (ECS cannot compose a URL). The apps need a small change
  to build those URLs (`sslmode=require`, `rediss://`).
- **Shared DB credential.** Both services currently use the RDS master user.
  The target state wants one least-privilege DB role per service, created by a
  post-apply migration step.
- **TLS.** Set `certificate_arn`; without it the ALB serves HTTP only.
- **Automated response.** High-severity GuardDuty findings go to SNS; the
  disable-IAM-user / quarantine-task Lambda and the honeytoken key are not
  built yet (Week 3 purple-team scope).
- **Image tags.** ECR tags are mutable until CI stops pushing `:latest`.

## Tearing down

Deletion protection is a variable, not an edit to the resources:

```
terraform apply -var deletion_protection=false     # lifts RDS + ALB protection, drops final snapshot, zero-day secret recovery
terraform destroy -var deletion_protection=false
```

The CloudTrail bucket has Object Lock (Governance, 365 days), so `destroy`
cannot empty it while the retention runs. Remove it from state
(`terraform state rm aws_s3_bucket.cloudtrail ...`) or empty it with
`s3:BypassGovernanceRetention` before destroying.
