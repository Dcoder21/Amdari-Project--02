resource "aws_ecr_repository" "this" {
  for_each = local.services

  name = "sentinelpay-${each.key}"
  # MUTABLE only because ci.yml still pushes :latest. Flip to IMMUTABLE
  # when the Week 3 pipeline tags by commit SHA / digest.
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.this["data"].arn
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each   = aws_ecr_repository.this
  repository = each.value.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 30 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 30 }
      action       = { type = "expire" }
    }]
  })
}
