terraform {
  backend "s3" {
    bucket       = "sentinelpay-dev-tfstate-dlaregboyi"
    key          = "dev/network/terraform.tfstate"
    region       = "eu-west-2"
    encrypt      = true
    use_lockfile = true
  }
}