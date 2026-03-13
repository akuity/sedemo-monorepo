provider "aws" {
  region = "us-west-2"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.65.0"
    }
  }

  backend "s3" {
    bucket       = "arad-tf-state-files"
    region       = "us-west-2"
    key          = "kargo-steps/beyond-k8s/dev/terraform.tfstate"
    use_lockfile = true
  }
}