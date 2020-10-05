terraform {
  required_providers {
    aws = {
      source           = "hashicorp/aws"
      required_version = ">= 3.5.0 < 4.0"
    }
  }
  required_version = ">= 0.13"
}
