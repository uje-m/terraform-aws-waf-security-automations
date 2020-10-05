locals {
  baseline_version = "v0.0.2"
  common_tags = {
    security_data_sensitivity = "protected"
    stack_version             = "0.1.0"
    stack_lifecycle           = "perm"
    VPCgroup                  = "greenfield"
  }
}


provider "aws" {
  region     = "ap-northeast-1"
}


module "webacl" {
  source = "../"

  name  = "Test"
  scope = "CLOUDFRONT"
  tags  = local.common_tags

}