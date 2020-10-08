<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Application Resources](#application-resources)
  - [Requirements](#requirements)
  - [Providers](#providers)
  - [Inputs](#inputs)
  - [Outputs](#outputs)
  - [Requirements](#requirements-1)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Application Resources


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.13 |

## Providers

| Name | Version |
|------|---------|
| aws | n/a |
| aws.scope\_region | n/a |
| random | n/a |
| template | n/a |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| allowed\_country\_codes | Whitelist access by country | `list` | `[]` | no |
| blacklist\_ipv4 | Block blacklist for IPV4 addresses | `list` | `[]` | no |
| name | name of environment | `any` | n/a | yes |
| reputation\_list\_ipv4 | These lists include the Spamhaus Dont Route Or Peer (DROP) and Extended Drop (EDROP) lists, the Proofpoint Emerging Threats IP list, and the Tor exit node list. | `list` | `[]` | no |
| reputation\_list\_ipv6 | These lists include the Spamhaus Dont Route Or Peer (DROP) and Extended Drop (EDROP) lists, the Proofpoint Emerging Threats IP list, and the Tor exit node list. | `list` | `[]` | no |
| scope | REGIONAL or CLOUDFRONT type WebACL | `any` | n/a | yes |
| tags | Resource tagging | `map` | `{}` | no |
| whitelist\_ipv4 | Allow whitelist for IPV4 addresses | `list` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| this\_wafv2\_webacl\_arn | The name WafV2 WebACL ARN |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

## Requirements

To develop on this repo the following binaries are nice to have.

- Terraform 0.12
- pre-commit (https://pre-commit.com/#install)
- terraform-docs (https://github.com/segmentio/terraform-docs)