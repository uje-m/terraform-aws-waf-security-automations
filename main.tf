# AWS provider and region
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

provider "aws" {
  region = local.provider
  alias  = "scope_region"
}

locals {
  source_code = {
    general = {
      source_bucket = "solutions"
      key_prefix    = "aws-waf-security-automations/v3.1.0"
    }
  }
  provider    = var.scope == "CLOUDFRONT" ? "us-east-1" : var.region
  common_tags = var.tags
  waf = {
    account_short_name = upper(var.name)
  }
}

##
# Resources
resource "random_id" "this" {
  byte_length = 8
}

###
# WAF IP4 sets
resource "aws_wafv2_ip_set" "WAFWhitelistSetV4" {
  name               = "${local.waf.account_short_name}-WhitelistSetIPV4-${random_id.this.hex}"
  description        = "Allow whitelist for IPV4 addresses"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.whitelist_ipv4
  provider           = aws.scope_region
  tags               = local.common_tags
  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_wafv2_ip_set" "WAFBlacklistSetV4" {
  name               = "${local.waf.account_short_name}-BlacklistSetIPV4-${random_id.this.hex}"
  description        = "Block blacklist for IPV4 addresses"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.blacklist_ipv4
  provider           = aws.scope_region
  tags               = local.common_tags
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_ip_set" "WAFReputationListsSetV4" {
  name               = "${local.waf.account_short_name}-IPReputationListsSetIPV4-${random_id.this.hex}"
  description        = "Block blacklist for IPV4 addresses"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.reputation_list_ipv4
  lifecycle {
    ignore_changes        = [addresses]
    create_before_destroy = true
  }

  provider = aws.scope_region

  tags = local.common_tags
}

###
# WAF IP6 sets

resource "aws_wafv2_ip_set" "WAFReputationListsSetV6" {
  name               = "${local.waf.account_short_name}-IPReputationListsSetIPV6-${random_id.this.hex}"
  description        = "Block blacklist for IPV6 addresses"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = var.reputation_list_ipv6
  lifecycle {
    ignore_changes        = [addresses]
    create_before_destroy = true
  }

  provider = aws.scope_region

  tags = local.common_tags
}

###
# WAF Web ACL & Rules
resource "aws_wafv2_web_acl" "WAFWebACL" {
  name        = "AWSWAFSecurityAutomations${var.scope}${random_id.this.hex}"
  description = "Custom WAFWebACL"
  scope       = var.scope
  provider    = aws.scope_region
  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "AWSWAFSecurityAutomations-WAFWebACL"
    sampled_requests_enabled   = true
  }
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 0
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        dynamic "excluded_rule" {
          for_each = var.asw_managed_rules_common_rule_set_exclude_rule == [] ? [] : var.asw_managed_rules_common_rule_set_exclude_rule
          content {
            name = excluded_rule.value
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RuleWithAWSManagedRulesMetric"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "${local.waf.account_short_name}-WhitelistRule"
    priority = 1
    action {
      allow {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.WAFWhitelistSetV4.arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.waf.account_short_name}-WhitelistRule"
      sampled_requests_enabled   = true
    }
  }
  dynamic "rule" {
    for_each = var.allowed_country_codes == [] ? [] : [1]
    content {
      name     = "${local.waf.account_short_name}-WhitelistRuleByCountry"
      priority = 2
      action {
        allow {}
      }
      statement {
        not_statement {
          statement {
            geo_match_statement {
              country_codes = var.allowed_country_codes
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.waf.account_short_name}-WhitelistRuleByCountry"
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "${local.waf.account_short_name}-BlacklistRule"
    priority = 3
    action {
      block {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.WAFBlacklistSetV4.arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.waf.account_short_name}-BlacklistRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "${local.waf.account_short_name}-IPReputationListsRule"
    priority = 6
    action {
      block {}
    }
    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFReputationListsSetV4.arn
          }
        }
        statement {

          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFReputationListsSetV6.arn
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.waf.account_short_name}-IPReputationListsRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "${local.waf.account_short_name}-AWSWAFSecurityAutomationsSqlInjectionRule"
    priority = 20
    statement {
      or_statement {
        statement {
          sqli_match_statement {
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          sqli_match_statement {
            field_to_match {
              body {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          sqli_match_statement {
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          sqli_match_statement {
            field_to_match {
              single_header {
                name = "authorization"
              }
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          sqli_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
      }
    }
    action {
      block {}
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.waf.account_short_name}-AWSWAFSecurityAutomationsSqlInjectionRule"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = var.enable_xss_rule ? [1] : []
    content {
      name     = "${local.waf.account_short_name}-XssRule"
      priority = 30
      statement {
        or_statement {
          statement {
            xss_match_statement {
              field_to_match {
                query_string {}
              }
              text_transformation {
                priority = 1
                type     = "URL_DECODE"
              }
              text_transformation {
                priority = 2
                type     = "HTML_ENTITY_DECODE"
              }
            }
          }
          statement {
            xss_match_statement {
              field_to_match {
                body {}
              }
              text_transformation {
                priority = 1
                type     = "URL_DECODE"
              }
              text_transformation {
                priority = 2
                type     = "HTML_ENTITY_DECODE"
              }
            }
          }
          statement {
            xss_match_statement {
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 1
                type     = "URL_DECODE"
              }
              text_transformation {
                priority = 2
                type     = "HTML_ENTITY_DECODE"
              }
            }
          }
          statement {
            xss_match_statement {
              field_to_match {
                single_header {
                  name = "cookie"
                }
              }
              text_transformation {
                priority = 1
                type     = "URL_DECODE"
              }
              text_transformation {
                priority = 2
                type     = "HTML_ENTITY_DECODE"
              }
            }
          }
        }
      }
      action {
        block {}
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.waf.account_short_name}-XssRule"
        sampled_requests_enabled   = true
      }
    }
  }
}
