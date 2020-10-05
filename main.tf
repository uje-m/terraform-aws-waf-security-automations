# AWS provider and region
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

provider "aws" {
  region = local.provider
  alias  = "scope_region"
}

locals {
  provider    = var.scope == "CLOUDFRONT" ? "us-east-1" : data.aws_region.current.name
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
  name               = "${local.waf.account_short_name}-WhitelistSetIPV4"
  description        = "Allow whitelist for IPV4 addresses"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.whitelist_ipv4
  provider = aws.scope_region
  tags = local.common_tags
  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_wafv2_ip_set" "WAFBlacklistSetV4" {
  name               = "${local.waf.account_short_name}-BlacklistSetIPV4"
  description        = "Block blacklist for IPV4 addresses"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.blacklist_ipv4
  provider = aws.scope_region
  tags = local.common_tags
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_ip_set" "WAFReputationListsSetV4" {
  name               = "${local.waf.account_short_name}-IPReputationListsSetIPV4"
  description        = "Block blacklist for IPV4 addresses"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.reputation_list_ipv4
  lifecycle {
    ignore_changes = [addresses]
    create_before_destroy = true
  }

  provider = aws.scope_region

  tags = local.common_tags
}

###
# WAF IP6 sets

resource "aws_wafv2_ip_set" "WAFReputationListsSetV6" {
  name               = "${local.waf.account_short_name}-IPReputationListsSetIPV6"
  description        = "Block blacklist for IPV6 addresses"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = var.reputation_list_ipv6
  lifecycle {
    ignore_changes = [addresses]
    create_before_destroy = true
  }

  provider = aws.scope_region

  tags = local.common_tags
}

###
# WAF Web ACL & Rules
resource "aws_wafv2_web_acl" "WAFWebACL" {
  name        = "AWSWAFSecurityAutomations"
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

  rule {
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



###
# IAM

resource "aws_iam_role" "LambdaRoleReputationListsParser" {
  name_prefix        = "LambdaRoleReputationListsParser"
  assume_role_policy = data.aws_iam_policy_document.LambdaRoleReputationListsParserAssumeRole.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "LambdaRoleReputationListsParserAssumeRole" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "LambdaRoleReputationListsParserCloudWatchLogs" {
  statement {
    effect    = "Allow"
    resources = ["arn:aws:logs:${local.provider}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*ReputationListsParser*"]

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }
}

data "aws_iam_policy_document" "WAFGetAndUpdateIPSet" {
  statement {
    effect = "Allow"
    resources = [aws_wafv2_ip_set.WAFReputationListsSetV4.arn,
      aws_wafv2_ip_set.WAFReputationListsSetV6.arn
    ]

    actions = [
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet",
    ]
  }
}

data "aws_iam_policy_document" "CloudWatchAccess" {
  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "cloudwatch:GetMetricStatistics"
    ]
  }
}

resource "aws_iam_policy" "LambdaRoleReputationListsParserCloudWatchLogs" {
  name   = "LambdaRoleReputationListsParserCloudWatchLogs${random_id.this.hex}"
  policy = data.aws_iam_policy_document.LambdaRoleReputationListsParserCloudWatchLogs.json
}

resource "aws_iam_policy" "WAFGetAndUpdateIPSet" {
  name   = "WAFGetAndUpdateIPSet${random_id.this.hex}"
  policy = data.aws_iam_policy_document.WAFGetAndUpdateIPSet.json
}

resource "aws_iam_policy" "CloudWatchAccess" {
  name   = "CloudWatchAccess${random_id.this.hex}"
  policy = data.aws_iam_policy_document.CloudWatchAccess.json
}

locals {
  LambdaRoleReputationListsParserPolicyArn = [
    aws_iam_policy.LambdaRoleReputationListsParserCloudWatchLogs.arn,
    aws_iam_policy.WAFGetAndUpdateIPSet.arn,
    aws_iam_policy.CloudWatchAccess.arn
  ]
}

resource "aws_iam_role_policy_attachment" "LambdaRoleReputationListsParser" {
  count      = length(local.LambdaRoleReputationListsParserPolicyArn)
  role       = aws_iam_role.LambdaRoleReputationListsParser.name
  policy_arn = local.LambdaRoleReputationListsParserPolicyArn[count.index]
}

resource "aws_lambda_permission" "LambdaInvokePermissionReputationListsParser" {
  provider      = aws.scope_region
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ReputationListsParser.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ReputationListsParserEventsRule.arn
  depends_on = [
    aws_lambda_function.ReputationListsParser,
    aws_cloudwatch_event_rule.ReputationListsParserEventsRule,
  ]
}

###
# Lambda ReputationListsParser

resource "aws_lambda_function" "ReputationListsParser" {
  function_name = "ReputationListsParser"
  handler       = "reputation-lists.lambda_handler"
  role          = aws_iam_role.LambdaRoleReputationListsParser.arn
  runtime       = "python3.8"
  memory_size   = 512
  timeout       = 300
  filename      = "${path.module}/assets/reputation_lists_parser.zip"
  provider      = aws.scope_region
  environment {
    variables = {
      IP_SET_ID_REPUTATIONV4      = aws_wafv2_ip_set.WAFReputationListsSetV4.arn
      IP_SET_ID_REPUTATIONV6      = aws_wafv2_ip_set.WAFReputationListsSetV6.arn
      IP_SET_NAME_REPUTATIONV4    = aws_wafv2_ip_set.WAFReputationListsSetV4.name
      IP_SET_NAME_REPUTATIONV6    = aws_wafv2_ip_set.WAFReputationListsSetV6.name
      SCOPE                       = var.scope
      LOG_LEVEL                   = "INFO"
      URL_LIST                    = data.template_file.inventory.rendered
      SOLUTION_ID                 = "SO0006"
      METRICS_URL                 = "https://metrics.awssolutionsbuilder.com/generic"
      STACK_NAME                  = "AWSWAFSecurityAutomations"
      LOG_TYPE                    = var.scope == "REGIONAL" ? "alb" : "cloudfront"
      SEND_ANONYMOUS_USAGE_DATA   = "No"
      IPREPUTATIONLIST_METRICNAME = "${local.waf.account_short_name}-IPReputationListsRule"
    }
  }
}

data "template_file" "inventory" {
  template = <<-EOT
[{"url":"https://www.spamhaus.org/drop/drop.txt"},{"url":"https://www.spamhaus.org/drop/edrop.txt"},{"url":"https://check.torproject.org/exit-addresses", "prefix":"ExitAddress"},{"url":"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"}]
EOT
}

###
# Event

resource "aws_cloudwatch_event_rule" "ReputationListsParserEventsRule" {
  name                = "ReputationListsParserEventsRule${random_id.this.hex}"
  description         = "Security Automation - WAF Reputation Lists"
  schedule_expression = "rate(1 hour)"
  provider            = aws.scope_region
}

resource "aws_cloudwatch_event_target" "ReputationListsParserEventsTarget" {
  provider = aws.scope_region
  arn      = aws_lambda_function.ReputationListsParser.arn
  rule     = aws_cloudwatch_event_rule.ReputationListsParserEventsRule.name
  input    = <<DOC
{
  "URL_LIST": [
    {
      "url": "https://www.spamhaus.org/drop/drop.txt"
    },
    {
      "url": "https://www.spamhaus.org/drop/edrop.txt"
    },
    {
      "url": "https://check.torproject.org/exit-addresses",
      "prefix": "ExitAddress"
    },
    {
      "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    }
  ],
  "IP_SET_ID_REPUTATIONV4": "${aws_wafv2_ip_set.WAFReputationListsSetV4.arn}",
  "IP_SET_ID_REPUTATIONV6": "${aws_wafv2_ip_set.WAFReputationListsSetV6.arn}",
  "IP_SET_NAME_REPUTATIONV4": "${aws_wafv2_ip_set.WAFReputationListsSetV4.name}",
  "IP_SET_NAME_REPUTATIONV6": "${aws_wafv2_ip_set.WAFReputationListsSetV6.name}",
  "SCOPE": "var.scope"
}
DOC
}
