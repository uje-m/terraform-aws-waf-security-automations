###
# Lambda ReputationListsParser

resource "aws_lambda_function" "ReputationListsParser" {
  function_name = "ReputationListsParser"
  handler       = "reputation-lists.lambda_handler"
  role          = aws_iam_role.LambdaRoleReputationListsParser.arn
  runtime       = "python3.8"
  memory_size   = 512
  timeout       = 300
  s3_bucket     = "${local.source_code.general.source_bucket}-${local.provider}"
  s3_key        = "${local.source_code.general.key_prefix}/reputation_lists_parser.zip"
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
    resources = ["arn:${data.aws_partition.current.partition}:logs:${local.provider}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*ReputationListsParser*"]

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
