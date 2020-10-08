output "this_wafv2_webacl_arn" {
  description = "The name WafV2 WebACL ARN"
  value       = aws_wafv2_web_acl.WAFWebACL.arn
}
