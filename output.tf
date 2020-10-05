output "this_wafv2_webacl_arn" {
  description = "The name of the bucket."
  value       = aws_wafv2_web_acl.WAFWebACL.arn
}
