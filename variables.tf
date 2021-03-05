variable "name" {
  description = "name of environment"
}

variable "tags" {
  description = "Resource tagging"
  default     = {}
}

variable "scope" {
  description = "REGIONAL or CLOUDFRONT type WebACL"
  validation {
    condition     = (var.scope == "REGIONAL" || var.scope == "CLOUDFRONT")
    error_message = "Please enter either REGIONAL or CLOUDFRONT."
  }
}

variable "whitelist_ipv4" {
  description = "Allow whitelist for IPV4 addresses"
  default     = []
}

variable "blacklist_ipv4" {
  default     = []
  description = "Block blacklist for IPV4 addresses"
}

variable "allowed_country_codes" {
  description = "Whitelist access by country"
  default     = []
}

variable "reputation_list_ipv6" {
  description = "These lists include the Spamhaus Dont Route Or Peer (DROP) and Extended Drop (EDROP) lists, the Proofpoint Emerging Threats IP list, and the Tor exit node list."
  default     = []
}
variable "reputation_list_ipv4" {
  description = "These lists include the Spamhaus Dont Route Or Peer (DROP) and Extended Drop (EDROP) lists, the Proofpoint Emerging Threats IP list, and the Tor exit node list."
  default     = []
}

variable "asw_managed_rules_common_rule_set_exclude_rule" {
  default     = []
  type        = list(string)
  description = "The ExcludedRules specification lists rules whose actions are overridden to count only."
}

variable "region" {
  description = "The current AWS region the resources will be created"
  type        = string
  default     = "eu-west-1"
}

variable "enable_xss_rule" {
  description = "Enable or disable XSS Rule"
  default     = "true"
  type        = bool
}

variable "enable_sqli_rule" {
  description = "Enable or disable SQLi Rule"
  default     = "true"
  type        = bool
}
