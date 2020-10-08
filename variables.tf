variable "name" {
  description = "name of environment"
}

variable "tags" {
  description = "Resource tagging"
  default     = {}
}

variable "scope" {
  description = "REGIONAL or CLOUDFRONT type WebACL"
  default     = "REGIONAL"
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
