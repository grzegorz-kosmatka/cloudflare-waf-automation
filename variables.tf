# ACTIONS TAKEN BY WAF
variable "action_block" {
  type        = string
  default     = "block"
  description = "block mode for both configurations: WAF and Firewall rules."
}

variable "action_js_challenge" {
  type        = string
  default     = "js_challenge"
  description = "js challenge mode for both configurations: WAF and Firewall rules."
}

variable "action_log" {
  type        = string
  default     = "log"
  description = "logging mode dedicated to WAF rules only."
}

variable "action_skip" {
  type        = string
  default     = "skip"
  description = "skip remaining rules."
}

# WAF - RULES DESCRIPTION
variable "description_attacks" {
  type    = string
  default = "(TF rule). Deny auto attacks"
}

variable "description_blacklist" {
  type    = string
  default = "(TF rule). Deny blacklisted IPs"
}

variable "description_payloads" {
  type    = string
  default = "(TF rule). Deny malicious payloads"
}

variable "description_tor" {
  type    = string
  default = "(TF rule). Deny TOR traffic"
}

# WAF DOMAIN SPECIFIC LANGUAGE
variable "expression_attacks" {
  type    = string
  default = "(http.user_agent contains \"Seekport Crawler\")"
}

variable "expression_blacklist" {
  type    = string
  default = "(ip.src in $deny_blacklisted_ip)"
}

variable "expression_payloads" {
  type    = string
  default = "(http.request.uri contains \"wp-includes\") or (http.request.uri contains \"wp-content\")"
}

variable "expression_tor" {
  type    = string
  default = "(ip.geoip.country eq \"T1\")"
}

# WAF - ATTACK CATEGORIES
variable "waf_category_aspnet" {
  type        = string
  default     = "microsoft-asp-net"
  description = "attack category - microsoft asp.net"
}

variable "waf_category_body" {
  type        = string
  default     = "body"
  description = "attack category - body anomaly"
}

variable "waf_category_command_injection" {
  type        = string
  default     = "command-injection"
  description = "attack category - command injection"
}

variable "waf_category_jquery" {
  type        = string
  default     = "jquery-file-upload"
  description = "attack category - jquery file upload"
}

variable "waf_category_dotnetnuke" {
  type        = string
  default     = "dotnetnuke"
  description = "attack category - dotnetnuke"
}

variable "waf_category_log4j" {
  type        = string
  default     = "log4j"
  description = "attack category - log4j"
}

variable "waf_category_sqli" {
  type        = string
  default     = "sqli"
  description = "attack category - sqli"
}

variable "waf_category_ssrf" {
  type        = string
  default     = "ssrf"
  description = "attack category - ssrf"
}

variable "waf_category_url" {
  type        = string
  default     = "url"
  description = "attack category - url"
}

variable "waf_category_user_agent" {
  type        = string
  default     = "user-agent"
  description = "attack category - user agent"
}

variable "waf_category_info_disclosure" {
  type        = string
  default     = "information-disclosure"
  description = "attack category - information disclosure"
}

variable "waf_category_header" {
  type        = string
  default     = "header"
  description = "attack category - header"
}

variable "waf_category_xss" {
  type        = string
  default     = "xss"
  description = "attack category - xss"
}

variable "waf_category_xxe" {
  type        = string
  default     = "xxe"
  description = "attack category - xxe"
}

# SPECIFIC SINGULAR RULES 
variable "waf_rule_949110_inbound_anomaly_score_exceeded" {
  type        = string
  default     = "6179ae15870a4bb7b2d480d4843b323c"
  description = "949110: Inbound Anomaly Score Exceeded. Associated with Machine Learning (ML) and scoring system. Can not be disabled."
}

variable "waf_rule_anomaly_body_large" {
  type        = string
  default     = "ee922cf00077462d9f2f7330b114b839"
  description = "Anomaly:Body - Large"
}

variable "waf_rule_anomaly_header_accept_missing" {
  type        = string
  default     = "92c7387108f3465da1f4c8f7cc74ff69"
  description = "Anomaly:Header:Accept - Missing or Empty"
}

variable "waf_rule_anomaly_header_ua_referer" {
  type        = string
  default     = "0fa48ed6287c4447b6cd89c4f59a8de9"
  description = "Anomaly:Header:User-Agent, Anomaly:Header:Referer - Missing or empty"
}

variable "waf_rule_anomaly_header_xforwarded_host" {
  type        = string
  default     = "4ccd67a8fbc645d78c5cd9ca4343ef6b"
  description = "Anomaly:Header:X-Forwarded-Host"
}

variable "waf_rule_anomaly_method_unknown_http" {
  type        = string
  default     = "6e2240ffcb87477bbd4881b6fd13142f"
  description = "Anomaly:Method - Unknown HTTP Method"
}

variable "waf_rule_anomaly_method_unusual_http" {
  type        = string
  default     = "ab53f93c9b03472ab34a5405d9bdc7d5"
  description = "Anomaly:Method - Unusual HTTP Method"
}

variable "waf_rule_code_injection_cve_2022_29078" {
  type        = string
  default     = "3fe69f2a728e40dfabd2cfb602a9ee96"
  description = "Code Injection - CVE:CVE-2022-29078"
}

variable "waf_rule_dangerous_file_upload" {
  type        = string
  default     = "3f02b0d1e3c84349818464b1563eac87"
  description = "Dangerous File Upload - Renamed"
}

variable "waf_rule_file_inclusion_double_slash_path" {
  type        = string
  default     = "6c643ea21e38417fbd12338ac991c746"
  description = "File Inclusion - Double Slash Path"
}

variable "waf_rule_rce_double_extension" {
  type        = string
  default     = "955112e62e3e4b1ebf27eb26d3cdd6ac"
  description = "Remote Code Execution - Double Extension"
}

variable "waf_rule_validate_headers" {
  type        = string
  default     = "a109ceed9326492db0a8ad90f4b0220e"
  description = "Validate Headers"
}

variable "waf_rule_vulnerability_scanner_activity" {
  type        = string
  default     = "0242110ae62e44028a13bf4834780914"
  description = "Vulnerability scanner activity"
}

variable "waf_rule_vulnerability_scanner_activity_2" {
  type        = string
  default     = "223829d453cc4a0e9324811f3a9dc737"
  description = "Vulnerability scanner activity"
}

variable "waf_rule_webshell_activity" {
  type        = string
  default     = "fd5d5678ce594ea898aa9bf149e6b538"
  description = "Web Shell Activity"
}

variable "waf_rule_webshell_malware" {
  type        = string
  default     = "9f35644b7f734c87a57cfd6d8b036974"
  description = "Malware, Web Shell"
}

# WAF OVERRIDE'S SECTION
variable "waf_rules_disabled" {
  type        = string
  default     = "disabled"
  description = "Override and disable specific rules on a WAF level."
}

variable "waf_rules_enabled" {
  type        = string
  default     = "enabled"
  description = "Override and enable specific rules on a WAF level."
}

# WAF SENSTIVITY LEVELS
variable "waf_tag_paranoia_level_1" {
  type        = string
  default     = "paranoia-level-1"
  description = "activate rules associated with PL1 level."
}

variable "waf_tag_paranoia_level_2" {
  type        = string
  default     = "paranoia-level-2"
  description = "activate rules associated with PL2 level."
}

variable "waf_tag_paranoia_level_3" {
  type        = string
  default     = "paranoia-level-3"
  description = "activate rules associated with PL3 level."
}

variable "waf_tag_paranoia_level_4" {
  type        = string
  default     = "paranoia-level-4"
  description = "activate rules associated with PL4 level."
}

# WAF THRESHOLDS
variable "waf_threshold_low" {
  type        = string
  default     = "60"
  description = "set the threshold to low - 60 or higher."
}

variable "waf_threshold_medium" {
  type        = string
  default     = "40"
  description = "set the threshold to low - 40 or higher."
}

variable "waf_threshold_high" {
  type        = string
  default     = "20"
  description = "set the threshold to low - 20 or higher."
}

# ZONE ID
variable "zoneID" {
  type        = string
  default     = ""
  description = ""
}
