locals {
  description_ruleset_core    = "OWASP Core ruleset configuration."
  description_ruleset_managed = "Cloudflare Managed ruleset overrides."
  description_waf_custom      = "Web Application Firewall (WAF) custom rules"
  description_waf_managed     = "Web Application Firewall (WAF) managed rules, OWASP CRS, settings and exceptions"
  kind_zone                   = "zone"
  rules_enforce               = "execute"
  ruleset_current             = "current"
  ruleset_core_id             = ""
  ruleset_managed_id          = ""
  ruleset_name                = "custom WAF ruleset for specific zone"
  ruleset_phase_custom        = "http_request_firewall_custom"
  ruleset_phase_managed       = "http_request_firewall_managed"
}

resource "cloudflare_ruleset" "zone_custom_firewall" {
  zone_id     = var.zoneID
  name        = local.ruleset_name
  description = local.description_waf_custom
  kind        = local.kind_zone
  phase       = local.ruleset_phase_custom

  rules {
    action      = var.action_block
    expression  = var.expression_blacklist
    description = var.description_blacklist
    enabled     = true
  }

  rules {
    action      = var.action_block
    expression  = var.expression_attacks
    description = var.description_attacks
    enabled     = true
  }

  rules {
    action      = var.action_block
    expression  = var.expression_payloads
    description = var.description_payloads
    enabled     = true
  }

  rules {
    action      = var.action_block
    expression  = var.expression_tor
    description = var.description_tor
    enabled     = true
  }
}

resource "cloudflare_ruleset" "zone_level_managed_waf" {
  zone_id     = var.zoneID
  name        = local.ruleset_name
  description = local.description_waf_managed
  kind        = local.kind_zone
  phase       = local.ruleset_phase_managed

  rules {
    action = local.rules_enforce
    action_parameters {
      id = local.ruleset_managed_id
      overrides {
        categories {
          category = var.waf_category_aspnet
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_body
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_command_injection
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_dotnetnuke
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_header
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_iis
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_info_disclosure
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_jquery
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_log4j
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_sqli
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_ssrf
          action   = var.action_log
          enabled  = true
        }
        categories {
          category = var.waf_category_url
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_user_agent
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_xss
          action   = var.action_block
          enabled  = true
        }
        categories {
          category = var.waf_category_xxe
          action   = var.action_block
          enabled  = true
        }
        rules {
          id      = var.waf_rule_anomaly_body_large
          action  = var.action_log
          enabled = false
        }
        rules {
          id      = var.waf_rule_anomaly_header_accept_missing
          action  = var.action_log
          enabled = false
        }
        rules {
          id      = var.waf_rule_anomaly_header_ua_referer
          action  = var.action_log
          enabled = false
        }
        rules {
          id      = var.waf_rule_anomaly_header_xforwarded_host
          action  = var.action_log
          enabled = false
        }
        rules {
          id      = var.waf_rule_anomaly_method_unknown_http
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_anomaly_method_unusual_http
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_code_injection_cve_2022_29078
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_dangerous_file_upload
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_file_inclusion_double_slash_path
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_validate_headers
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_vulnerability_scanner_activity
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_vulnerability_scanner_activity_2
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_webshell_activity
          action  = var.action_block
          enabled = true
        }
        rules {
          id      = var.waf_rule_webshell_malware
          action  = var.action_block
          enabled = true
        }
      }
    }
    description = local.description_ruleset_managed
    expression  = true
    enabled     = true
  }

  rules {
    action = local.rules_enforce
    action_parameters {
      id = local.ruleset_core_id
      overrides {
        categories {
          category = var.waf_tag_paranoia_level_3
          enabled  = false
        }
        categories {
          category = var.waf_tag_paranoia_level_4
          enabled  = false
        }
        rules {
          id              = var.waf_rule_949110_inbound_anomaly_score_exceeded
          action          = var.action_block
          score_threshold = var.waf_threshold_low
        }
      }
    }
    description = local.description_ruleset_core
    expression  = true
    enabled     = true
  }
}
