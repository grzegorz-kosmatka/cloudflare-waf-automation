output "return_waf_custom_config" {
  description = "custom WAF configuration entrypoint ID"
  value       = cloudflare_ruleset.zone_custom_firewall.id
}

output "return_waf_custom_config_id" {
  description = "custom WAF configuration"
  value       = cloudflare_ruleset.zone_custom_firewall
}

output "return_waf_managed_config_id" {
  description = "managed WAF configuration entrypoint IDs"
  value       = cloudflare_ruleset.zone_level_managed_waf.id
}

output "return_waf_managed_config" {
  description = "managed WAF configuration"
  value       = cloudflare_ruleset.zone_level_managed_waf
}
