locals {
  apiToken               = ""
  az_kv_name             = ""
  az_kv_rg               = ""
  az_subscription_dev_id = ""
}

terraform {
  required_version = ">= 0.13"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "4.13.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.71.0"
    }
  }
}

provider "cloudflare" {
  api_token = data.azurerm_key_vault_secret.cf_api_token.value
}

provider "azurerm" {
  features {}
}

provider "azurerm" {
  features {}
  alias           = ""
  subscription_id = local.az_subscription_dev_id
}

terraform {
  backend "azurerm" {
    resource_group_name  = ""
    storage_account_name = ""
    container_name       = ""
    key                  = "terraform.tfstate"
    subscription_id      = "" 
    tenant_id            = ""
  }
}

data "azurerm_key_vault" "dh_kv" {
  provider            = azurerm.cytiva-dcx-dev
  name                = local.az_kv_name
  resource_group_name = local.az_kv_rg
}

data "azurerm_key_vault_secret" "cf_api_token" {
  name         = local.apiToken
  key_vault_id = data.azurerm_key_vault.dh_kv.id
}
