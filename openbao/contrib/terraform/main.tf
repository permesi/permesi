terraform {
  required_version = ">= 1.7.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.6.0"
    }
  }
}
