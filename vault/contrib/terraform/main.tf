terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.6.0"
    }
  }
}

resource "vault_audit" "file" {
  type = "file"

  options = {
    file_path = "/vault/logs/audit.log"
  }
}
