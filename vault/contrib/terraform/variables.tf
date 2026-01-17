# Database host (default: localhost)
variable "database_host" {
  type    = string
  default = "127.0.0.1"
}

# Database port (default: 5432)
variable "database_port" {
  type    = number
  default = 5432
}

# Permesi Postgres root user for Vault to connect with
variable "permesi_database_username" {
  type    = string
  default = "vault_permesi"
}

# Permesi Postgres root password for Vault to connect with
variable "permesi_database_password" {
  type      = string
  sensitive = true
}

# Genesis Postgres root user for Vault to connect with
variable "genesis_database_username" {
  type    = string
  default = "vault_genesis"
}

# Genesis Postgres root password for Vault to connect with
variable "genesis_database_password" {
  type      = string
  sensitive = true
}

# SSL mode for DB connections (disable for local dev)
variable "database_sslmode" {
  type    = string
  default = "disable"
}

# PKI: Root CA
variable "pki_root_common_name" {
  type    = string
  default = "permesi Root CA"
}

variable "pki_root_ttl" {
  type    = string
  default = "87600h" # 10 years
}

variable "pki_root_issuing_certificates_url" {
  type    = string
  default = "https://vault.example.invalid/v1/pki_root/ca"
}

variable "pki_root_crl_distribution_points_url" {
  type    = string
  default = "https://vault.example.invalid/v1/pki_root/crl"
}

# PKI: Intermediate CA
variable "pki_intermediate_common_name" {
  type    = string
  default = "permesi Intermediate CA"
}

variable "pki_intermediate_ttl" {
  type    = string
  default = "26280h" # 3 years
}

variable "pki_int_issuing_certificates_url" {
  type    = string
  default = "https://vault.example.invalid/v1/pki_int/ca"
}

variable "pki_int_crl_distribution_points_url" {
  type    = string
  default = "https://vault.example.invalid/v1/pki_int/crl"
}
