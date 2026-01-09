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
