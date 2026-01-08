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

# Postgres username for Vault to connect with
variable "database_username" {
  type    = string
  default = "postgres"
}

# Postgres password for Vault to connect with
variable "database_password" {
  type      = string
  sensitive = true
}

# SSL mode for DB connections (disable for local dev)
variable "database_sslmode" {
  type    = string
  default = "disable"
}