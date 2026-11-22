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

# Permesi Postgres root user for OpenBao to connect with
variable "permesi_database_username" {
  type    = string
  default = "openbao_permesi"
}

# Permesi Postgres root password for OpenBao to connect with
variable "permesi_database_password" {
  type      = string
  sensitive = true
}

# Genesis Postgres root user for OpenBao to connect with
variable "genesis_database_username" {
  type    = string
  default = "openbao_genesis"
}

# Genesis Postgres root password for OpenBao to connect with
variable "genesis_database_password" {
  type      = string
  sensitive = true
}

# SSL mode for OpenBao's privileged DB connections. Verified TLS is the default so
# an omitted value cannot silently send credential-management SQL in the clear;
# local dev sets "disable" explicitly.
variable "database_sslmode" {
  type    = string
  default = "verify-full"

  validation {
    condition     = contains(["disable", "require", "verify-ca", "verify-full"], var.database_sslmode)
    error_message = "database_sslmode must be disable, require, verify-ca or verify-full."
  }
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
  default = "https://openbao.example.invalid/v1/pki-root/ca"
}

variable "pki_root_crl_distribution_points_url" {
  type    = string
  default = "https://openbao.example.invalid/v1/pki-root/crl"
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
  default = "https://openbao.example.invalid/v1/pki-int/ca"
}

variable "pki_int_crl_distribution_points_url" {
  type    = string
  default = "https://openbao.example.invalid/v1/pki-int/crl"
}

variable "genesis_login_connection_limit" {
  description = "Maximum simultaneous PostgreSQL connections per Genesis lease."
  type        = number
  default     = 10
  validation {
    condition     = var.genesis_login_connection_limit >= 1 && var.genesis_login_connection_limit == floor(var.genesis_login_connection_limit) && var.genesis_login_connection_limit <= 2147483647
    error_message = "Use a positive PostgreSQL connection limit."
  }
}

variable "genesis_quota_rate" {
  description = "Requests per second per source IP and reachable node for each edge path."
  type        = number
  default     = 30
  validation {
    condition     = var.genesis_quota_rate >= 1 && var.genesis_quota_rate == floor(var.genesis_quota_rate)
    error_message = "Rate must be a positive integer."
  }
}
