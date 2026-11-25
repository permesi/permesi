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

# Permesi Postgres root password for OpenBao to connect with. Write-only: it
# reaches OpenBao but never the state or a saved plan.
variable "permesi_database_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

# Genesis Postgres root user for OpenBao to connect with
variable "genesis_database_username" {
  type    = string
  default = "openbao_genesis"
}

# Genesis Postgres root password for OpenBao to connect with. Write-only: it
# reaches OpenBao but never the state or a saved plan.
variable "genesis_database_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

# The passwords above only bootstrap a connection: rotate each root password with
# `bao write -f database/rotate-root/<service>` after the first apply, so only
# OpenBao knows it. A password is sent when its version changes: raise one after
# resetting that root password in PostgreSQL. The versions are separate because
# OpenBao verifies a connection whenever its password is sent, so a shared one
# would push the other service's stale password and fail. State from before
# write-only passwords has version 0; keep 0 there if the root password has been
# rotated since, for the same reason.
variable "permesi_database_password_version" {
  type    = number
  default = 1
  validation {
    condition     = var.permesi_database_password_version >= 0 && var.permesi_database_password_version == floor(var.permesi_database_password_version)
    error_message = "permesi_database_password_version must be a non-negative integer."
  }
}

variable "genesis_database_password_version" {
  type    = number
  default = 1
  validation {
    condition     = var.genesis_database_password_version >= 0 && var.genesis_database_password_version == floor(var.genesis_database_password_version)
    error_message = "genesis_database_password_version must be a non-negative integer."
  }
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
