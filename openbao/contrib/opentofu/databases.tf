resource "vault_mount" "db" {
  path        = "database"
  type        = "database"
  description = "Database secrets engine"
}

# ----------------------------------------------------------------------------
# Permesi DB Connection & Role
# ----------------------------------------------------------------------------
resource "vault_database_secret_backend_connection" "permesi" {
  backend       = vault_mount.db.path
  name          = "permesi"
  allowed_roles = ["permesi"]

  # OpenBao has no scheduled root rotation (a Vault Enterprise feature it ignores);
  # these statements run on `bao write -f database/rotate-root/permesi`.
  root_rotation_statements = [
    "ALTER ROLE \"${var.permesi_database_username}\" WITH PASSWORD '{{password}}';",
  ]

  postgresql {
    connection_url          = "postgresql://{{username}}:{{password}}@${var.database_host}:${var.database_port}/permesi?sslmode=${var.database_sslmode}"
    username                = var.permesi_database_username
    password_wo             = var.permesi_database_password
    password_wo_version     = var.permesi_database_password_version
    max_connection_lifetime = 120
  }
}

resource "vault_database_secret_backend_role" "permesi" {
  backend     = vault_mount.db.path
  name        = "permesi"
  db_name     = vault_database_secret_backend_connection.permesi.name
  default_ttl = 3600
  max_ttl     = 14400

  # SECURITY NOTE: Dynamic users should not be able to create schemas/tables.
  # Local dev enforces this by revoking `CREATE` on the `public` schema (see `db/sql/00_init.sql`).
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT permesi_runtime TO \"{{name}}\";",
  ]

  renew_statements = [
    "ALTER ROLE \"{{name}}\" WITH VALID UNTIL '{{expiration}}';",
  ]

  revocation_statements = [
    "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';",
    "REVOKE permesi_runtime FROM \"{{name}}\";",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]
}

# ----------------------------------------------------------------------------
# Genesis DB Connection & Role
# ----------------------------------------------------------------------------
resource "vault_database_secret_backend_connection" "genesis" {
  backend       = vault_mount.db.path
  name          = "genesis"
  allowed_roles = ["genesis"]

  # Rotated on demand with `bao write -f database/rotate-root/genesis`.
  root_rotation_statements = [
    "ALTER ROLE \"${var.genesis_database_username}\" WITH PASSWORD '{{password}}';",
  ]

  postgresql {
    connection_url          = "postgresql://{{username}}:{{password}}@${var.database_host}:${var.database_port}/postgres?sslmode=${var.database_sslmode}"
    username                = var.genesis_database_username
    password_wo             = var.genesis_database_password
    password_wo_version     = var.genesis_database_password_version
    max_connection_lifetime = 120
  }
}

resource "vault_database_secret_backend_role" "genesis" {
  backend     = vault_mount.db.path
  name        = "genesis"
  db_name     = vault_database_secret_backend_connection.genesis.name
  default_ttl = 3600
  max_ttl     = 14400

  # SECURITY NOTE: Dynamic users should not be able to create schemas/tables.
  # Local dev enforces this by revoking `CREATE` on the `public` schema (see `db/sql/00_init.sql`).
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN CONNECTION LIMIT ${var.genesis_login_connection_limit} PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT genesis_runtime TO \"{{name}}\";",
  ]

  renew_statements = [
    "ALTER ROLE \"{{name}}\" WITH VALID UNTIL '{{expiration}}';",
  ]

  revocation_statements = [
    "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';",
    "REVOKE genesis_runtime FROM \"{{name}}\";",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]
}
