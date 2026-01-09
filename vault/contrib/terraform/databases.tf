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

  rotation_period = 86400
  root_rotation_statements = [
    "ALTER ROLE \"${var.permesi_database_username}\" WITH PASSWORD '{{password}}';",
  ]

  postgresql {
    connection_url          = "postgresql://{{username}}:{{password}}@${var.database_host}:${var.database_port}/permesi?sslmode=${var.database_sslmode}"
    username                = var.permesi_database_username
    password                = var.permesi_database_password
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

  rotation_period = 86400
  root_rotation_statements = [
    "ALTER ROLE \"${var.genesis_database_username}\" WITH PASSWORD '{{password}}';",
  ]

  postgresql {
    connection_url          = "postgresql://{{username}}:{{password}}@${var.database_host}:${var.database_port}/genesis?sslmode=${var.database_sslmode}"
    username                = var.genesis_database_username
    password                = var.genesis_database_password
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
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
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
