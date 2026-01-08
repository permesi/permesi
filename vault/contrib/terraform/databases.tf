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

  postgresql {
    connection_url          = "postgresql://{{username}}:{{password}}@${var.database_host}:${var.database_port}/permesi?sslmode=${var.database_sslmode}"
    username                = var.database_username
    password                = var.database_password
    max_connection_lifetime = 120
  }
}

resource "vault_database_secret_backend_role" "permesi" {
  backend     = vault_mount.db.path
  name        = "permesi"
  db_name     = vault_database_secret_backend_connection.permesi.name
  default_ttl = 3600
  max_ttl     = 14400

  # SECURITY NOTE: "GRANT ALL" allows the app to perform migrations (DDL).
  # In a strict least-privilege production environment, consider splitting this
  # into a migration role (DDL) and a runtime role (SELECT, INSERT, UPDATE, DELETE only).
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT ALL PRIVILEGES ON DATABASE permesi TO \"{{name}}\";",
    "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
    "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";",
  ]

  revocation_statements = [
    "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';",
    "REVOKE ALL PRIVILEGES ON DATABASE permesi FROM \"{{name}}\";",
    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";",
    "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{{name}}\";",
    "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM \"{{name}}\";",
    "REASSIGN OWNED BY \"{{name}}\" TO postgres;",
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

  postgresql {
    connection_url          = "postgresql://{{username}}:{{password}}@${var.database_host}:${var.database_port}/genesis?sslmode=${var.database_sslmode}"
    username                = var.database_username
    password                = var.database_password
    max_connection_lifetime = 120
  }
}

resource "vault_database_secret_backend_role" "genesis" {
  backend     = vault_mount.db.path
  name        = "genesis"
  db_name     = vault_database_secret_backend_connection.genesis.name
  default_ttl = 3600
  max_ttl     = 14400

  # SECURITY NOTE: "GRANT ALL" allows the app to perform migrations (DDL).
  # In a strict least-privilege production environment, consider splitting this
  # into a migration role (DDL) and a runtime role (SELECT, INSERT, UPDATE, DELETE only).
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT ALL PRIVILEGES ON DATABASE genesis TO \"{{name}}\";",
    "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
    "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";",
  ]

  revocation_statements = [
    "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';",
    "REVOKE ALL PRIVILEGES ON DATABASE genesis FROM \"{{name}}\";",
    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";",
    "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{{name}}\";",
    "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM \"{{name}}\";",
    "REASSIGN OWNED BY \"{{name}}\" TO postgres;",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]
}