FROM hashicorp/vault:latest

ENV VAULT_ADDR=http://127.0.0.1:8200 \
    VAULT_DEV_ROOT_TOKEN_ID=dev-root \
    VAULT_APPROLE_MOUNT=approle \
    VAULT_TRANSIT_MOUNT=transit/permesi \
    VAULT_TRANSIT_KEY=users \
    VAULT_DATABASE_MOUNT=database \
    VAULT_POSTGRES_HOST=host.containers.internal \
    VAULT_POSTGRES_PORT=5432 \
    VAULT_POSTGRES_USERNAME=postgres \
    VAULT_POSTGRES_PASSWORD=postgres \
    VAULT_POSTGRES_DATABASE_GENESIS=genesis \
    VAULT_POSTGRES_DATABASE_PERMESI=permesi \
    VAULT_POSTGRES_SSLMODE=disable \
    VAULT_POSTGRES_REASSIGN_OWNER=postgres

COPY vault/bootstrap.sh /usr/local/bin/bootstrap-vault
RUN chmod +x /usr/local/bin/bootstrap-vault

EXPOSE 8200

ENTRYPOINT ["/usr/local/bin/bootstrap-vault"]
