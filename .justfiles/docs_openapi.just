# ----------------------
# ----------------------
# Documentation (Redoc)
# ----------------------

docs:
    mkdir -p docs/redoc
    cp apps/web/public/logo.svg docs/redoc/logo.svg
    cp docs/openapi/*.json docs/redoc/
    @echo "Redoc generated at docs/redoc/index.html"

docs-clean:
    rm -rf docs/redoc

# ----------------------
# OpenAPI spec generation
# ----------------------

openapi: openapi-permesi openapi-genesis

openapi-permesi:
  mkdir -p docs/openapi
  cargo run -p permesi --bin permesi-openapi > docs/openapi/permesi.json

openapi-genesis:
  mkdir -p docs/openapi
  cargo run -p genesis --bin genesis-openapi > docs/openapi/genesis.json
