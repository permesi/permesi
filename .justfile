run:
    podman run --rm \
    --name permesi \
    -e POSTGRES_USER=permesi \
    -e POSTGRES_PASSWORD=permesi \
    -p 5432:5432 \
    -v $PWD/.postgres-volume:/var/lib/postgresql/data \
    postgres:latest &

stop:
    podman stop permesi
