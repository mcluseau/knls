# ------------------------------------------------------------------------
from rust:1.89.0-alpine3.22 as build

run apk add --no-cache build-base musl-dev openssl-dev openssl-libs-static git

workdir /app
copy . .

run --mount=type=cache,id=rust-alpine-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=rust-alpine-target,sharing=private,target=/app/target \
    cargo install --path . --root /dist

# ------------------------------------------------------------------------
from alpine:3.22.0
entrypoint ["knls"]
run apk add --no-cache nftables wireguard-tools
copy --from=build /dist/bin/ /bin/

