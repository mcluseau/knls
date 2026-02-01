# ------------------------------------------------------------------------
from rust:1.93.0-alpine3.23 as build

run apk add --no-cache build-base musl-dev openssl-dev openssl-libs-static git

workdir /app
copy . .

run --mount=type=cache,id=rust-alpine-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=rust-alpine-target,sharing=private,target=/app/target \
  cargo build -r && install -D target/release/knls /dist/bin/knls
#  cargo install --path . --root /dist

# ------------------------------------------------------------------------
from alpine:3.23.3
entrypoint ["knls"]
run apk add --no-cache nftables wireguard-tools
copy --from=build /dist/bin/ /bin/

