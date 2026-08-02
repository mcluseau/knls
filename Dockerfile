# ------------------------------------------------------------------------
from rust:1.97.1-alpine3.24 as build

run apk add --no-cache build-base musl-dev openssl-dev openssl-libs-static git libmnl-dev libnftnl-dev

workdir /app
copy . .

run --mount=type=cache,id=rust-alpine-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=rust-alpine-target,sharing=private,target=/app/target \
  cargo install --locked --path . --root /dist

# ------------------------------------------------------------------------
from alpine:3.24.1
entrypoint ["knls"]
run apk add --no-cache nftables wireguard-tools conntrack-tools
copy --from=build /dist/bin/ /bin/

