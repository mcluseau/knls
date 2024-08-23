# ------------------------------------------------------------------------
from rust:1.82.0-alpine3.20 as build

run apk add --no-cache build-base musl-dev openssl-dev openssl-libs-static

workdir /app
copy . .

run --mount=type=cache,id=rust-alpine-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=rust-alpine-target,sharing=private,target=/app/target \
    cargo build --release \
 && mkdir -p /dist \
 && find target/release -maxdepth 1 -type f -executable -exec cp -v {} /dist/ +

# ------------------------------------------------------------------------
from alpine:3.20.3
entrypoint ["knls"]
run apk add --no-cache nftables wireguard-tools
copy --from=build /dist/ /bin/

