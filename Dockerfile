# ------------------------------------------------------------------------
from rust:1.99.1-alpine3.24 as build

run apk add --no-cache build-base musl-dev openssl-dev openssl-libs-static git

workdir /app
copy . .

run --mount=type=cache,id=rust-alpine-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=rust-alpine-target,sharing=private,target=/app/target \
  cargo install --locked --path . --root /dist

# ------------------------------------------------------------------------
from alpine:3.24.2 as assets
run apk add --no-cache zstd

run wget https://downloads.pingoo.io/geoip.mmdb.zst
copy --from=build /dist/bin/index-geoip .
run ./index-geoip

workdir /assets
run unzstd -o country_ips.db /country_ips.db.zst

# ------------------------------------------------------------------------
from alpine:3.24.2
entrypoint ["knls"]
run apk add --no-cache nftables wireguard-tools
copy --from=assets /assets/ /assets/
copy --from=build /dist/bin/ /bin/

