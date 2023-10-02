#!/bin/bash

UPSTREAM_HOST="$1"
REGISTRY_CACHE_ENDPOINT="$2"
UPSTREAM_URL="$3"

# TODO: can we make it single script for all caches?

# TODO: introduce flags

CONFIG_PATH="/etc/containerd/certs.d"

# TODO: Add max tries

HTTP_CODE=$(curl --silent --show-error --connect-timeout 5 --write-out "%{http_code}" $REGISTRY_CACHE_ENDPOINT)
while [[ $HTTP_CODE != 200 ]]; do
  echo "Request to $REGISTRY_CACHE_ENDPOINT failed. Will retry in 10 seconds..."
  sleep 10

  HTTP_CODE=$(curl --silent --show-error --connect-timeout 5 --write-out "%{http_code}" $REGISTRY_CACHE_ENDPOINT)
done

echo "Request to $REGISTRY_CACHE_ENDPOINT succeeded. Will create hosts.toml file..."

mkdir -p "$CONFIG_PATH/$UPSTREAM_HOST"
cat <<EOF > "$CONFIG_PATH/$UPSTREAM_HOST/hosts.toml"
server = "$UPSTREAM_URL"

[host."$REGISTRY_CACHE_ENDPOINT"]
  capabilities = ["pull", "resolve"]
EOF

echo "Created hosts.toml file for upstream $UPSTREAM_HOST."
