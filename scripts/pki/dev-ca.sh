#!/usr/bin/env sh
set -eu

OUT_DIR="${1:-certs}"
mkdir -p "$OUT_DIR"

openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout "$OUT_DIR/dev-ca.key" \
  -out "$OUT_DIR/dev-ca.crt" \
  -subj "/CN=Private Inference Gateway Dev CA"

openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/server.key" \
  -out "$OUT_DIR/server.csr" \
  -subj "/CN=localhost"

openssl x509 -req -in "$OUT_DIR/server.csr" \
  -CA "$OUT_DIR/dev-ca.crt" \
  -CAkey "$OUT_DIR/dev-ca.key" \
  -CAcreateserial \
  -out "$OUT_DIR/server.crt" \
  -days 365 \
  -sha256

openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT_DIR/client.key" \
  -out "$OUT_DIR/client.csr" \
  -subj "/CN=private-inference-gateway-client"

openssl x509 -req -in "$OUT_DIR/client.csr" \
  -CA "$OUT_DIR/dev-ca.crt" \
  -CAkey "$OUT_DIR/dev-ca.key" \
  -CAcreateserial \
  -out "$OUT_DIR/client.crt" \
  -days 365 \
  -sha256

rm -f "$OUT_DIR/server.csr" "$OUT_DIR/client.csr" "$OUT_DIR/dev-ca.srl"
chmod 600 "$OUT_DIR"/*.key

echo "wrote development certificates to $OUT_DIR"
