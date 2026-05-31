#!/usr/bin/env bash
set -euo pipefail

PROTO_DIR="$(cd "$(dirname "$0")/.." && pwd)/pkg/proto"
OUT_DIR="${PROTO_DIR}/gen"

mkdir -p "$OUT_DIR"

protoc --go_out="$OUT_DIR" --go-grpc_out="$OUT_DIR" \
       --go_opt=paths=source_relative \
       --go-grpc_opt=paths=source_relative \
       -I"$PROTO_DIR" \
       "$PROTO_DIR"/scanner.proto
