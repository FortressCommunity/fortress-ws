# development

## local setup (no docker)

```bash
# start redis
redis-server --port 6379 &

# generate proto stubs
make proto

# build everything
make build

# start the rust scanner (terminal 1)
cd rust && cargo run --release

# start the gateway (terminal 2)
FORTRESS_JWT_SECRET="dev-secret-key-32-bytes-long!!" \
  ./bin/fortress-gw

# use the cli
./bin/fortress-ctl connect ws://localhost:8443/ws
```

## running tests

```bash
make test
```

Go tests use `-race` by default. Rust tests run in-tree under `rust/`.

If you want to run just one side:

```bash
go test -race ./internal/auth/...
cd rust && cargo test scanner::payload::tests
```

## proto generation

```bash
make proto
```

The `scripts/gen-proto.sh` script wraps protoc calls for Go stubs. Rust stubs are generated at build time by `rust/build.rs` using tonic-build — no extra step needed.

Requirements: `protoc` on PATH (`apt install protobuf-compiler` on Debian, or grab a release from github). Go plugins: `protoc-gen-go` and `protoc-gen-go-grpc`.

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

## adding a new scanner pattern

Edit `rust/src/scanner/payload.rs`, add a new entry to the patterns vec:

```rust
(
    Regex::new(r"(?i)your-pattern-here").unwrap(),
    "threat_name".to_string(),
),
```

Rebuild scanner, restart. No gateway changes needed.

## CI

Two workflows in `.github/workflows/`:

- `ci.yml` — go vet + test + lint, rust build + test + clippy
- `security.yml` — gosec (Go) + cargo-audit (Rust dependencies)

Both run on push to main and on PRs.

## known quirks

- protoc must be on PATH before `cargo build` in rust/ — tonic-build calls it at compile time
- the gateway generates a self-signed TLS cert if none is configured; browsers will complain, use `-k` with curl or disable TLS check in your WS client
- Redis failure mode: rate limiter fails closed (denies all), the rest of the gateway continues without rate limiting
- the Rust scanner listens on 0.0.0.0:50051 by default; change with `SCANNER_GRPC_ADDR` env var
