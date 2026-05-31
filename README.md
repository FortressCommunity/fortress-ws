# fortress-ws

WebSocket gateway with inline threat detection. Go front-end, Rust back-end for the hot path.

## what it does

Accepts WebSocket connections, runs each frame through a Rust gRPC scanner before forwarding. Drops or flags payloads matching XSS, SQL injection, command injection patterns. Rate limits per IP and per token. Logs everything structured to stdout.

## project layout

```
cmd/
  fortress-gw/         # gateway binary - main entrypoint
  fortress-ctl/        # cli tool - connect, scan, bench
internal/
  auth/                # jwt + hmac handshake verification
  ratelimit/           # sliding window via redis
  tls/                 # origin enforcement, cert checks
  conn/                # connection tracking, max conns, idle timeout
  logger/              # structured json + otel traces
  admin/               # /health /metrics /connections /blacklist
pkg/proto/             # protobuf contract, shared by go + rust
rust/
  src/frame/           # rfc6455 frame parser
  src/scanner/         # regex-based payload scanner
config/                # default.yaml + env overrides
docker/                # compose + multi-stage dockerfiles
```

## quick start

```bash
make proto       # generate protobuf stubs
make build       # go bins + rust release
make test        # go test -race + cargo test
```

Single binary to run the gateway:

```bash
FORTRESS_JWT_SECRET="change-me-32-bytes-min" ./bin/fortress-gw
```

Or with docker:

```bash
make docker-up
```

## prerequisites

- Go 1.22+
- Rust toolchain (stable)
- protoc (for proto gen) — `apt install protobuf-compiler` on debian
- Redis (for rate limiter, token blacklist)
- make

## configuration

Everything in `config/default.yaml`. Environment variables take precedence where noted (see `FORTRESS_JWT_SECRET`, `REDIS_PASSWORD`).

Full reference: [docs/CONFIG.md](docs/CONFIG.md).

## why two languages

The Rust scanner runs as a sidecar gRPC server. Go handles connections, auth, routing — the high-touch orchestration. Rust parses raw frames and runs regex without GC pauses. Keeps tail latency predictable under load.

## license

MIT
