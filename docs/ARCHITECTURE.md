# architecture

## overview

Two-process split. Go gateway owns the public surface (WS + REST). Rust scanner handles the compute-intensive work. Communication over gRPC on localhost:50051.

```
client <--wss--> [fortress-gw :8443] <--grpc--> [scanner :50051]
                        |
                   [redis :6379]
```

## request flow

1. WS client connects to `wss://host:8443/ws`
2. Handshake path: JWT from query param or `Sec-WebSocket-Protocol` header → HMAC-SHA256 verification
3. On handshake ok, conn mgr registers the peer (bounded at `max_connections`)
4. Rate limiter checks per-IP sliding window in Redis
5. Frame arrives: opcode, masking, payload extracted
6. Payload sent to Rust scanner via gRPC `ScanFrame` RPC
7. Scanner returns `{is_threat, threat_type, confidence}`
8. If threat flagged → conn closed with policy violation close code, logged
9. If clean → frame forwarded upstream, logged

## components

### auth (Go)

JWT extracted from `Sec-WebSocket-Protocol` header during upgrade. Token claims: `sub` (client id), `iat`, `exp`. HMAC-SHA256 using secret from env. Tokens issued externally (fortress-ctl can do it, but the gateway only verifies).

### ratelimit (Go + Redis)

Sliding window counter. Key format:

```
ratelimit:{peer_ip}:{window_start}
```

Two windows tracked: per-IP (60 req/min default) and per-token (optional, same window). Burst allowance spills into next window.

### conn manager (Go)

Tracks active connections in a sync.Map keyed by a UUID. Each conn has: `peer_ip`, `connected_at`, `last_activity`, `token`. Admin API exposes `/connections` for inspection. Idle timeout is configurable (default 5m). On shutdown, conn mgr initiates graceful drain.

### frame parser (Rust)

RFC 6455 parser. Unpacks:

- opcode (1=text, 2=binary, 8=close, 9=ping, 10=pong)
- mask bit + masking key
- payload length (7/16/63 bit encoding)
- payload bytes

Minimal allocation — works on slices where possible. Returns a struct or error.

### payload scanner (Rust) {#payload-scanner}

Three regex categories compiled at init:

| category | pattern | hits |
|----------|---------|------|
| xss | `<script`, `javascript:`, `on\w+=` | event handlers, script tags, uri schemes |
| sql_injection | `union select`, `drop table`, `insert into` | basic SQLi |
| command_injection | `; cmd`, `\| cmd`, backtick + shell cmd | RCE attempts |

Scans raw bytes as lossy UTF-8. Returns `{is_threat, threat_type, confidence}`. Confidence is binary for now (1.0 or 0.0) — room for scoring later.

### logger (Go)

Wraps `slog` with JSON handler. Opentelemetry traces injected via `otelhttp` middleware on the admin routes. Trace ID propagates to the Rust scanner via gRPC metadata for correlation.

### admin API (Go)

| route | method | what |
|-------|--------|------|
| `/health` | GET | liveness probe |
| `/metrics` | GET | prometheus-style counters |
| `/connections` | GET | active conns, per-peer breakdown |
| `/blacklist` | POST/DELETE | add/remove token from redis blocklist |

## why this split

Rust sidecar keeps GC out of the hot path. Frame parsing and regex scanning are allocation-heavy in Go — offloading them keeps gateway latency flat. gRPC adds ~1ms per call which is acceptable for WS frame latency budgets.

The alternative (FFI/cgo) would couple the runtimes and complicate builds. gRPC gives us a clean interface boundary, independent deployability, and the same protobuf contract for any future scanner implementations.
