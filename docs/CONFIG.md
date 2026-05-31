# configuration

All values live in `config/default.yaml`. Environment variables override where marked.

## gateway

```yaml
gateway:
  addr: ":8443"               # listen address
  max_connections: 10000      # hard ceiling on concurrent ws conns
  idle_timeout: "5m"          # conn closed if no message for this long
  allowed_origins:
    - "https://example.com"   # origin header check during upgrade
```

## auth

```yaml
auth:
  jwt_secret_env: "FORTRESS_JWT_SECRET"   # env var holding the hmac key
  token_ttl: "1h"                         # max token age
  issuer: "fortress-ws"                   # expected "iss" claim
```

The JWT secret must be at least 32 bytes. The gateway reads it from the environment — don't put it in the yaml.

## rate limiter

```yaml
rate_limit:
  requests_per_minute: 60     # sliding window limit
  burst: 10                   # allowed burst above limit
```

Uses Redis. Missing Redis = rate limiter refuses all requests (fail closed).

## redis

```yaml
redis:
  addr: "localhost:6379"
  password_env: "REDIS_PASSWORD"
  db: 0
```

`password_env` names the env var holding the Redis AUTH password. Leave empty for unauthenticated connections.

## scanner

```yaml
scanner:
  grpc_addr: "localhost:50051"    # rust scanner gRPC endpoint
  timeout: "5s"                   # per-call deadline
```

If the scanner is unreachable, the gateway returns a 503 during WS upgrade.

## tls

```yaml
tls:
  cert_file: ""              # path to tls cert (empty = auto self-signed)
  key_file: ""               # path to tls key (empty = auto self-signed)
  enforce: true              # reject non-tls origins
```

Leave cert/key empty in dev — the gateway generates a self-signed cert on startup and logs the fingerprint.

## logging

```yaml
logging:
  level: "info"              # debug | info | warn | error
  format: "json"             # json | text
```

JSON format is intended for production (stdout → log shipper). Text format is easier on the eyes during dev.
