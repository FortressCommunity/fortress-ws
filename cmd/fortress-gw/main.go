package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/fortress-ws/fortress-ws/internal/admin"
	"github.com/fortress-ws/fortress-ws/internal/auth"
	"github.com/fortress-ws/fortress-ws/internal/conn"
	"github.com/fortress-ws/fortress-ws/internal/logger"
	"github.com/fortress-ws/fortress-ws/internal/ratelimit"
	"github.com/fortress-ws/fortress-ws/internal/tls"
	pb "github.com/fortress-ws/fortress-ws/pkg/proto/gen"
)

var (
	wsConnTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ws_connections_total",
		Help: "Total number of WebSocket connections established",
	})
	wsMsgTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ws_messages_total",
		Help: "Total number of WebSocket messages processed",
	})
	wsThreatsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ws_threats_detected_total",
		Help: "Total number of threats detected in WebSocket messages",
	})
)

type gatewayConfig struct {
	Addr            string
	MaxConns        int
	IdleTimeout     time.Duration
	AllowedOrigins  []string
	JWTSecret       string
	TokenTTL        time.Duration
	Issuer          string
	RateLimitRPM    int64
	RateLimitBurst  int
	RedisAddr       string
	RedisPassword   string
	RedisDB         int
	ScannerGRPCAddr string
	ScannerTimeout  time.Duration
	TLSCertFile     string
	TLSKeyFile      string
	TLSEnforce      bool
	LogLevel        string
}

func loadConfig() (*gatewayConfig, error) {
	v := viper.New()
	v.SetConfigFile("config/default.yaml")
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	v.AutomaticEnv()
	v.SetEnvPrefix("FORTRESS")

	cfg := &gatewayConfig{
		Addr:            v.GetString("gateway.addr"),
		MaxConns:        v.GetInt("gateway.max_connections"),
		IdleTimeout:     v.GetDuration("gateway.idle_timeout"),
		AllowedOrigins:  v.GetStringSlice("gateway.allowed_origins"),
		JWTSecret:       os.Getenv(v.GetString("auth.jwt_secret_env")),
		TokenTTL:        v.GetDuration("auth.token_ttl"),
		Issuer:          v.GetString("auth.issuer"),
		RateLimitRPM:    v.GetInt64("rate_limit.requests_per_minute"),
		RateLimitBurst:  v.GetInt("rate_limit.burst"),
		RedisAddr:       v.GetString("redis.addr"),
		RedisPassword:   os.Getenv(v.GetString("redis.password_env")),
		RedisDB:         v.GetInt("redis.db"),
		ScannerGRPCAddr: v.GetString("scanner.grpc_addr"),
		ScannerTimeout:  v.GetDuration("scanner.timeout"),
		TLSCertFile:     v.GetString("tls.cert_file"),
		TLSKeyFile:      v.GetString("tls.key_file"),
		TLSEnforce:      v.GetBool("tls.enforce"),
		LogLevel:        v.GetString("logging.level"),
	}

	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT secret (env %s) is required", v.GetString("auth.jwt_secret_env"))
	}
	if len(cfg.JWTSecret) < 32 {
		return nil, fmt.Errorf("JWT secret must be at least 32 bytes")
	}

	return cfg, nil
}

func connectRedis(cfg *gatewayConfig) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return rdb, nil
}

func connectScanner(ctx context.Context, addr string, timeout time.Duration) (pb.ScannerServiceClient, *grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("scanner gRPC dial: %w", err)
	}
	client := pb.NewScannerServiceClient(conn)
	return client, conn, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	zapLogger, err := logger.NewZapLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}
	defer zapLogger.Sync()

	zapLogger.Info("starting fortress-gw", zap.String("addr", cfg.Addr))

	rdb, err := connectRedis(cfg)
	if err != nil {
		zapLogger.Fatal("redis connection failed", zap.Error(err))
	}
	defer rdb.Close()

	var scannerClient pb.ScannerServiceClient
	var scannerConn *grpc.ClientConn
	for i := 0; i < 3; i++ {
		zapLogger.Info("connecting to scanner", zap.String("addr", cfg.ScannerGRPCAddr), zap.Int("attempt", i+1))
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ScannerTimeout)
		scannerClient, scannerConn, err = connectScanner(ctx, cfg.ScannerGRPCAddr, cfg.ScannerTimeout)
		cancel()
		if err == nil {
			break
		}
		zapLogger.Warn("scanner connection failed, retrying", zap.Error(err), zap.Int("attempt", i+1))
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		zapLogger.Fatal("failed to connect to scanner after retries", zap.Error(err))
	}
	defer scannerConn.Close()
	zapLogger.Info("connected to scanner gRPC")

	connMgr := conn.NewConnectionManager(cfg.MaxConns, cfg.IdleTimeout)
	rateLimiter := ratelimit.NewSlidingWindowLimiter(rdb, cfg.RateLimitRPM, time.Minute)

	adminHandler := admin.NewHandler(connMgr, rdb, zapLogger)

	mux := http.NewServeMux()
	adminHandler.RegisterRoutes(mux)

	upgrader := &websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     tls.AllowOrigins(cfg.AllowedOrigins),
	}

	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		handleWS(w, r, upgrader, connMgr, scannerClient, rateLimiter, cfg, zapLogger)
	})

	var h http.Handler = mux

	if cfg.TLSEnforce {
		h = tls.EnforceTLS(h)
	}

	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		zapLogger.Info("listening", zap.String("addr", cfg.Addr))
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			if err := srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				zapLogger.Fatal("http server error", zap.Error(err))
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				zapLogger.Fatal("http server error", zap.Error(err))
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	zapLogger.Info("shutting down gateway")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := connMgr.Shutdown(shutdownCtx); err != nil {
		zapLogger.Error("connection manager shutdown error", zap.Error(err))
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		zapLogger.Error("http server shutdown error", zap.Error(err))
	}
}

func handleWS(
	w http.ResponseWriter,
	r *http.Request,
	upgrader *websocket.Upgrader,
	connMgr *conn.ConnectionManager,
	scannerClient pb.ScannerServiceClient,
	rateLimiter *ratelimit.SlidingWindowLimiter,
	cfg *gatewayConfig,
	logger *zap.Logger,
) {
	// Rate limit check
	allowed, err := rateLimiter.Allow(r.Context(), r.RemoteAddr)
	if err != nil {
		logger.Error("rate limit check error", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// JWT auth
	tokenStr := r.Header.Get("Authorization")
	if tokenStr != "" {
		if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
			tokenStr = tokenStr[7:]
		}
		_, err := auth.ParseToken(tokenStr, []byte(cfg.JWTSecret))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("websocket upgrade error", zap.Error(err))
		return
	}

	connID := fmt.Sprintf("ws-%d", time.Now().UnixNano())
	if err := connMgr.Register(connID, conn); err != nil {
		logger.Error("connection register error", zap.Error(err))
		conn.Close()
		return
	}
	wsConnTotal.Inc()

	defer func() {
		connMgr.Unregister(connID)
		conn.Close()
	}()

	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				logger.Warn("websocket read error", zap.Error(err))
			}
			return
		}
		wsMsgTotal.Inc()

		// Scan via gRPC
		ctx, cancel := context.WithTimeout(r.Context(), cfg.ScannerTimeout)
		scanReq := &pb.ScanRequest{
			Payload:  msg,
			Opcode:   uint32(msgType),
			IsMasked: false,
		}
		scanResp, err := scannerClient.ScanFrame(ctx, scanReq)
		cancel()
		if err != nil {
			logger.Error("scan rpc error", zap.Error(err))
		} else if scanResp.IsThreat {
			wsThreatsTotal.Inc()
			logger.Warn("threat detected",
				zap.String("threat_type", scanResp.ThreatType),
				zap.Float64("confidence", float64(scanResp.Confidence)),
				zap.String("conn_id", connID),
			)
		}
	}
}
