package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/fortress-ws/fortress-ws/internal/conn"
)

// Handler groups HTTP handlers for the admin REST API.
type Handler struct {
	connMgr *conn.ConnectionManager
	rdb     *redis.Client
	logger  *zap.Logger
}

// NewHandler creates a new admin handler with the given dependencies.
func NewHandler(connMgr *conn.ConnectionManager, rdb *redis.Client, logger *zap.Logger) *Handler {
	return &Handler{
		connMgr: connMgr,
		rdb:     rdb,
		logger:  logger,
	}
}

// Health returns a simple health check handler.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Metrics returns the Prometheus metrics handler.
func (h *Handler) Metrics() http.Handler {
	return promhttp.Handler()
}

// Connections returns a JSON list of active connections.
func (h *Handler) Connections(w http.ResponseWriter, r *http.Request) {
	list := h.connMgr.List()
	type connInfo struct {
		ID         string `json:"id"`
		RemoteAddr string `json:"remote_addr"`
		LastSeen   string `json:"last_seen"`
	}
	result := make([]connInfo, 0, len(list))
	for _, mc := range list {
		result = append(result, connInfo{
			ID:         mc.ID,
			RemoteAddr: mc.RemoteAddrStr(),
			LastSeen:   mc.LastSeen.Format(time.RFC3339),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// BlacklistRequest is the JSON body for the blacklist endpoint.
type BlacklistRequest struct {
	Token string `json:"token"`
	TTL   string `json:"ttl"`
}

// Blacklist adds a JWT token to the Redis blacklist.
func (h *Handler) Blacklist(w http.ResponseWriter, r *http.Request) {
	var req BlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, `{"error":"token is required"}`, http.StatusBadRequest)
		return
	}
	ttl := 24 * time.Hour
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err == nil {
			ttl = parsed
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	key := "fw:blacklist:" + req.Token
	if err := h.rdb.Set(ctx, key, "1", ttl).Err(); err != nil {
		h.logger.Error("failed to blacklist token", zap.Error(err))
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "blacklisted"})
}

// RegisterRoutes registers all admin routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.Health)
	mux.Handle("GET /metrics", h.Metrics())
	mux.HandleFunc("GET /api/v1/connections", h.Connections)
	mux.HandleFunc("POST /api/v1/blacklist", h.Blacklist)
}
