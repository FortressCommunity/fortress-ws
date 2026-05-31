package tls

import (
	"encoding/json"
	"net/http"
)

type errorResponse struct {
	Error string `json:"error"`
}

// EnforceTLS returns middleware that rejects non-TLS requests with 426 Upgrade Required.
func EnforceTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			proto := r.Header.Get("X-Forwarded-Proto")
			if proto != "https" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUpgradeRequired)
				json.NewEncoder(w).Encode(errorResponse{
					Error: "TLS is required",
				})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// AllowOrigins returns a CheckOrigin function that performs exact-match origin validation.
func AllowOrigins(origins []string) func(r *http.Request) bool {
	allowed := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		allowed[o] = struct{}{}
	}
	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		_, ok := allowed[origin]
		return ok
	}
}
