package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndParseToken(t *testing.T) {
	secret := []byte("super-secret-key-at-least-32-bytes-long!!")
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "fortress-ws",
		},
		Role:      "admin",
		SessionID: "sess-123",
	}
	ttl := 1 * time.Hour

	tokenStr, err := GenerateToken(claims, secret, ttl)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	if tokenStr == "" {
		t.Fatal("GenerateToken() returned empty token")
	}

	parsed, err := ParseToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("ParseToken() error = %v", err)
	}
	if parsed.Role != "admin" {
		t.Errorf("ParseToken() role = %q, want %q", parsed.Role, "admin")
	}
	if parsed.SessionID != "sess-123" {
		t.Errorf("ParseToken() session_id = %q, want %q", parsed.SessionID, "sess-123")
	}
}

func TestParseTokenExpired(t *testing.T) {
	secret := []byte("super-secret-key-at-least-32-bytes-long!!")
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "fortress-ws",
		},
		Role:      "user",
		SessionID: "sess-expired",
	}

	tokenStr, err := GenerateToken(claims, secret, -1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = ParseToken(tokenStr, secret)
	if err != ErrTokenExpired {
		t.Errorf("ParseToken() error = %v, want %v", err, ErrTokenExpired)
	}
}

func TestParseTokenInvalidSecret(t *testing.T) {
	secret := []byte("super-secret-key-at-least-32-bytes-long!!")
	wrongSecret := []byte("wrong-secret-key-that-is-also-32-bytes-amirite?")
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "fortress-ws",
		},
		Role: "user",
	}

	tokenStr, err := GenerateToken(claims, secret, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = ParseToken(tokenStr, wrongSecret)
	if err != ErrTokenInvalid {
		t.Errorf("ParseToken() error = %v, want %v", err, ErrTokenInvalid)
	}
}

func TestParseTokenMalformed(t *testing.T) {
	secret := []byte("super-secret-key-at-least-32-bytes-long!!")
	_, err := ParseToken("not-a-valid-token", secret)
	if err != ErrTokenInvalid {
		t.Errorf("ParseToken() error = %v, want %v", err, ErrTokenInvalid)
	}
}
