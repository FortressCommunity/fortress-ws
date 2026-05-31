package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignHMAC computes a Hex-encoded HMAC-SHA256 of the message using the provided secret.
func SignHMAC(message []byte, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC checks whether the provided signature matches a computed HMAC-SHA256 of the message.
func VerifyHMAC(message []byte, secret []byte, signature string) bool {
	expected := SignHMAC(message, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}
