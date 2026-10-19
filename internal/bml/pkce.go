package bml

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// pkce holds RFC 7636 values plus the OAuth state and nonce for one attempt.
type pkce struct {
	verifier  string
	challenge string
	state     string
	nonce     string
}

// newPKCE generates a 64 hex-char verifier, its S256 challenge
// (base64url, no padding), and 32 hex-char state and nonce values.
func newPKCE() pkce {
	verifier := randomHex(32)
	sum := sha256.Sum256([]byte(verifier))
	return pkce{
		verifier:  verifier,
		challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		state:     randomHex(16),
		nonce:     randomHex(16),
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	// crypto/rand.Read never returns an error on supported platforms.
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
