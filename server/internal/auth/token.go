// Package auth: token storage (hash-only), nonce replay protection,
// per-IP rate limiting and lockout.
package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Store holds per-device token hashes. Raw tokens are never stored.
type Store struct {
	mu     sync.RWMutex
	tokens map[string][]byte // device -> SHA256(token) (raw 32B)

	nonces map[string]time.Time // nonce b64 -> expiry (single-use)

	muL     sync.Mutex
	attempt map[string]*attempt // ip -> state
}

type attempt struct {
	fails   int
	lockUnt time.Time
	window  []time.Time // handshake starts in the last minute
}

const (
	maxHandshakesPerMin = 10
	maxFailsBeforeLock  = 5
)

// New creates an empty store.
func New() *Store {
	return &Store{
		tokens:  make(map[string][]byte),
		nonces:  make(map[string]time.Time),
		attempt: make(map[string]*attempt),
	}
}

// LoadFile reads tokens.json: {"devices": {"phone-1": "<base64url or hex sha256>"}}.
func (s *Store) LoadFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		Devices map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("tokens file: %w", err)
	}
	if len(doc.Devices) == 0 {
		return fmt.Errorf("tokens file %s has no devices", path)
	}
	m := make(map[string][]byte, len(doc.Devices))
	for name, tok := range doc.Devices {
		h, err := DecodeHash(tok)
		if err != nil {
			return fmt.Errorf("device %s: %w", name, err)
		}
		m[name] = h
	}
	s.mu.Lock()
	s.tokens = m
	s.mu.Unlock()
	return nil
}

// DecodeHash accepts base64url or hex, returns raw 32 bytes.
func DecodeHash(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == sha256.Size {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == sha256.Size {
		return b, nil
	}
	return nil, fmt.Errorf("expected 32-byte sha256 (base64url/hex)")
}

// HashToken returns SHA256(token) raw bytes.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Devices lists known device names.
func (s *Store) Devices() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.tokens))
	for k := range s.tokens {
		out = append(out, k)
	}
	return out
}

// Verify returns the device name if any stored hash authenticates.
func (s *Store) Verify(nonceB64, sessionID, providedHMAC string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for name, hash := range s.tokens {
		if verifyHash(hash, nonceB64, sessionID, providedHMAC) {
			return name, true
		}
	}
	return "", false
}

// PutNonce registers a fresh nonce (single use).
func (s *Store) PutNonce(nonce string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, exp := range s.nonces {
		if exp.Before(now) {
			delete(s.nonces, k)
		}
	}
	s.nonces[nonce] = now.Add(ttl)
}

// TakeNonce consumes a nonce; replay returns false.
func (s *Store) TakeNonce(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.nonces[nonce]
	if !ok || exp.Before(time.Now()) {
		return false
	}
	delete(s.nonces, nonce)
	return true
}

// AllowHandshake rate-limits connection attempts per IP.
func (s *Store) AllowHandshake(ip string) bool {
	s.muL.Lock()
	defer s.muL.Unlock()
	a := s.attempt[ip]
	if a == nil {
		a = &attempt{}
		s.attempt[ip] = a
	}
	now := time.Now()
	if now.Before(a.lockUnt) {
		return false
	}
	kept := a.window[:0]
	for _, t := range a.window {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	a.window = kept
	if len(a.window) >= maxHandshakesPerMin {
		return false
	}
	a.window = append(a.window, now)
	return true
}

// ReportFailure records a failed auth and locks the IP out if needed.
func (s *Store) ReportFailure(ip string) bool { // returns true if now locked
	s.muL.Lock()
	defer s.muL.Unlock()
	a := s.attempt[ip]
	if a == nil {
		a = &attempt{}
		s.attempt[ip] = a
	}
	a.fails++
	if a.fails >= maxFailsBeforeLock {
		shift := a.fails - maxFailsBeforeLock
		if shift > 5 {
			shift = 5
		}
		a.lockUnt = time.Now().Add((30 << shift) * time.Second) // 30s..10min
		return true
	}
	return false
}

// ResetFailures clears fail counter after success.
func (s *Store) ResetFailures(ip string) {
	s.muL.Lock()
	defer s.muL.Unlock()
	if a := s.attempt[ip]; a != nil {
		a.fails = 0
		a.lockUnt = time.Time{}
	}
}
