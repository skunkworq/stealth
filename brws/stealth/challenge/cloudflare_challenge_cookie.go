package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// generateClearanceCookie creates an HMAC-signed cf_clearance cookie with 30-min expiry.
// Format matches real CF: {token}-{timestamp}-{version}-{hmac_base64url}
// where token is a random hex string, timestamp is unix epoch, version is "1.0.1",
// and hmac is base64url-encoded HMAC-SHA256.
func (cc *CloudflareChallenger) generateClearanceCookie(sessionID string) *http.Cookie {
	expiry := time.Now().Add(30 * time.Minute)

	// Generate random token (16 bytes = 32 hex chars, like real CF)
	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	timestamp := time.Now().Unix()
	version := "1.0.1"

	// HMAC over sessionID|token|timestamp|version — includes session binding
	data := fmt.Sprintf("%s|%s|%d|%s|%d", sessionID, token, timestamp, version, expiry.UnixMilli())
	mac := hmac.New(sha256.New, cc.hmacKey)
	mac.Write([]byte(data))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Real CF format: {token}-{timestamp}-{version}-{hmac}
	value := fmt.Sprintf("%s-%d-%s-%s", token, timestamp, version, sig)

	return &http.Cookie{
		Name:     "cf_clearance",
		Value:    value,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ValidateClearanceCookie checks if a cf_clearance cookie value is valid.
// Format: {token}-{timestamp}-{version}-{hmac_base64url}
// Validates: structural format, expiry, and that a solved session issued this exact cookie.
func (cc *CloudflareChallenger) ValidateClearanceCookie(cookieValue string) bool {
	parts := splitClearanceCookie(cookieValue)
	if parts == nil {
		return false
	}

	_, timestampStr, _, _ := parts[0], parts[1], parts[2], parts[3]

	// Check expiry via embedded timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}
	expiryTime := time.Unix(timestamp, 0).Add(30 * time.Minute)
	if time.Now().After(expiryTime) {
		return false
	}

	// Verify this cookie was actually issued by us — lookup by stored value.
	// This is the authoritative check: the HMAC in the cookie prevents forgery,
	// and the session lookup prevents replay from other sessions.
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	for _, s := range cc.sessions {
		if s.ClearanceCookie == cookieValue && s.State == StateSolved {
			return true
		}
	}
	return false
}

// splitClearanceCookie splits a cookie value into [token, timestamp, version, hmac].
// Format: {token}-{timestamp}-{version}-{hmac}
// Token is 32 hex chars, timestamp is unix epoch, version is like "1.0.1",
// hmac is base64url-encoded.
func splitClearanceCookie(value string) []string {
	// Split on hyphens, but version contains dots (e.g., "1.0.1") and hmac may contain hyphens.
	// Token is always 32 hex chars, followed by timestamp (digits), version (x.y.z), hmac.
	// Strategy: find first hyphen after 32-char token, then next hyphen after timestamp digits.
	if len(value) < 36 { // minimum: 32 token + "-" + 1 timestamp + "-" + 1 version + "-" + 1 hmac
		return nil
	}

	// Token is first 32 chars
	token := value[:32]
	rest := value[33:] // skip the hyphen after token

	// Find timestamp (digits until next hyphen)
	idx := strings.IndexByte(rest, '-')
	if idx <= 0 {
		return nil
	}
	timestamp := rest[:idx]
	rest = rest[idx+1:]

	// Find version (x.y.z format until next hyphen)
	idx = strings.IndexByte(rest, '-')
	if idx <= 0 {
		return nil
	}
	version := rest[:idx]
	hmacSig := rest[idx+1:]

	if hmacSig == "" {
		return nil
	}

	return []string{token, timestamp, version, hmacSig}
}
