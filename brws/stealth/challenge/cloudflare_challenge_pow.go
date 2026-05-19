package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

// scaleDifficulty maps a detection score to PoW difficulty bits.
func (cc *CloudflareChallenger) scaleDifficulty(detectionScore float64) int {
	switch {
	case detectionScore < 0.2:
		return cc.powConfig.MinBits
	case detectionScore < 0.4:
		return 14
	case detectionScore < 0.6:
		return cc.powConfig.DefaultBits
	case detectionScore < 0.8:
		return 20
	default:
		// Scale between 22-24 for very high scores
		bits := 22 + int(math.Round((detectionScore-0.8)*10))
		if bits > cc.powConfig.MaxBits {
			bits = cc.powConfig.MaxBits
		}
		return bits
	}
}

// verifyPoWHash checks that SHA-256(prefix+nonce) has the required leading zero bits.
func (cc *CloudflareChallenger) verifyPoWHash(prefix, nonce string, requiredBits int) bool {
	data := prefix + nonce
	hash := sha256.Sum256([]byte(data))
	return hasLeadingZeroBits(hash[:], requiredBits)
}

// hasLeadingZeroBits checks if a hash has at least n leading zero bits.
func hasLeadingZeroBits(hash []byte, n int) bool {
	fullBytes := n / 8
	remainBits := n % 8

	for i := 0; i < fullBytes; i++ {
		if i >= len(hash) {
			return false
		}
		if hash[i] != 0 {
			return false
		}
	}

	if remainBits > 0 && fullBytes < len(hash) {
		mask := byte(0xFF << (8 - remainBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

// generatePoW creates a new PoW challenge with the given difficulty.
func (cc *CloudflareChallenger) generatePoW(difficulty int) *PoWChallenge {
	prefix := make([]byte, 32)
	_, _ = rand.Read(prefix)

	return &PoWChallenge{
		ChallengeID:   fmt.Sprintf("pow_%d", time.Now().UnixNano()),
		Prefix:        hex.EncodeToString(prefix),
		Difficulty:    difficulty,
		Algorithm:     "SHA-256",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		MaxIterations: 50_000_000,
	}
}
