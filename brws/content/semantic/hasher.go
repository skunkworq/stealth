package semantic

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

func StructuralHash(tag string, classes, childrenHashes []string) string {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write([]byte("|"))

	sortedClasses := make([]string, len(classes))
	copy(sortedClasses, classes)
	sort.Strings(sortedClasses)
	for _, class := range sortedClasses {
		h.Write([]byte(class))
		h.Write([]byte(","))
	}
	h.Write([]byte("|"))

	for _, childHash := range childrenHashes {
		h.Write([]byte(childHash))
		h.Write([]byte(";"))
	}

	return hex.EncodeToString(h.Sum(nil))
}

func ContentHash(text string) string {
	h := sha256.New()
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

func SelectorToID(selector string) string {
	h := sha256.Sum256([]byte(selector))
	short := uint64(h[0]) | uint64(h[1])<<8 | uint64(h[2])<<16 | uint64(h[3])<<24
	short = short & 0xFFFFF
	return "n-" + base36(short)
}

func base36(n uint64) string {
	if n == 0 {
		return "0"
	}
	chars := "0123456789abcdefghijklmnopqrstuvwxyz"
	var result []byte
	for n > 0 {
		result = append(result, chars[n%36])
		n /= 36
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

func ExtractDomain(url string) string {
	parts := strings.SplitN(url, "://", 2)
	if len(parts) > 1 {
		url = parts[1]
	}
	parts = strings.Split(url, "/")
	return parts[0]
}

func EstimateTokens(text string) uint32 {
	tokens := uint32(len(text) / 4)
	if tokens < 1 {
		return 1
	}
	return tokens
}
