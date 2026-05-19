package completions

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// fetchImageBase64 downloads an image and returns its raw base64-encoded data
// and MIME type. The base64 string does not include a data URI prefix.
func fetchImageBase64(ctx context.Context, imageURL string) (b64 string, mimeType string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("image fetch: %w", err)
	}
	resp, err := llmHTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("image fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("image fetch: status %d for %s", resp.StatusCode, imageURL)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("image read: %w", err)
	}
	mimeType = resp.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "image/jpeg"
	}
	return base64.StdEncoding.EncodeToString(data), mimeType, nil
}
