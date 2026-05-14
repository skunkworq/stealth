package completions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// anthropicClient calls the Anthropic messages API.
// Wire format differs from OpenAI: separate system field, content-block array
// in the response, and x-api-key / anthropic-version headers.
type anthropicClient struct {
	apiKey string
	model  string
}

type anthropicReq struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []anthMsg `json:"messages"`
}

type anthMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *anthropicClient) Complete(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(anthropicReq{
		Model:     c.model,
		MaxTokens: 4096,
		System:    system,
		Messages:  []anthMsg{{Role: "user", Content: user}},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()
	var result anthropicResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("api error: %s", result.Error.Message)
	}
	for _, block := range result.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("no text block in response")
}

func (c *anthropicClient) CompleteJSON(ctx context.Context, system, user string, v any) error {
	return completeJSON(ctx, c, system, user, v)
}

// Anthropic multimodal types — content is an array of blocks, not a string.

type anthVisionMsg struct {
	Role    string        `json:"role"`
	Content []anthVisionBlk `json:"content"`
}

type anthVisionBlk struct {
	Type   string         `json:"type"`
	Text   string         `json:"text,omitempty"`
	Source *anthImgSource `json:"source,omitempty"`
}

type anthImgSource struct {
	Type      string `json:"type"`       // "base64"
	MediaType string `json:"media_type"` // e.g. "image/jpeg"
	Data      string `json:"data"`       // raw base64, no data URI prefix
}

type anthVisionReq struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system,omitempty"`
	Messages  []anthVisionMsg `json:"messages"`
}

func (c *anthropicClient) DescribeImage(ctx context.Context, imageURL string) (string, error) {
	b64, mime, err := fetchImageBase64(ctx, imageURL)
	if err != nil {
		return "", err
	}
	return c.doVisionRequest(ctx,
		"You describe images concisely.",
		"Describe what you see in this image in 1-2 sentences.",
		b64, mime, 256)
}

func (c *anthropicClient) AskAboutImage(ctx context.Context, imageURL, question string) (string, error) {
	b64, mime, err := fetchImageBase64(ctx, imageURL)
	if err != nil {
		return "", err
	}
	return c.doVisionRequest(ctx, "", question, b64, mime, 512)
}

func (c *anthropicClient) AskAboutImageData(ctx context.Context, imageData []byte, mimeType, question string) (string, error) {
	b64 := base64Encode(imageData)
	return c.doVisionRequest(ctx, "", question, b64, mimeType, 1024)
}

func (c *anthropicClient) doVisionRequest(ctx context.Context, system, prompt, b64, mime string, maxTokens int) (string, error) {
	body, err := json.Marshal(anthVisionReq{
		Model:     c.model,
		MaxTokens: maxTokens,
		System:    system,
		Messages: []anthVisionMsg{
			{
				Role: "user",
				Content: []anthVisionBlk{
					{Type: "image", Source: &anthImgSource{Type: "base64", MediaType: mime, Data: b64}},
					{Type: "text", Text: prompt},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic vision request: %w", err)
	}
	defer resp.Body.Close()
	var result anthropicResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode vision response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("api error: %s", result.Error.Message)
	}
	for _, block := range result.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("no text block in vision response")
}

// NewAnthropic returns an Anthropic client. Default model: claude-opus-4-20250514.
func NewAnthropic(apiKey, model string) LLM {
	if model == "" {
		model = "claude-opus-4-20250514"
	}
	return &anthropicClient{apiKey: apiKey, model: model}
}
