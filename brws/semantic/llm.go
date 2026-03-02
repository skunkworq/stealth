package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	OpenRouterChatURL  = "https://openrouter.ai/api/v1/chat/completions"
	DefaultLLMModel    = "openai/gpt-oss-120b"
	DefaultVisionModel = "google/gemini-2.5-flash"
)

type LLMClient struct {
	client        *http.Client
	apiKey        string
	compressModel string
	visionModel   string
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func NewLLMClient(apiKey string) *LLMClient {
	return &LLMClient{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		apiKey:        apiKey,
		compressModel: DefaultLLMModel,
		visionModel:   DefaultVisionModel,
	}
}

func (c *LLMClient) WithCompressModel(model string) *LLMClient {
	c.compressModel = model
	return c
}

func (c *LLMClient) WithVisionModel(model string) *LLMClient {
	c.visionModel = model
	return c
}

func (c *LLMClient) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	req := chatRequest{
		Model: c.compressModel,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.0,
		MaxTokens:   4096,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", OpenRouterChatURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", NewLLMError(fmt.Sprintf("request failed: %v", err))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", NewLLMError(fmt.Sprintf("OpenRouter returned %d: %s", resp.StatusCode, string(bodyBytes)))
	}

	var result chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", NewLLMError("empty response")
	}

	return result.Choices[0].Message.Content, nil
}

func (c *LLMClient) CompleteJSON(ctx context.Context, systemPrompt, userPrompt string, v interface{}) error {
	response, err := c.Complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return err
	}

	jsonStr := response
	if len(response) > 7 && response[:7] == "```json" {
		jsonStr = response[7:]
		if idx := strings.LastIndex(jsonStr, "```"); idx != -1 {
			jsonStr = jsonStr[:idx]
		}
	} else if len(response) > 3 && response[:3] == "```" {
		jsonStr = response[3:]
		if idx := strings.LastIndex(jsonStr, "```"); idx != -1 {
			jsonStr = jsonStr[:idx]
		}
	}
	jsonBytes := bytes.TrimSpace([]byte(jsonStr))

	if err := json.Unmarshal(jsonBytes, v); err != nil {
		return NewLLMError(fmt.Sprintf("failed to parse JSON: %v\nRaw: %s", err, response))
	}

	return nil
}
