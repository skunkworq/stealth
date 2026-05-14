package completions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// chatClient implements LLM for any OpenAI chat-completions compatible server.
// Shared by OpenAI, Mistral, Ollama, llama.cpp, vLLM, OpenRouter, and Gemini —
// they all speak the same protocol with different base URLs.
type chatClient struct {
	baseURL string
	apiKey  string
	model   string
}

type oaRequest struct {
	Model    string      `json:"model"`
	Messages []oaMessage `json:"messages"`
}

type oaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *chatClient) Complete(ctx context.Context, system, user string) (string, error) {
	var msgs []oaMessage
	if system != "" {
		msgs = append(msgs, oaMessage{Role: "system", Content: system})
	}
	msgs = append(msgs, oaMessage{Role: "user", Content: user})

	body, err := json.Marshal(oaRequest{Model: c.model, Messages: msgs})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s request: %w", c.model, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		var errResp oaResponse
		if json.Unmarshal(raw, &errResp) == nil && errResp.Error != nil {
			return "", fmt.Errorf("api error (status %d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var result oaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("api error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty choices in response")
	}
	return result.Choices[0].Message.Content, nil
}

func (c *chatClient) CompleteJSON(ctx context.Context, system, user string, v any) error {
	return completeJSON(ctx, c, system, user, v)
}

// Vision types for OpenAI multimodal requests.

type oaVisionMsg struct {
	Role    string         `json:"role"`
	Content []oaVisionBlk  `json:"content"`
}

type oaVisionBlk struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *oaImgURL `json:"image_url,omitempty"`
}

type oaImgURL struct {
	URL string `json:"url"`
}

type oaVisionReq struct {
	Model     string        `json:"model"`
	Messages  []oaVisionMsg `json:"messages"`
	MaxTokens int           `json:"max_tokens"`
}

func (c *chatClient) DescribeImage(ctx context.Context, imageURL string) (string, error) {
	b64, mime, err := fetchImageBase64(ctx, imageURL)
	if err != nil {
		return "", err
	}
	return c.doVisionRequest(ctx, "Describe what you see in this image in 1-2 sentences.", b64, mime, 256)
}

func (c *chatClient) AskAboutImage(ctx context.Context, imageURL, question string) (string, error) {
	b64, mime, err := fetchImageBase64(ctx, imageURL)
	if err != nil {
		return "", err
	}
	return c.doVisionRequest(ctx, question, b64, mime, 512)
}

func (c *chatClient) AskAboutImageData(ctx context.Context, imageData []byte, mimeType, question string) (string, error) {
	b64 := base64Encode(imageData)
	return c.doVisionRequest(ctx, question, b64, mimeType, 1024)
}

func (c *chatClient) doVisionRequest(ctx context.Context, prompt, b64, mime string, maxTokens int) (string, error) {
	dataURL := fmt.Sprintf("data:%s;base64,%s", mime, b64)
	reqBody := oaVisionReq{
		Model: c.model,
		Messages: []oaVisionMsg{
			{
				Role: "user",
				Content: []oaVisionBlk{
					{Type: "text", Text: prompt},
					{Type: "image_url", ImageURL: &oaImgURL{URL: dataURL}},
				},
			},
		},
		MaxTokens: maxTokens,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s vision request: %w", c.model, err)
	}
	defer resp.Body.Close()
	var result oaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode vision response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("api error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty choices in vision response")
	}
	return result.Choices[0].Message.Content, nil
}

// Constructors

// NewOpenAI returns an OpenAI client. Default model: gpt-4o.
func NewOpenAI(apiKey, model string) LLM {
	if model == "" {
		model = "gpt-4o"
	}
	return &chatClient{baseURL: "https://api.openai.com/v1", apiKey: apiKey, model: model}
}

// NewOpenAIWithBase returns an OpenAI-compatible client at a custom base URL.
// Useful for Azure OpenAI, proxies, or any OpenAI-compatible API.
func NewOpenAIWithBase(apiKey, model, baseURL string) LLM {
	return &chatClient{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, model: model}
}

// NewMistral returns a Mistral client (OpenAI-compatible).
// Default model: mistral-large-latest.
func NewMistral(apiKey, model string) LLM {
	if model == "" {
		model = "mistral-large-latest"
	}
	return &chatClient{baseURL: "https://api.mistral.ai/v1", apiKey: apiKey, model: model}
}

// NewOllama returns a client for a local Ollama server (OpenAI-compatible).
// Default host: http://localhost:11434. Override with OLLAMA_HOST env var.
// Default model: llama3.1.
func NewOllama(model string) LLM {
	if model == "" {
		model = "llama3.1"
	}
	host := os.Getenv("OLLAMA_HOST")
	if host == "" {
		host = "http://localhost:11434"
	}
	return &chatClient{baseURL: strings.TrimRight(host, "/") + "/v1", model: model}
}

// NewOllamaWithBase returns an Ollama client at a specific host, ignoring OLLAMA_HOST.
func NewOllamaWithBase(model, host string) LLM {
	return &chatClient{baseURL: strings.TrimRight(host, "/") + "/v1", model: model}
}

// NewOpenRouter returns an OpenRouter client (OpenAI-compatible).
// Default model: anthropic/claude-sonnet-4-5.
func NewOpenRouter(apiKey, model string) LLM {
	if model == "" {
		model = "anthropic/claude-sonnet-4-5"
	}
	return &chatClient{baseURL: "https://openrouter.ai/api/v1", apiKey: apiKey, model: model}
}

// NewLlamaCpp returns a client for a local llama.cpp server (llama-server).
// Default host: http://localhost:8080. Override with LLAMACPP_HOST env var.
func NewLlamaCpp(model string) LLM {
	host := os.Getenv("LLAMACPP_HOST")
	if host == "" {
		host = "http://localhost:8080"
	}
	return &chatClient{baseURL: strings.TrimRight(host, "/") + "/v1", model: model}
}

// NewVLLM returns a client for a local vLLM server (OpenAI-compatible).
// Default host: http://localhost:8000. Override with VLLM_HOST env var.
func NewVLLM(model string) LLM {
	host := os.Getenv("VLLM_HOST")
	if host == "" {
		host = "http://localhost:8000"
	}
	return &chatClient{baseURL: strings.TrimRight(host, "/") + "/v1", model: model}
}

// NewGemini returns a Gemini client using Google's OpenAI-compatible endpoint.
// Default model: gemini-2.5-flash. Override base URL via GEMINI_BASE_URL.
func NewGemini(apiKey, model string) LLM {
	if model == "" {
		model = "gemini-2.5-flash"
	}
	base := os.Getenv("GEMINI_BASE_URL")
	if base == "" {
		base = "https://generativelanguage.googleapis.com/v1beta/openai"
	}
	return &chatClient{baseURL: strings.TrimRight(base, "/"), apiKey: apiKey, model: model}
}
