package semantic

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (c *LLMClient) DescribeImage(ctx context.Context, imageURL string) (string, error) {
	imageData, mimeType, err := fetchImageData(ctx, imageURL)
	if err != nil {
		return "", err
	}

	imageBase64 := base64.StdEncoding.EncodeToString(imageData)

	systemPrompt := "You describe images concisely. Provide a 1-2 sentence description of what's visible."
	userPrompt := "Describe what you see in this image."

	req := visionRequest{
		Model: c.visionModel,
		Messages: []visionMessage{
			{
				Role:    "system",
				Content: []visionContent{{Type: "text", Text: systemPrompt}},
			},
			{
				Role: "user",
				Content: []visionContent{
					{Type: "text", Text: userPrompt},
					{Type: "image_url", ImageURL: &imageURLData{URL: fmt.Sprintf("data:%s;base64,%s", mimeType, imageBase64)}},
				},
			},
		},
		MaxTokens: 256,
	}

	resp, err := c.doVisionRequest(ctx, req)
	if err != nil {
		return "", err
	}

	return resp, nil
}

func (c *LLMClient) AskAboutImage(ctx context.Context, imageURL, question string) (string, error) {
	imageData, mimeType, err := fetchImageData(ctx, imageURL)
	if err != nil {
		return "", err
	}

	imageBase64 := base64.StdEncoding.EncodeToString(imageData)

	req := visionRequest{
		Model: c.visionModel,
		Messages: []visionMessage{
			{
				Role: "user",
				Content: []visionContent{
					{Type: "text", Text: question},
					{Type: "image_url", ImageURL: &imageURLData{URL: fmt.Sprintf("data:%s;base64,%s", mimeType, imageBase64)}},
				},
			},
		},
		MaxTokens: 512,
	}

	resp, err := c.doVisionRequest(ctx, req)
	if err != nil {
		return "", err
	}

	return resp, nil
}

type visionRequest struct {
	Model     string          `json:"model"`
	Messages  []visionMessage `json:"messages"`
	MaxTokens int             `json:"max_tokens"`
}

type visionMessage struct {
	Role    string          `json:"role"`
	Content []visionContent `json:"content"`
}

type visionContent struct {
	Type     string        `json:"type"`
	Text     string        `json:"text,omitempty"`
	ImageURL *imageURLData `json:"image_url,omitempty"`
}

type imageURLData struct {
	URL string `json:"url"`
}

type visionResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (c *LLMClient) doVisionRequest(ctx context.Context, req visionRequest) (string, error) {
	body, err := encodeJSONRequest(req)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", OpenRouterChatURL, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", NewLLMError(fmt.Sprintf("OpenRouter returned %d: %s", resp.StatusCode, string(bodyBytes)))
	}

	var result visionResponse
	if err := decodeJSONFromReader(resp.Body, &result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", NewLLMError("empty response")
	}

	return result.Choices[0].Message.Content, nil
}

func fetchImageData(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch image: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("failed to fetch image: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read image: %w", err)
	}

	mimeType := resp.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "image/jpeg"
	}

	return data, mimeType, nil
}

func encodeJSONRequest(v interface{}) (string, error) {
	b, err := encodeJSONBytes(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeJSONFromReader(r io.Reader, v interface{}) error {
	return decodeJSONReader(r, v)
}

func encodeJSONBytes(v interface{}) ([]byte, error) {
	return encodeToJSONBytes(v)
}
