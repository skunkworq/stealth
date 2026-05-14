// Package solver provides CAPTCHA solving capabilities for various challenge types.
package external_service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Solver defines the interface for CAPTCHA solving services.
type Solver interface {
	SolveRecaptchaV2(ctx context.Context, siteKey, url string) (string, error)
	SolveRecaptchaV3(ctx context.Context, siteKey, url string, minScore float64) (string, error)
	SolveHCaptcha(ctx context.Context, siteKey, url string) (string, error)
	SolveTurnstile(ctx context.Context, siteKey, url string) (string, error)
	GetBalance(ctx context.Context) (float64, error)
}

// CapSolver implements the Solver interface using CapSolver API.
type CapSolver struct {
	apiKey   string
	client   *http.Client
	timeout  time.Duration
	pollRate time.Duration
}

type CapSolverTaskResult struct {
	TaskID   string          `json:"taskId"`
	Status   string          `json:"status"`
	Solution json.RawMessage `json:"solution"`
	ErrorID  int             `json:"errorId,omitempty"`
	Error    string          `json:"errorDescription,omitempty"`
}

type RecaptchaV2Solution struct {
	GRecaptchaResponse string `json:"gRecaptchaResponse"`
}

type RecaptchaV3Solution struct {
	GRecaptchaResponse string  `json:"gRecaptchaResponse"`
	Score              float64 `json:"score"`
}

type TurnstileSolution struct {
	Token string `json:"token"`
}

func NewCapSolver(apiKey string) *CapSolver {
	return &CapSolver{
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 120 * time.Second},
		timeout:  120 * time.Second,
		pollRate: 5 * time.Second,
	}
}

func (c *CapSolver) createTask(ctx context.Context, taskType string, taskData map[string]interface{}) (string, error) {
	taskData["type"] = taskType

	reqBody := map[string]interface{}{
		"clientKey": c.apiKey,
		"task":      taskData,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.client.Post("https://api.capsolver.com/createTask", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("post request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var createResp struct {
		TaskID  string `json:"taskId"`
		ErrorID int    `json:"errorId"`
		Error   string `json:"errorDescription"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	if createResp.ErrorID != 0 {
		return "", fmt.Errorf("capsolver error: %s", createResp.Error)
	}

	return createResp.TaskID, nil
}

func (c *CapSolver) getTaskResult(ctx context.Context, taskID string) (*CapSolverTaskResult, error) {
	reqBody := map[string]interface{}{
		"clientKey": c.apiKey,
		"taskId":    taskID,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.client.Post("https://api.capsolver.com/getTaskResult", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("get task result: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result CapSolverTaskResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}

	return &result, nil
}

func (c *CapSolver) waitForResult(ctx context.Context, taskID string) (json.RawMessage, error) {
	ticker := time.NewTicker(c.pollRate)
	defer ticker.Stop()

	timeout := time.After(c.timeout)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for solution")
		case <-ticker.C:
			result, err := c.getTaskResult(ctx, taskID)
			if err != nil {
				return nil, err
			}

			if result.Status == "ready" {
				return result.Solution, nil
			}
			if result.Status == "failed" {
				return nil, fmt.Errorf("task failed: %s", result.Error)
			}
		}
	}
}

func (c *CapSolver) SolveRecaptchaV2(ctx context.Context, siteKey, url string) (string, error) {
	taskID, err := c.createTask(ctx, "ReCaptchaV2Task", map[string]interface{}{
		"websiteKey": siteKey,
		"websiteURL": url,
	})
	if err != nil {
		return "", err
	}

	solution, err := c.waitForResult(ctx, taskID)
	if err != nil {
		return "", err
	}

	var sol RecaptchaV2Solution
	if err := json.Unmarshal(solution, &sol); err != nil {
		return "", fmt.Errorf("unmarshal solution: %w", err)
	}

	return sol.GRecaptchaResponse, nil
}

func (c *CapSolver) SolveRecaptchaV3(ctx context.Context, siteKey, url string, minScore float64) (string, error) {
	taskID, err := c.createTask(ctx, "ReCaptchaV3Task", map[string]interface{}{
		"websiteKey": siteKey,
		"websiteURL": url,
		"minScore":   minScore,
		"pageAction": "verify",
	})
	if err != nil {
		return "", err
	}

	solution, err := c.waitForResult(ctx, taskID)
	if err != nil {
		return "", err
	}

	var sol RecaptchaV3Solution
	if err := json.Unmarshal(solution, &sol); err != nil {
		return "", fmt.Errorf("unmarshal solution: %w", err)
	}

	return sol.GRecaptchaResponse, nil
}

func (c *CapSolver) SolveHCaptcha(ctx context.Context, siteKey, url string) (string, error) {
	taskID, err := c.createTask(ctx, "HCaptchaTask", map[string]interface{}{
		"websiteKey": siteKey,
		"websiteURL": url,
	})
	if err != nil {
		return "", err
	}

	solution, err := c.waitForResult(ctx, taskID)
	if err != nil {
		return "", err
	}

	var sol struct {
		GRecaptchaResponse string `json:"gRecaptchaResponse"`
	}
	if err := json.Unmarshal(solution, &sol); err != nil {
		return "", fmt.Errorf("unmarshal solution: %w", err)
	}

	return sol.GRecaptchaResponse, nil
}

func (c *CapSolver) SolveTurnstile(ctx context.Context, siteKey, url string) (string, error) {
	taskID, err := c.createTask(ctx, "TurnstileTask", map[string]interface{}{
		"websiteKey": siteKey,
		"websiteURL": url,
	})
	if err != nil {
		return "", err
	}

	solution, err := c.waitForResult(ctx, taskID)
	if err != nil {
		return "", err
	}

	var sol TurnstileSolution
	if err := json.Unmarshal(solution, &sol); err != nil {
		return "", fmt.Errorf("unmarshal solution: %w", err)
	}

	return sol.Token, nil
}

func (c *CapSolver) GetBalance(ctx context.Context) (float64, error) {
	reqBody := map[string]interface{}{
		"clientKey": c.apiKey,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.client.Post("https://api.capsolver.com/getBalance", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("get balance: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Balance float64 `json:"balance"`
		ErrorID int     `json:"errorId"`
		Error   string  `json:"errorDescription"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	if result.ErrorID != 0 {
		return 0, fmt.Errorf("capsolver error: %s", result.Error)
	}

	return result.Balance, nil
}

type SolverConfig struct {
	Provider string
	//nolint:gosec // APIKey field name required for API compatibility
	APIKey     string
	AutoSolve  bool
	MaxRetries int
	Timeout    time.Duration
}

func NewSolver(config SolverConfig) (Solver, error) {
	switch config.Provider {
	case "capsolver":
		return NewCapSolver(config.APIKey), nil
	default:
		return nil, fmt.Errorf("unknown solver provider: %s", config.Provider)
	}
}
