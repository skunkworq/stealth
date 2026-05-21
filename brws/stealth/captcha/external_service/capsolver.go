// Package solver provides CAPTCHA solving capabilities for various challenge types.
package external_service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/skunkworq/stealth/brws/core/constants"
	httpclient "github.com/skunkworq/stealth/brws/network/client"
)

// Solver defines the interface for CAPTCHA solving services.
type Solver interface {
	SolveRecaptchaV2(ctx context.Context, siteKey, url string) (string, error)
	SolveRecaptchaV3(ctx context.Context, siteKey, url string, minScore float64) (string, error)
	SolveHcaptcha(ctx context.Context, siteKey, url string) (string, error)
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

// NewCapSolver creates a CapSolver with default timeouts.
func NewCapSolver(apiKey string) *CapSolver {
	return NewCapSolverWithConfig(SolverConfig{APIKey: apiKey})
}

// NewCapSolverWithConfig creates a CapSolver from a SolverConfig.
// Zero-value Timeout falls back to constants.SolverTimeout; zero-value
// PollRate falls back to constants.SolverPollRate.
func NewCapSolverWithConfig(cfg SolverConfig) *CapSolver {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = constants.SolverTimeout
	}
	pollRate := cfg.PollRate
	if pollRate == 0 {
		pollRate = constants.SolverPollRate
	}
	// HTTP client timeout governs individual API calls; the total solve wait is
	// tracked separately via c.timeout.
	httpCfg := httpclient.DefaultConfig()
	return &CapSolver{
		apiKey:   cfg.APIKey,
		client:   httpclient.New(httpCfg),
		timeout:  timeout,
		pollRate: pollRate,
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

func (c *CapSolver) SolveHcaptcha(ctx context.Context, siteKey, url string) (string, error) {
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
	// Timeout is the total time to wait for a solve to complete across all
	// polling iterations. Defaults to constants.SolverTimeout when zero.
	Timeout time.Duration
	// PollRate is how often to check for a completed task result.
	// Defaults to constants.SolverPollRate when zero.
	PollRate time.Duration
}

func NewSolver(config SolverConfig) (Solver, error) {
	switch config.Provider {
	case "capsolver":
		return NewCapSolverWithConfig(config), nil
	default:
		return nil, fmt.Errorf("unknown solver provider: %s", config.Provider)
	}
}
