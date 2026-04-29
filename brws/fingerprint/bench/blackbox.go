package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/core/types"
)

// BlackboxPhaseKind identifies the kind of benchmark phase.
type BlackboxPhaseKind string

const (
	PhaseCapture BlackboxPhaseKind = "capture"
	PhaseShield  BlackboxPhaseKind = "shield"
)

const (
	urlPlaceholder = "{{URL}}"
	defaultTimeout = 20 * time.Second
)

// BlackboxCommandResult captures an external command's outcome.
type BlackboxCommandResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// BlackboxCommandRunner executes an external probe command.
type BlackboxCommandRunner interface {
	Run(context.Context, []string, []string, string) (*BlackboxCommandResult, error)
}

// BlackboxPhaseSpec describes one phase for a tool.
type BlackboxPhaseSpec struct {
	Name    string            `json:"name"`
	Kind    BlackboxPhaseKind `json:"kind"`
	URLPath string            `json:"url_path"`
	Command []string          `json:"command"`
	Env     []string          `json:"env,omitempty"`
	Workdir string            `json:"workdir,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`
}

// BlackboxToolSpec defines a real tool/process to benchmark.
type BlackboxToolSpec struct {
	Name              string              `json:"name"`
	Description       string              `json:"description"`
	Language          string              `json:"language,omitempty"`
	Category          string              `json:"category,omitempty"`
	AvailabilityCheck []string            `json:"availability_check,omitempty"`
	Phases            []BlackboxPhaseSpec `json:"phases"`
}

// BlackboxConfig controls a real-tool blackbox benchmark run.
type BlackboxConfig struct {
	BaseURL                  string
	InsecureTLS              bool
	Tools                    []BlackboxToolSpec
	Runner                   BlackboxCommandRunner
	AllowMissing             bool
	IncludeModeledComparison bool
	Verbose                  bool
}

// BlackboxAvailability describes whether a tool can be executed locally.
type BlackboxAvailability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// BlackboxCaptureSummary is a compact view of the capture phase result.
type BlackboxCaptureSummary struct {
	ID          string   `json:"id,omitempty"`
	UserAgent   string   `json:"user_agent,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	JA3Hash     string   `json:"ja3_hash,omitempty"`
	JA4         string   `json:"ja4,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	HeaderCount int      `json:"header_count,omitempty"`
	HasTLS      bool     `json:"has_tls"`
	HasHTTP2    bool     `json:"has_http2"`
}

// BlackboxCaptureResult is the output of the raw fingerprint capture phase.
type BlackboxCaptureResult struct {
	Executed    bool                       `json:"executed"`
	Error       string                     `json:"error,omitempty"`
	Command     []string                   `json:"command,omitempty"`
	CommandInfo *BlackboxCommandResult     `json:"command_info,omitempty"`
	Fingerprint *types.CompleteFingerprint `json:"fingerprint,omitempty"`
	Summary     *BlackboxCaptureSummary    `json:"summary,omitempty"`
}

// BlackboxShieldResult is the output of the shield scoring phase.
type BlackboxShieldResult struct {
	Executed     bool                   `json:"executed"`
	Error        string                 `json:"error,omitempty"`
	Command      []string               `json:"command,omitempty"`
	CommandInfo  *BlackboxCommandResult `json:"command_info,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	IsBot        bool                   `json:"is_bot"`
	IsStealth    bool                   `json:"is_stealth"`
	Score        float64                `json:"score"`
	Confidence   float64                `json:"confidence"`
	Indicators   []string               `json:"indicators,omitempty"`
	VectorScores map[string]float64     `json:"vector_scores,omitempty"`
}

// BlackboxModeledComparison links a real-tool run to the modeled benchmark result.
type BlackboxModeledComparison struct {
	DetectionRate float64 `json:"detection_rate"`
	AvgBotScore   float64 `json:"avg_bot_score"`
	AvgConfidence float64 `json:"avg_confidence"`
}

// BlackboxToolResult captures the benchmark outcome for one tool.
type BlackboxToolResult struct {
	Name              string                     `json:"name"`
	Description       string                     `json:"description"`
	Language          string                     `json:"language,omitempty"`
	Category          string                     `json:"category,omitempty"`
	Availability      BlackboxAvailability       `json:"availability"`
	Capture           *BlackboxCaptureResult     `json:"capture,omitempty"`
	Shield            *BlackboxShieldResult      `json:"shield,omitempty"`
	ModeledComparison *BlackboxModeledComparison `json:"modeled_comparison,omitempty"`
}

// BlackboxReport is the full report for a real-tool benchmark pass.
type BlackboxReport struct {
	Timestamp     time.Time            `json:"timestamp"`
	BaseURL       string               `json:"base_url"`
	ToolCount     int                  `json:"tool_count"`
	ExecutedCount int                  `json:"executed_count"`
	SkippedCount  int                  `json:"skipped_count"`
	Results       []BlackboxToolResult `json:"results"`
}

// ExecBlackboxRunner executes external commands with exec.CommandContext.
type ExecBlackboxRunner struct{}

// Run executes one external command.
func (ExecBlackboxRunner) Run(ctx context.Context, argv, env []string, workdir string) (*BlackboxCommandResult, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	if workdir != "" {
		cmd.Dir = workdir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &BlackboxCommandResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err == nil {
		return result, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}

	return result, err
}

// DefaultBlackboxToolSpecs returns the built-in real-tool blackbox presets.
func DefaultBlackboxToolSpecs(pythonBin string) []BlackboxToolSpec {
	if pythonBin == "" {
		pythonBin = "python3"
	}

	fixture := blackboxFixturePath("python_blackbox_probe.py")
	makePythonTool := func(name, description, category string) BlackboxToolSpec {
		availability := []string{pythonBin, fixture, "--tool", name, "--check"}
		command := func(url string) []string {
			return []string{pythonBin, fixture, "--tool", name, "--url", url}
		}
		return BlackboxToolSpec{
			Name:              name,
			Description:       description,
			Language:          "Python",
			Category:          category,
			AvailabilityCheck: availability,
			Phases: []BlackboxPhaseSpec{
				{
					Name:    "capture",
					Kind:    PhaseCapture,
					URLPath: "/capture/json",
					Command: command(urlPlaceholder),
					Timeout: defaultTimeout,
				},
				{
					Name:    "shield",
					Kind:    PhaseShield,
					URLPath: "/api/stealth-test",
					Command: command(urlPlaceholder),
					Timeout: defaultTimeout,
				},
			},
		}
	}

	return []BlackboxToolSpec{
		makePythonTool("scrapy_default", "Real Scrapy process using a single scripted spider", "bare_http"),
		makePythonTool("nodriver", "Real nodriver browser launch against the local lab", "browser_stealth"),
		makePythonTool("scrapling_stealthy", "Real Scrapling StealthyFetcher against the local lab", "browser_stealth"),
		makePythonTool("scrapling_playwright", "Real Scrapling DynamicFetcher against the local lab", "browser_default"),
	}
}

// RunBlackboxBenchmark executes the configured tools against the local lab/shield endpoints.
func RunBlackboxBenchmark(ctx context.Context, cfg *BlackboxConfig) (*BlackboxReport, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	if cfg.BaseURL == "" {
		return nil, errors.New("base URL is required")
	}
	if len(cfg.Tools) == 0 {
		return nil, errors.New("at least one tool spec is required")
	}

	runner := cfg.Runner
	if runner == nil {
		runner = ExecBlackboxRunner{}
	}

	report := &BlackboxReport{
		Timestamp: time.Now().UTC(),
		BaseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		ToolCount: len(cfg.Tools),
		Results:   make([]BlackboxToolResult, 0, len(cfg.Tools)),
	}

	var modeled map[string]BlackboxModeledComparison
	if cfg.IncludeModeledComparison {
		modeled = modeledComparisonMap()
	}

	for _, tool := range cfg.Tools {
		result := BlackboxToolResult{
			Name:        tool.Name,
			Description: tool.Description,
			Language:    tool.Language,
			Category:    tool.Category,
		}

		availability, err := detectBlackboxAvailability(ctx, runner, tool)
		if err != nil {
			return nil, err
		}
		result.Availability = availability
		if cmp, ok := modeled[tool.Name]; ok {
			result.ModeledComparison = &cmp
		}

		if !availability.Available {
			report.SkippedCount++
			report.Results = append(report.Results, result)
			if !cfg.AllowMissing {
				return nil, fmt.Errorf("tool %s unavailable: %s", tool.Name, availability.Reason)
			}
			continue
		}

		report.ExecutedCount++
		for _, phase := range tool.Phases {
			phaseResult, err := runBlackboxPhase(ctx, runner, report.BaseURL, cfg.InsecureTLS, tool, phase)
			if err != nil {
				return nil, err
			}
			switch phase.Kind {
			case PhaseCapture:
				result.Capture = phaseResult.capture
			case PhaseShield:
				result.Shield = phaseResult.shield
			}
		}

		report.Results = append(report.Results, result)
	}

	return report, nil
}

// PrintBlackboxReport writes a concise human-readable report.
func PrintBlackboxReport(report *BlackboxReport) {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║               BLACKBOX TOOL BENCHMARK REPORT                 ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Base URL:      %s\n", report.BaseURL)
	fmt.Printf("Tools:         %d\n", report.ToolCount)
	fmt.Printf("Executed:      %d\n", report.ExecutedCount)
	fmt.Printf("Skipped:       %d\n", report.SkippedCount)
	fmt.Println()

	fmt.Printf("%-22s │ %-9s │ %-8s │ %-8s │ %-8s │ %s\n", "Tool", "Available", "Capture", "Shield", "Score", "Notes")
	fmt.Println(strings.Repeat("─", 92))

	for _, result := range report.Results {
		available := "yes"
		if !result.Availability.Available {
			available = "no"
		}
		capture := "-"
		if result.Capture != nil && result.Capture.Executed {
			capture = result.Capture.Summary.Protocol
			if capture == "" {
				capture = "ok"
			}
		}
		shield := "-"
		score := "-"
		notes := result.Availability.Reason
		if result.Shield != nil && result.Shield.Executed {
			if result.Shield.IsBot {
				shield = "bot"
			} else {
				shield = "human"
			}
			score = fmt.Sprintf("%.3f", result.Shield.Score)
			if len(result.Shield.Indicators) > 0 {
				notes = strings.Join(result.Shield.Indicators[:minInt(3, len(result.Shield.Indicators))], ", ")
			}
		}
		fmt.Printf("%-22s │ %-9s │ %-8s │ %-8s │ %-8s │ %s\n",
			result.Name, available, capture, shield, score, notes)
	}
}

// ExportBlackboxJSON renders the report as formatted JSON.
func ExportBlackboxJSON(report *BlackboxReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

type blackboxPhaseExecution struct {
	capture *BlackboxCaptureResult
	shield  *BlackboxShieldResult
}

func detectBlackboxAvailability(ctx context.Context, runner BlackboxCommandRunner, tool BlackboxToolSpec) (BlackboxAvailability, error) {
	if len(tool.AvailabilityCheck) == 0 {
		return BlackboxAvailability{Available: true}, nil
	}

	result, err := runner.Run(ctx, tool.AvailabilityCheck, nil, "")
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
			return BlackboxAvailability{Available: false, Reason: execErr.Name + " not installed"}, nil
		}
		return BlackboxAvailability{}, err
	}

	if payload := parseAvailabilityJSON(result.Stdout); payload != nil {
		return *payload, nil
	}
	if result.ExitCode != 0 {
		reason := strings.TrimSpace(result.Stderr)
		if reason == "" {
			reason = strings.TrimSpace(result.Stdout)
		}
		if reason == "" {
			reason = fmt.Sprintf("availability check exit %d", result.ExitCode)
		}
		return BlackboxAvailability{Available: false, Reason: reason}, nil
	}

	return BlackboxAvailability{Available: true}, nil
}

func runBlackboxPhase(ctx context.Context, runner BlackboxCommandRunner, baseURL string, insecureTLS bool, tool BlackboxToolSpec, phase BlackboxPhaseSpec) (*blackboxPhaseExecution, error) {
	command := expandBlackboxCommand(phase.Command, strings.TrimRight(baseURL, "/")+phase.URLPath)
	timeout := phase.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	phaseCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := runner.Run(phaseCtx, command, buildPhaseEnv(phase.Env, insecureTLS), phase.Workdir)
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
			msg := execErr.Name + " not installed"
			switch phase.Kind {
			case PhaseCapture:
				return &blackboxPhaseExecution{capture: &BlackboxCaptureResult{Command: command, Error: msg}}, nil
			case PhaseShield:
				return &blackboxPhaseExecution{shield: &BlackboxShieldResult{Command: command, Error: msg}}, nil
			}
		}
		return nil, err
	}

	switch phase.Kind {
	case PhaseCapture:
		capture := &BlackboxCaptureResult{
			Executed:    true,
			Command:     command,
			CommandInfo: result,
		}
		if result.ExitCode != 0 {
			capture.Error = blackboxResultError(result)
			return &blackboxPhaseExecution{capture: capture}, nil
		}
		fp, err := parseCompleteFingerprint(result.Stdout)
		if err != nil {
			capture.Error = err.Error()
			return &blackboxPhaseExecution{capture: capture}, nil
		}
		capture.Fingerprint = fp
		capture.Summary = summarizeFingerprint(fp)
		return &blackboxPhaseExecution{capture: capture}, nil

	case PhaseShield:
		shield := &BlackboxShieldResult{
			Executed:    true,
			Command:     command,
			CommandInfo: result,
		}
		if result.ExitCode != 0 {
			shield.Error = blackboxResultError(result)
			return &blackboxPhaseExecution{shield: shield}, nil
		}
		parsed, err := parseShieldResponse(result.Stdout)
		if err != nil {
			shield.Error = err.Error()
			return &blackboxPhaseExecution{shield: shield}, nil
		}
		*shield = *parsed
		shield.Executed = true
		shield.Command = command
		shield.CommandInfo = result
		return &blackboxPhaseExecution{shield: shield}, nil
	}

	return nil, fmt.Errorf("unsupported phase kind %q", phase.Kind)
}

func expandBlackboxCommand(command []string, targetURL string) []string {
	expanded := make([]string, 0, len(command))
	for _, part := range command {
		expanded = append(expanded, strings.ReplaceAll(part, urlPlaceholder, targetURL))
	}
	return expanded
}

func buildPhaseEnv(base []string, insecureTLS bool) []string {
	if len(base) == 0 && !insecureTLS {
		return nil
	}

	env := make([]string, 0, len(base)+1)
	env = append(env, base...)
	if insecureTLS {
		env = append(env, "BLACKBOX_INSECURE_TLS=1")
	}
	return env
}

func parseAvailabilityJSON(stdout string) *BlackboxAvailability {
	var payload struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
	}
	if err := decodeFirstJSON(stdout, &payload); err != nil {
		return nil
	}
	return &BlackboxAvailability{Available: payload.Available, Reason: payload.Reason}
}

func parseCompleteFingerprint(stdout string) (*types.CompleteFingerprint, error) {
	var fp types.CompleteFingerprint
	if err := decodeFirstJSON(stdout, &fp); err != nil {
		return nil, fmt.Errorf("decode capture fingerprint: %w", err)
	}
	if fp.ID == "" {
		var envelope struct {
			Body string `json:"body"`
		}
		if err := decodeFirstJSON(stdout, &envelope); err == nil && strings.TrimSpace(envelope.Body) != "" {
			return parseCompleteFingerprint(envelope.Body)
		}
		return nil, errors.New("capture response missing fingerprint id")
	}
	return &fp, nil
}

func parseShieldResponse(stdout string) (*BlackboxShieldResult, error) {
	var payload struct {
		RequestID  string  `json:"request_id"`
		IsBot      bool    `json:"is_bot"`
		IsStealth  bool    `json:"is_stealth"`
		Score      float64 `json:"score"`
		Confidence float64 `json:"confidence"`
		Vectors    []struct {
			Category string  `json:"category"`
			Score    float64 `json:"score"`
		} `json:"vectors"`
		Indicators []struct {
			Name string `json:"name"`
		} `json:"indicators"`
		Body string `json:"body"`
	}
	if err := decodeFirstJSON(stdout, &payload); err != nil {
		return nil, fmt.Errorf("decode shield response: %w", err)
	}
	if payload.RequestID == "" && strings.TrimSpace(payload.Body) != "" {
		return parseShieldResponse(payload.Body)
	}

	result := &BlackboxShieldResult{
		RequestID:    payload.RequestID,
		IsBot:        payload.IsBot,
		IsStealth:    payload.IsStealth,
		Score:        payload.Score,
		Confidence:   payload.Confidence,
		Indicators:   make([]string, 0, len(payload.Indicators)),
		VectorScores: make(map[string]float64, len(payload.Vectors)),
	}
	for _, vector := range payload.Vectors {
		result.VectorScores[vector.Category] = vector.Score
	}
	for _, indicator := range payload.Indicators {
		result.Indicators = append(result.Indicators, indicator.Name)
	}
	return result, nil
}

func decodeFirstJSON(stdout string, dst any) error {
	trimmed := strings.TrimSpace(stdout)
	if trimmed == "" {
		return errors.New("empty output")
	}

	start := strings.IndexAny(trimmed, "{[")
	if start < 0 {
		return errors.New("no JSON payload found")
	}

	decoder := json.NewDecoder(strings.NewReader(trimmed[start:]))
	return decoder.Decode(dst)
}

func summarizeFingerprint(fp *types.CompleteFingerprint) *BlackboxCaptureSummary {
	if fp == nil {
		return nil
	}
	summary := &BlackboxCaptureSummary{
		ID:       fp.ID,
		HasTLS:   fp.TLS != nil,
		HasHTTP2: fp.HTTP2 != nil,
	}
	if fp.HTTP != nil {
		summary.UserAgent = fp.HTTP.UserAgent
		summary.Protocol = fp.HTTP.Protocol
		summary.HeaderCount = len(fp.HTTP.Headers)
	}
	if fp.TLS != nil {
		summary.JA3Hash = fp.TLS.JA3Hash
		summary.JA4 = fp.TLS.JA4
		summary.ALPN = append(summary.ALPN, fp.TLS.ALPN...)
	}
	return summary
}

func blackboxResultError(result *BlackboxCommandResult) string {
	if result == nil {
		return "unknown command failure"
	}
	if payload := parseAvailabilityJSON(result.Stdout); payload != nil && !payload.Available {
		return payload.Reason
	}
	if stderr := strings.TrimSpace(result.Stderr); stderr != "" {
		return stderr
	}
	if stdout := strings.TrimSpace(result.Stdout); stdout != "" {
		return stdout
	}
	return fmt.Sprintf("command exited with code %d", result.ExitCode)
}

func modeledComparisonMap() map[string]BlackboxModeledComparison {
	report := RunToolComparison(&ToolComparisonConfig{
		IncludeBehavioral: true,
		Iterations:        1,
	})

	results := make(map[string]BlackboxModeledComparison, len(report.Results))
	for _, result := range report.Results {
		results[result.Tool.Name] = BlackboxModeledComparison{
			DetectionRate: result.DetectionRate,
			AvgBotScore:   result.AvgBotScore,
			AvgConfidence: result.AvgConfidence,
		}
	}
	return results
}

func blackboxFixturePath(name string) string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return name
	}
	return filepath.Join(filepath.Dir(currentFile), "fixtures", name)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FilterBlackboxTools returns built-in specs limited to the requested names.
func FilterBlackboxTools(tools []BlackboxToolSpec, names []string) []BlackboxToolSpec {
	if len(names) == 0 {
		return tools
	}

	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[strings.TrimSpace(name)] = struct{}{}
	}

	filtered := make([]BlackboxToolSpec, 0, len(names))
	for _, tool := range tools {
		if _, ok := allowed[tool.Name]; ok {
			filtered = append(filtered, tool)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Name < filtered[j].Name
	})

	return filtered
}
