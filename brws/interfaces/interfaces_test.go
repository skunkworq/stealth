package interfaces

import (
	"context"
	"testing"

	"go.uber.org/mock/gomock"
)

// TestEngineMock tests the Engine mock
func TestEngineMock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := NewMockEngine(ctrl)

	mock.EXPECT().Name().Return("chromium-stealth")
	mock.EXPECT().Do(context.Background(), "https://example.com").Return(200, []byte("body"), nil)
	mock.EXPECT().Close().Return(nil)

	if mock.Name() != "chromium-stealth" {
		t.Errorf("expected chromium-stealth, got %s", mock.Name())
	}

	status, body, err := mock.Do(context.Background(), "https://example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if status != 200 {
		t.Errorf("expected status 200, got %d", status)
	}
	if string(body) != "body" {
		t.Errorf("expected body 'body', got %s", string(body))
	}

	if err := mock.Close(); err != nil {
		t.Errorf("unexpected close error: %v", err)
	}
}

// TestChallengeDetectorMock tests the ChallengeDetector mock
func TestChallengeDetectorMock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := NewMockChallengeDetector(ctrl)

	mock.EXPECT().Detect(gomock.Any()).Return(true, "recaptcha")

	detected, challengeType := mock.Detect([]byte("some content"))
	if !detected {
		t.Error("expected detected=true")
	}
	if challengeType != "recaptcha" {
		t.Errorf("expected recaptcha, got %s", challengeType)
	}
}

// TestSessionManagerMock tests the SessionManager mock
func TestSessionManagerMock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := NewMockSessionManager(ctrl)
	mockSession := NewMockSession(ctrl)

	mock.EXPECT().Create(gomock.Any()).Return(mockSession, nil)
	mock.EXPECT().Get(gomock.Any()).Return(mockSession, nil)
	mock.EXPECT().List().Return([]Session{mockSession})
	mock.EXPECT().Delete(gomock.Any()).Return(nil)

	session, err := mock.Create("test-session")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if session == nil {
		t.Error("expected non-nil session")
	}

	session, err = mock.Get("session-id")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	sessions := mock.List()
	if len(sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessions))
	}

	if err := mock.Delete("session-id"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestChallengeSolverMock tests the ChallengeSolver mock
func TestChallengeSolverMock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := NewMockChallengeSolver(ctrl)

	mock.EXPECT().SolveRecaptchaV2(gomock.Any(), gomock.Any(), gomock.Any()).Return("token123", nil)
	mock.EXPECT().SolveHCaptcha(gomock.Any(), gomock.Any(), gomock.Any()).Return("hcaptcha_token", nil)
	mock.EXPECT().GetBalance(gomock.Any()).Return(10.50, nil)

	token, err := mock.SolveRecaptchaV2(context.Background(), "sitekey", "https://example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if token != "token123" {
		t.Errorf("expected token123, got %s", token)
	}

	token, err = mock.SolveHCaptcha(context.Background(), "sitekey", "https://example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if token != "hcaptcha_token" {
		t.Errorf("expected hcaptcha_token, got %s", token)
	}

	balance, err := mock.GetBalance(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if balance != 10.50 {
		t.Errorf("expected 10.50, got %f", balance)
	}
}

// TestMockExpectations tests that mock expectations are called
func TestMockExpectations(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	engine := NewMockEngine(ctrl)

	// Set up ordered expectations
	gomock.InOrder(
		engine.EXPECT().Name().Return("test-engine"),
		engine.EXPECT().Do(context.Background(), "https://example.com").Return(200, []byte("ok"), nil),
		engine.EXPECT().Close().Return(nil),
	)

	name := engine.Name()
	if name != "test-engine" {
		t.Errorf("expected test-engine, got %s", name)
	}

	status, body, err := engine.Do(context.Background(), "https://example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if status != 200 || string(body) != "ok" {
		t.Errorf("unexpected response: %d %s", status, string(body))
	}

	if err := engine.Close(); err != nil {
		t.Errorf("unexpected close error: %v", err)
	}
}
