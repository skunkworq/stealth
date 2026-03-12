package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewManager(t *testing.T) {
	tmpDir := t.TempDir()

	mgr, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	if mgr == nil {
		t.Fatal("Manager is nil")
	}

	// Verify directory was created
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Error("Sessions directory was not created")
	}
}

func TestCreateSession(t *testing.T) {
	tmpDir := t.TempDir()

	mgr, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	sess, err := mgr.Create("test-session", "chromium")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if sess.ID == "" {
		t.Error("Session ID is empty")
	}

	if sess.Name != "test-session" {
		t.Errorf("Expected name 'test-session', got '%s'", sess.Name)
	}

	if sess.Engine != "chromium" {
		t.Errorf("Expected engine 'chromium', got '%s'", sess.Engine)
	}

	// Verify profile directory exists
	if _, err := os.Stat(sess.ProfileDir); os.IsNotExist(err) {
		t.Error("Profile directory was not created")
	}

	// Verify session file exists
	sessionFile := filepath.Join(tmpDir, sess.ID, "session.json")
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		t.Error("Session file was not created")
	}
}

func TestGetSession(t *testing.T) {
	tmpDir := t.TempDir()

	mgr, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	sess, err := mgr.Create("test-session", "firefox")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Retrieve session
	retrieved, err := mgr.Get(sess.ID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrieved.ID != sess.ID {
		t.Errorf("Expected ID '%s', got '%s'", sess.ID, retrieved.ID)
	}

	// Try to get non-existent session
	_, err = mgr.Get("non-existent-id")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}

func TestListSessions(t *testing.T) {
	tmpDir := t.TempDir()

	mgr, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Create a few sessions
	for _, name := range []string{"session1", "session2", "session3"} {
		_, err := mgr.Create(name, "chromium")
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
	}

	sessions := mgr.List()
	if len(sessions) != 3 {
		t.Errorf("Expected 3 sessions, got %d", len(sessions))
	}
}

func TestDeleteSession(t *testing.T) {
	tmpDir := t.TempDir()

	mgr, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	sess, err := mgr.Create("to-delete", "webkit")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	sessionDir := filepath.Join(tmpDir, sess.ID)

	// Delete session
	err = mgr.Delete(sess.ID)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify directory is gone
	if _, err := os.Stat(sessionDir); !os.IsNotExist(err) {
		t.Error("Session directory still exists after deletion")
	}

	// Try to delete again
	err = mgr.Delete(sess.ID)
	if err == nil {
		t.Error("Expected error when deleting non-existent session")
	}
}

func TestSessionCookieJar(t *testing.T) {
	tmpDir := t.TempDir()

	mgr, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	sess, err := mgr.Create("cookie-test", "chromium")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	jar := sess.CookieJar()
	if jar == nil {
		t.Error("Cookie jar is nil")
	}
}
