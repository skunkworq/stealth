package integration

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/content/semantic"
)

type SessionState struct {
	Cookies      []Cookie
	LocalStorage map[string]string
	SessionToken string
	AuthToken    string
	CSRFToken    string
	UserAgent    string
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

type Cookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Expires  time.Time
	Secure   bool
	HttpOnly bool
}

type SessionManager struct {
	sessions sync.Map // map[string]*SessionState
	current  *SessionState
	mu       sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

func (sm *SessionManager) CreateSession(id string) *SessionState {
	session := &SessionState{
		LocalStorage: make(map[string]string),
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
	}

	sm.sessions.Store(id, session)
	sm.mu.Lock()
	sm.current = session
	sm.mu.Unlock()

	return session
}

func (sm *SessionManager) GetSession(id string) *SessionState {
	if val, ok := sm.sessions.Load(id); ok {
		return val.(*SessionState)
	}
	return nil
}

func (sm *SessionManager) GetCurrentSession() *SessionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.current
}

func (sm *SessionManager) SetCurrentSession(id string) bool {
	if session := sm.GetSession(id); session != nil {
		sm.mu.Lock()
		sm.current = session
		sm.mu.Unlock()
		return true
	}
	return false
}

func (sm *SessionManager) UpdateSession(id string, updates func(*SessionState)) {
	if session := sm.GetSession(id); session != nil {
		updates(session)
		session.LastUsedAt = time.Now()
	}
}

func (sm *SessionManager) SetCookie(id, name, value, domain, path string) {
	sm.UpdateSession(id, func(s *SessionState) {
		s.Cookies = append(s.Cookies, Cookie{
			Name:   name,
			Value:  value,
			Domain: domain,
			Path:   path,
		})
	})
}

func (sm *SessionManager) SetLocalStorage(id, key, value string) {
	sm.UpdateSession(id, func(s *SessionState) {
		s.LocalStorage[key] = value
	})
}

func (sm *SessionManager) SetAuthToken(id, token string) {
	sm.UpdateSession(id, func(s *SessionState) {
		s.AuthToken = token
	})
}

func (sm *SessionManager) SetCSRFToken(id, token string) {
	sm.UpdateSession(id, func(s *SessionState) {
		s.CSRFToken = token
	})
}

func (sm *SessionManager) IsAuthenticated(id string) bool {
	session := sm.GetSession(id)
	if session == nil {
		return false
	}
	return session.AuthToken != "" || len(session.Cookies) > 0
}

func (sm *SessionManager) GetAuthorizationHeader(id string) string {
	session := sm.GetSession(id)
	if session == nil || session.AuthToken == "" {
		return ""
	}
	return "Bearer " + session.AuthToken
}

func (sm *SessionManager) ClearSession(id string) {
	sm.sessions.Delete(id)
	sm.mu.Lock()
	if sm.current != nil && sm.GetSession(id) == nil {
		sm.current = nil
	}
	sm.mu.Unlock()
}

func (sm *SessionManager) ListSessions() []string {
	var ids []string
	sm.sessions.Range(func(key, value interface{}) bool {
		ids = append(ids, key.(string))
		return true
	})
	return ids
}

func (sm *SessionManager) ExtractSessionFromTree(ctx context.Context, tree *semantic.SemanticTree) map[string]string {
	tokens := make(map[string]string)

	for _, node := range tree.AllNodes() {
		if node.Summary == "" {
			continue
		}

		summaryLower := strings.ToLower(node.Summary)

		if strings.Contains(summaryLower, "csrf") || strings.Contains(summaryLower, "xsrf") {
			for _, attr := range []string{"value", "content", "data-token"} {
				if val := extractValueFromNode(node, attr); val != "" {
					tokens["csrf"] = val
					break
				}
			}
		}

		if strings.Contains(summaryLower, "auth") || strings.Contains(summaryLower, "token") {
			for _, attr := range []string{"value", "data-token", "token"} {
				if val := extractValueFromNode(node, attr); val != "" {
					if !strings.Contains(summaryLower, "csrf") {
						tokens["auth"] = val
					}
					break
				}
			}
		}

		if strings.Contains(summaryLower, "session") {
			for _, attr := range []string{"data-session", "session-id", "value"} {
				if val := extractValueFromNode(node, attr); val != "" {
					tokens["session"] = val
					break
				}
			}
		}
	}

	return tokens
}

func extractValueFromNode(node *semantic.SemanticNode, attr string) string {
	return ""
}

func (sm *SessionManager) DetectAuthState(tree *semantic.SemanticTree) AuthState {
	state := AuthState{}

	for _, node := range tree.AllNodes() {
		summaryLower := strings.ToLower(node.Summary)

		if strings.Contains(summaryLower, "logout") || strings.Contains(summaryLower, "sign out") {
			state.LoggedIn = true
			state.LogoutSelector = findClickSelector(node)
		}

		if strings.Contains(summaryLower, "login") || strings.Contains(summaryLower, "sign in") {
			state.LoginSelector = findClickSelector(node)
		}

		if strings.Contains(summaryLower, "username") || strings.Contains(summaryLower, "email") {
			state.UsernameField = findInputSelector(node)
		}

		if strings.Contains(summaryLower, "password") {
			state.PasswordField = findInputSelector(node)
		}
	}

	return state
}

type AuthState struct {
	LoggedIn       bool
	LoginSelector  string
	LogoutSelector string
	UsernameField  string
	PasswordField  string
}

func findClickSelector(node *semantic.SemanticNode) string {
	for _, action := range node.Actions {
		if action.Type == semantic.ActionClick {
			return action.Selector
		}
	}
	return ""
}

func findInputSelector(node *semantic.SemanticNode) string {
	for _, action := range node.Actions {
		if action.Type == semantic.ActionFill {
			return action.Selector
		}
	}
	return ""
}
