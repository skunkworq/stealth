package integration

import (
	"testing"

	"github.com/skunkworq/stealth/brws/content/understand"
)

func TestSmartNavigatorFindBestMatch(t *testing.T) {
	tree := &understand.SemanticTree{
		RootNodes: []understand.SemanticNode{
			{
				DOMSelector: "body",
				Actions: []understand.Action{
					{Type: understand.ActionClick, Selector: "button.login", Description: "Login button"},
					{Type: understand.ActionClick, Selector: "a.home", Description: "Go to homepage"},
				},
				Children: []understand.SemanticNode{
					{
						DOMSelector: "body/nav",
						Actions: []understand.Action{
							{Type: understand.ActionClick, Selector: "a.about", Description: "About us link"},
							{Type: understand.ActionClick, Selector: "a.contact", Description: "Contact page"},
						},
					},
				},
			},
		},
	}

	nav := &SmartNavigator{navigator: nil}

	intent := NavigationIntent{
		Description: "login",
		ActionType:  "click",
		Priority:    8,
	}

	result := nav.findBestIntentMatch(tree, intent)

	if !result.Found {
		t.Fatal("expected to find login action")
	}

	if result.Selector != "button.login" {
		t.Errorf("wrong selector: %s", result.Selector)
	}

	if result.Confidence < 5.0 {
		t.Errorf("confidence too low: %.1f", result.Confidence)
	}

	t.Logf("Found: %s (confidence: %.1f)", result.Selector, result.Confidence)
}

func TestSmartNavigatorFindLinkByText(t *testing.T) {
	tree := &understand.SemanticTree{
		RootNodes: []understand.SemanticNode{
			{
				DOMSelector: "body",
				Actions: []understand.Action{
					{Type: understand.ActionClick, Selector: "a.products", Description: "View all products"},
					{Type: understand.ActionClick, Selector: "a.services", Description: "Our services"},
				},
			},
		},
	}

	nav := &SmartNavigator{navigator: nil}

	result := nav.findBestIntentMatch(tree, NavigationIntent{
		Description: "products link",
		Priority:    7,
	})

	if !result.Found {
		t.Fatal("expected to find products link")
	}

	if result.Selector != "a.products" {
		t.Errorf("wrong selector: %s", result.Selector)
	}
}

func TestSmartNavigatorScoring(t *testing.T) {
	action := &understand.Action{
		Type:        understand.ActionClick,
		Selector:    "button.submit-form",
		Description: "Submit the form",
	}

	nav := &SmartNavigator{navigator: nil}

	score1 := nav.scoreIntentMatch(action, []string{"submit"}, "")
	t.Logf("Score with 'submit' text only: %.1f", score1)

	score2 := nav.scoreIntentMatch(action, []string{"submit"}, string(understand.ActionClick))
	t.Logf("Score with 'submit' text + action type: %.1f", score2)

	if score2 <= score1 {
		t.Errorf("expected action type to add bonus: %.1f vs %.1f", score2, score1)
	}

	score3 := nav.scoreIntentMatch(action, []string{"random", "words"}, "")
	if score3 > 0 {
		t.Errorf("expected low score for non-matching, got %.1f", score3)
	}

	score4 := nav.scoreIntentMatch(action, []string{"submit", "form"}, "")
	t.Logf("Score with 2 matching words: %.1f", score4)

	if score4 <= score1 {
		t.Errorf("expected more matching words to increase score: %.1f vs %.1f", score4, score1)
	}
}

func TestSmartNavigatorAlternatives(t *testing.T) {
	tree := &understand.SemanticTree{
		RootNodes: []understand.SemanticNode{
			{
				DOMSelector: "body",
				Actions: []understand.Action{
					{Type: understand.ActionClick, Selector: "a.shop-1", Description: "Shop now"},
					{Type: understand.ActionClick, Selector: "a.shop-2", Description: "Visit our shop"},
					{Type: understand.ActionClick, Selector: "a.store", Description: "Store locations"},
				},
			},
		},
	}

	nav := &SmartNavigator{navigator: nil}

	result := nav.findBestIntentMatch(tree, NavigationIntent{
		Description: "shop",
		Priority:    5,
	})

	if !result.Found {
		t.Fatal("expected to find shop actions")
	}

	if len(result.Alternatives) < 1 {
		t.Error("expected at least 1 alternative")
	}

	t.Logf("Best: %s, Alternatives: %d", result.Selector, len(result.Alternatives))
}

func TestSessionManagerBasics(t *testing.T) {
	sm := NewSessionManager()

	session := sm.CreateSession("test-session")

	if session == nil {
		t.Fatal("failed to create session")
	}

	if len(session.LocalStorage) != 0 {
		t.Error("expected empty local storage")
	}

	sm.SetCookie("test-session", "session_id", "abc123", "example.com", "/")

	session = sm.GetSession("test-session")
	if session == nil || len(session.Cookies) != 1 {
		t.Error("cookie not set")
	}

	sm.SetLocalStorage("test-session", "user_pref", "dark_mode")

	session = sm.GetSession("test-session")
	if session == nil || session.LocalStorage["user_pref"] != "dark_mode" {
		t.Error("local storage not set")
	}

	if len(sm.ListSessions()) != 1 {
		t.Error("expected 1 session")
	}

	sm.ClearSession("test-session")

	if sm.GetSession("test-session") != nil {
		t.Error("session should be cleared")
	}
}

func TestSessionManagerAuthTokens(t *testing.T) {
	sm := NewSessionManager()

	_ = sm.CreateSession("auth-test")

	if sm.IsAuthenticated("auth-test") {
		t.Error("should not be authenticated initially")
	}

	sm.SetAuthToken("auth-test", "bearer-token-123")

	if !sm.IsAuthenticated("auth-test") {
		t.Error("should be authenticated after setting token")
	}

	authHeader := sm.GetAuthorizationHeader("auth-test")
	if authHeader != "Bearer bearer-token-123" {
		t.Errorf("wrong auth header: %s", authHeader)
	}

	sm.SetCSRFToken("auth-test", "csrf-token-xyz")

	session := sm.GetSession("auth-test")
	if session == nil || session.CSRFToken != "csrf-token-xyz" {
		t.Error("CSRF token not set")
	}
}

func TestSessionManagerCurrentSession(t *testing.T) {
	sm := NewSessionManager()

	if sm.GetCurrentSession() != nil {
		t.Error("expected nil current session initially")
	}

	_ = sm.CreateSession("session-1")

	if sm.GetCurrentSession() == nil {
		t.Error("expected current session after create")
	}

	_ = sm.CreateSession("session-2")

	sm.SetCurrentSession("session-1")

	current := sm.GetCurrentSession()
	if current == nil {
		t.Error("expected current session")
	}
}

func TestFormFillerDetectForm(t *testing.T) {
	filler := &SemanticFormFiller{}

	tree := &understand.SemanticTree{
		RootNodes: []understand.SemanticNode{
			{
				DOMSelector: "body > form.login",
				Actions: []understand.Action{
					{Type: understand.ActionFill, Selector: "input.email", Description: "Email address"},
					{Type: understand.ActionFill, Selector: "input.password", Description: "Password"},
					{Type: understand.ActionClick, Selector: "button[type=submit]", Description: "Login"},
				},
			},
		},
	}

	forms := filler.findFormsInTree(tree)

	if len(forms) == 0 {
		t.Fatal("expected to find forms")
	}

	if forms[0].Selector != "body > form.login" {
		t.Errorf("wrong form selector: %s", forms[0].Selector)
	}

	t.Logf("Found form: %s", forms[0].Selector)
}

func TestFormFillerExtractFormSchema(t *testing.T) {
	node := &understand.SemanticNode{
		DOMSelector: "form#checkout",
		Actions: []understand.Action{
			{
				Type:        understand.ActionFill,
				Selector:    "input[name=card]",
				FillOptions: &understand.FillOptions{FieldType: understand.FieldTypeText},
			},
		},
		Children: []understand.SemanticNode{
			{
				DOMSelector: "form#checkout > div",
				Actions: []understand.Action{
					{
						Type:        understand.ActionFill,
						Selector:    "input[name=cvv]",
						FillOptions: &understand.FillOptions{FieldType: understand.FieldTypePassword},
					},
					{
						Type:        understand.ActionClick,
						Selector:    "button.pay",
						Description: "Submit payment",
					},
				},
			},
		},
	}

	filler := &SemanticFormFiller{}
	action := understand.Action{Type: understand.ActionFill}

	form := filler.extractFormFromNode(node, action)

	if form == nil {
		t.Fatal("expected form schema")
	}

	if form.Selector != "form#checkout" {
		t.Errorf("wrong form selector: %s", form.Selector)
	}

	if form.SubmitButton != "button.pay" {
		t.Errorf("wrong submit button: %s", form.SubmitButton)
	}
}

func TestFormFillerDefaultOptions(t *testing.T) {
	opts := DefaultFillOptions

	if !opts.HumanizeTyping {
		t.Error("expected humanized typing by default")
	}

	if opts.TypingSpeedMin >= opts.TypingSpeedMax {
		t.Error("invalid typing speed range")
	}

	if opts.FieldDelay == 0 {
		t.Error("expected field delay")
	}

	t.Logf("Typing speed: %v - %v, Field delay: %v",
		opts.TypingSpeedMin, opts.TypingSpeedMax, opts.FieldDelay)
}
