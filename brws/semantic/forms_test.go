package semantic

import (
	"encoding/json"
	"testing"
)

func TestExtractFormSchemas(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<body>
	<form action="/login" method="POST">
		<label for="email">Email Address</label>
		<input type="email" id="email" name="email" required placeholder="you@example.com">
		
		<label for="password">Password</label>
		<input type="password" id="password" name="password" required minlength="8">
		
		<label for="remember">Remember me</label>
		<input type="checkbox" id="remember" name="remember" value="1">
		
		<input type="hidden" name="csrf_token" value="abc123">
		
		<button type="submit">Log In</button>
	</form>

	<form action="/search" method="GET">
		<input type="search" name="q" placeholder="Search...">
		<select name="category">
			<option value="">All</option>
			<option value="products">Products</option>
			<option value="articles">Articles</option>
		</select>
		<input type="submit" value="Search">
	</form>

	<form action="/feedback" method="POST">
		<label for="message">Your feedback</label>
		<textarea id="message" name="message" rows="5" maxlength="500"></textarea>
		<button>Send</button>
	</form>
</body>
</html>`

	forms := ExtractFormSchemas(html)
	if len(forms) != 3 {
		t.Fatalf("Expected 3 forms, got %d", len(forms))
	}

	t.Run("login_form", func(t *testing.T) {
		form := forms[0]
		if form.Action != "/login" {
			t.Errorf("Expected action /login, got %s", form.Action)
		}
		if form.Method != "POST" {
			t.Errorf("Expected POST, got %s", form.Method)
		}
		if !form.HasCSRF {
			t.Error("Expected CSRF token detection")
		}
		if form.SubmitButton != "Log In" {
			t.Errorf("Expected submit button 'Log In', got %s", form.SubmitButton)
		}
		if len(form.Fields) != 4 {
			t.Errorf("Expected 4 fields, got %d", len(form.Fields))
		}

		emailField := findField(&form, "email")
		if emailField == nil {
			t.Fatal("email field not found")
		}
		if emailField.Type != "email" {
			t.Errorf("Expected type email, got %s", emailField.Type)
		}
		if emailField.Label != "Email Address" {
			t.Errorf("Expected label 'Email Address', got %s", emailField.Label)
		}
		if !emailField.Required {
			t.Error("Expected email to be required")
		}

		pwField := findField(&form, "password")
		if pwField == nil {
			t.Fatal("password field not found")
		}
		if pwField.MinLength != 8 {
			t.Errorf("Expected minlength 8, got %d", pwField.MinLength)
		}
	})

	t.Run("search_form", func(t *testing.T) {
		form := forms[1]
		if form.Action != "/search" {
			t.Errorf("Expected action /search, got %s", form.Action)
		}
		if form.Method != "GET" {
			t.Errorf("Expected GET, got %s", form.Method)
		}

		categoryField := findField(&form, "category")
		if categoryField == nil {
			t.Fatal("category field not found")
		}
		if categoryField.Type != "select" {
			t.Errorf("Expected type select, got %s", categoryField.Type)
		}
		if len(categoryField.Options) != 3 {
			t.Errorf("Expected 3 options, got %d", len(categoryField.Options))
		}
	})

	t.Run("feedback_form", func(t *testing.T) {
		form := forms[2]
		if form.Action != "/feedback" {
			t.Errorf("Expected action /feedback, got %s", form.Action)
		}

		msgField := findField(&form, "message")
		if msgField == nil {
			t.Fatal("message field not found")
		}
		if msgField.Type != "textarea" {
			t.Errorf("Expected type textarea, got %s", msgField.Type)
		}
		if msgField.MaxLength != 500 {
			t.Errorf("Expected maxlength 500, got %d", msgField.MaxLength)
		}
	})

	t.Run("json_serialization", func(t *testing.T) {
		data, err := json.MarshalIndent(forms, "", "  ")
		if err != nil {
			t.Fatalf("JSON marshal failed: %v", err)
		}
		t.Logf("Forms JSON:\n%s", string(data))
	})
}

func TestFormSchemaDescribe(t *testing.T) {
	form := &FormSchema{
		Action:  "/submit",
		Method:  "POST",
		HasCSRF: true,
		Fields: []FormField{
			{Name: "email", Type: "email", Required: true},
			{Name: "password", Type: "password", Required: true},
		},
	}

	desc := form.Describe()
	t.Log(desc)
}

func findField(form *FormSchema, name string) *FormField {
	for i := range form.Fields {
		if form.Fields[i].Name == name {
			return &form.Fields[i]
		}
	}
	return nil
}
