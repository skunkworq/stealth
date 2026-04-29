package integration

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/skunkworq/stealth/brws/content/semantic"
	"github.com/skunkworq/stealth/brws/stealth"
)

type SmartNavigator struct {
	client    *stealth.Client
	navigator *SemanticNavigator
}

type NavigationIntent struct {
	Description string
	ActionType  string // "click", "navigate", "submit", etc.
	Priority    int
}

type IntentResult struct {
	Found        bool
	Selector     string
	Action       *semantic.Action
	Confidence   float32
	Alternatives []*semantic.Action
}

func NewSmartNavigator(client *stealth.Client, nav *SemanticNavigator) *SmartNavigator {
	return &SmartNavigator{
		client:    client,
		navigator: nav,
	}
}

func (s *SmartNavigator) NavigateByIntent(ctx context.Context, url string, intent NavigationIntent) (*IntentResult, error) {
	result, err := s.navigator.NavigateWithIntent(ctx, url, intent.Description)
	if err != nil {
		return nil, err
	}

	tree := result.SemanticTree
	if tree == nil {
		return nil, fmt.Errorf("no semantic tree extracted")
	}

	intentResult := s.findBestIntentMatch(tree, intent)

	return intentResult, nil
}

func (s *SmartNavigator) findBestIntentMatch(tree *semantic.SemanticTree, intent NavigationIntent) *IntentResult {
	allActions := s.collectActions(tree)

	scored := make([]struct {
		action *semantic.Action
		score  float32
	}, 0)

	intentLower := strings.ToLower(intent.Description)
	intentWords := strings.Fields(intentLower)

	for _, action := range allActions {
		score := s.scoreIntentMatch(action, intentWords, intent.ActionType)
		if score > 0 {
			scored = append(scored, struct {
				action *semantic.Action
				score  float32
			}{action: action, score: score})
		}
	}

	if len(scored) == 0 {
		return &IntentResult{Found: false}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	result := &IntentResult{
		Found:      true,
		Selector:   scored[0].action.Selector,
		Action:     scored[0].action,
		Confidence: scored[0].score,
	}

	if len(scored) > 1 {
		result.Alternatives = make([]*semantic.Action, 0)
		for i := 1; i < len(scored) && i < 5; i++ {
			result.Alternatives = append(result.Alternatives, scored[i].action)
		}
	}

	return result
}

func (s *SmartNavigator) collectActions(tree *semantic.SemanticTree) []*semantic.Action {
	actions := make([]*semantic.Action, 0)

	for _, node := range tree.AllNodes() {
		for i := range node.Actions {
			actions = append(actions, &node.Actions[i])
		}
	}

	return actions
}

func (s *SmartNavigator) scoreIntentMatch(action *semantic.Action, intentWords []string, actionType string) float32 {
	score := float32(0.0)

	descLower := strings.ToLower(action.Description)
	descWords := strings.Fields(descLower)

	for _, intentWord := range intentWords {
		for _, descWord := range descWords {
			if intentWord == descWord {
				score += 10.0
			} else if strings.Contains(descWord, intentWord) || strings.Contains(intentWord, descWord) {
				score += 5.0
			}
		}
	}

	for _, intentWord := range intentWords {
		if strings.Contains(action.Selector, intentWord) {
			score += 3.0
		}
	}

	if actionType != "" && string(action.Type) == actionType {
		score += 8.0
	}

	if action.Type == semantic.ActionClick && (strings.Contains(descLower, "button") || strings.Contains(descLower, "link")) {
		score += 2.0
	}

	return score
}

func (s *SmartNavigator) ClickBestMatch(ctx context.Context, url string, intent NavigationIntent) error {
	result, err := s.NavigateByIntent(ctx, url, intent)
	if err != nil {
		return err
	}

	if !result.Found {
		return fmt.Errorf("no matching action found for intent: %s", intent.Description)
	}

	if s.client != nil {
		return s.client.ClickSelector(ctx, result.Selector)
	}

	return nil
}

func (s *SmartNavigator) ClickAlternative(ctx context.Context, alternatives []*semantic.Action, idx int) error {
	if idx >= len(alternatives) {
		return fmt.Errorf("alternative index out of range")
	}

	if s.client == nil {
		return fmt.Errorf("no stealth client configured")
	}

	return s.client.ClickSelector(ctx, alternatives[idx].Selector)
}

func (s *SmartNavigator) FindByText(ctx context.Context, url, text string) (*IntentResult, error) {
	return s.NavigateByIntent(ctx, url, NavigationIntent{
		Description: text,
		Priority:    5,
	})
}

func (s *SmartNavigator) FindButton(ctx context.Context, url, description string) (*IntentResult, error) {
	return s.NavigateByIntent(ctx, url, NavigationIntent{
		Description: description,
		ActionType:  string(semantic.ActionClick),
		Priority:    8,
	})
}

func (s *SmartNavigator) FindLink(ctx context.Context, url, linkText string) (*IntentResult, error) {
	return s.NavigateByIntent(ctx, url, NavigationIntent{
		Description: linkText + " link",
		ActionType:  string(semantic.ActionClick),
		Priority:    7,
	})
}

func (s *SmartNavigator) FindForm(ctx context.Context, url, formType string) (*IntentResult, error) {
	return s.NavigateByIntent(ctx, url, NavigationIntent{
		Description: formType + " form",
		ActionType:  string(semantic.ActionFill),
		Priority:    6,
	})
}

func (s *SmartNavigator) CascadeClick(ctx context.Context, url string, intents []NavigationIntent) error {
	for i, intent := range intents {
		result, err := s.NavigateByIntent(ctx, url, intent)
		if err != nil {
			return fmt.Errorf("step %d: %w", i, err)
		}

		if !result.Found {
			return fmt.Errorf("step %d: no match for intent: %s", i, intent.Description)
		}

		var clickErr error
		if i == 0 {
			clickErr = s.client.ClickSelector(ctx, result.Selector)
		} else {
			// For subsequent clicks, might need to wait for page or re-extract
			clickErr = s.client.ClickSelector(ctx, result.Selector)
		}

		if clickErr != nil {
			return fmt.Errorf("step %d: click failed: %w", i, clickErr)
		}

		if i < len(intents)-1 {
			// Could add wait for navigation here
		}
	}

	return nil
}

func (s *SmartNavigator) Close() error {
	return nil
}
