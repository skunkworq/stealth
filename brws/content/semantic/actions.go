package semantic

type FieldType string

const (
	FieldTypeText     FieldType = "text"
	FieldTypePassword FieldType = "password"
	FieldTypeEmail    FieldType = "email"
	FieldTypeNumber   FieldType = "number"
	FieldTypeSearch   FieldType = "search"
	FieldTypeURL      FieldType = "url"
	FieldTypeTextarea FieldType = "textarea"
)

type Action struct {
	Type        ActionType `json:"type"`
	Selector    string     `json:"selector"`
	Description string     `json:"description,omitempty"`

	FillOptions *FillOptions `json:"fill_options,omitempty"`
	SelectOpts  *SelectOpts  `json:"select_options,omitempty"`
	ToggleState *bool        `json:"toggle_state,omitempty"`
}

type ActionType string

const (
	ActionClick  ActionType = "click"
	ActionFill   ActionType = "fill"
	ActionSelect ActionType = "select"
	ActionToggle ActionType = "toggle"
)

type FillOptions struct {
	FieldType FieldType `json:"field_type"`
}

type SelectOpts struct {
	Options []string `json:"options"`
}

func (a *Action) GetSelector() string { return a.Selector }

func (a *Action) GetDescription() string { return a.Description }

type InteractiveElement struct {
	Selector   string            `json:"selector"`
	Tag        string            `json:"tag"`
	Attrs      map[string]string `json:"attrs"`
	ActionType string            `json:"action_type"`
}
