package understand

import "errors"

var (
	ErrParseError     = errors.New("html parsing failed")
	ErrLLMError       = errors.New("llm request failed")
	ErrEmbeddingError = errors.New("embedding request failed")
	ErrCacheError     = errors.New("cache error")
	ErrSerialization  = errors.New("serialization error")
	ErrNodeNotFound   = errors.New("node not found")
	ErrBudgetExceeded = errors.New("budget exceeded")
	ErrHTTTPError     = errors.New("http error")
	ErrJSONError      = errors.New("json error")
)

type SemanticError struct {
	Type    error
	Message string
}

func (e *SemanticError) Error() string {
	return e.Type.Error() + ": " + e.Message
}

func NewParseError(msg string) error {
	return &SemanticError{Type: ErrParseError, Message: msg}
}

func NewLLMError(msg string) error {
	return &SemanticError{Type: ErrLLMError, Message: msg}
}

func NewEmbeddingError(msg string) error {
	return &SemanticError{Type: ErrEmbeddingError, Message: msg}
}

func NewCacheError(msg string) error {
	return &SemanticError{Type: ErrCacheError, Message: msg}
}

func NewSerializationError(msg string) error {
	return &SemanticError{Type: ErrSerialization, Message: msg}
}

func NewNodeNotFoundError(nodeID string) error {
	return &SemanticError{Type: ErrNodeNotFound, Message: nodeID}
}

func NewBudgetExceeded(requested, budget uint32) error {
	return &SemanticError{
		Type:    ErrBudgetExceeded,
		Message: "requested tokens exceed budget",
	}
}
