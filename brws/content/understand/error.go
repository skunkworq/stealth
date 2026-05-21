package understand

import (
	"errors"
	"fmt"
)

var (
	ErrParseError     = errors.New("html parsing failed")
	ErrLLMError       = errors.New("llm request failed")
	ErrEmbeddingError = errors.New("embedding request failed")
	ErrCacheError     = errors.New("cache error")
	ErrSerialization  = errors.New("serialization error")
	ErrNodeNotFound   = errors.New("node not found")
	ErrBudgetExceeded = errors.New("budget exceeded")
	ErrHTTPError      = errors.New("http error")
	ErrJSONError      = errors.New("json error")
)

type SemanticError struct {
	Type    error
	Message string
	cause   error
}

func (e *SemanticError) Error() string {
	if e.cause != nil {
		return e.Type.Error() + ": " + e.Message + ": " + e.cause.Error()
	}
	return e.Type.Error() + ": " + e.Message
}

// Unwrap returns the sentinel error type, enabling errors.Is checks against ErrCacheError etc.
func (e *SemanticError) Unwrap() error {
	return e.Type
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

func NewCacheError(msg string, cause ...error) error {
	e := &SemanticError{Type: ErrCacheError, Message: msg}
	if len(cause) > 0 {
		e.cause = cause[0]
	}
	return e
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
		Message: fmt.Sprintf("requested %d tokens exceeds budget of %d", requested, budget),
	}
}
