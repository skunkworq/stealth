package langextract

import "fmt"

// LXError is the base error type for this package.
type LXError struct {
	Op  string
	Msg string
}

func (e *LXError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Op == "" {
		return e.Msg
	}
	if e.Msg == "" {
		return e.Op
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Msg)
}

// InferenceError represents provider runtime/config failures.
type InferenceError struct{ *LXError }

// InferenceConfigError represents bad provider/model configuration.
type InferenceConfigError struct{ *LXError }

// InferenceOutputError represents missing/invalid inference outputs.
type InferenceOutputError struct{ *LXError }

// InvalidDocumentError represents invalid document input state.
type InvalidDocumentError struct{ *LXError }

// FormatError represents parsing/formatting failures.
type FormatError struct{ *LXError }

// ResolverParsingError represents resolver parse failures.
type ResolverParsingError struct{ *LXError }

func newErr(op, msg string) *LXError { return &LXError{Op: op, Msg: msg} }
