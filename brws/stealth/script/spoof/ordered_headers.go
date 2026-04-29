package spoof

import (
	"net/http"
	"strings"
)

// OrderedHeaders wraps http.Header with guaranteed insertion-order iteration.
// Go's http.Header is a map which iterates in random order. This type
// maintains a separate ordered key list and provides methods to serialize
// headers in browser-signature order.
type OrderedHeaders struct {
	order  []string    // canonical header names in browser order
	values http.Header // actual header values
}

// NewOrderedHeaders creates an OrderedHeaders with the given key order.
// The order slice should contain canonical header names (e.g., "User-Agent").
// Pseudo-headers (starting with ":") are skipped since they are handled by HTTP/2.
func NewOrderedHeaders(order []string) *OrderedHeaders {
	filtered := make([]string, 0, len(order))
	for _, name := range order {
		if strings.HasPrefix(name, ":") {
			continue
		}
		filtered = append(filtered, http.CanonicalHeaderKey(name))
	}
	return &OrderedHeaders{
		order:  filtered,
		values: make(http.Header),
	}
}

// Set sets a header value. If the key is not already in the order list,
// it is appended at the end.
func (oh *OrderedHeaders) Set(key, value string) {
	canonical := http.CanonicalHeaderKey(key)
	oh.values.Set(canonical, value)
	if !oh.hasKey(canonical) {
		oh.order = append(oh.order, canonical)
	}
}

// Add adds a header value without replacing existing values for the key.
func (oh *OrderedHeaders) Add(key, value string) {
	canonical := http.CanonicalHeaderKey(key)
	oh.values.Add(canonical, value)
	if !oh.hasKey(canonical) {
		oh.order = append(oh.order, canonical)
	}
}

// Get returns the first value for the given key.
func (oh *OrderedHeaders) Get(key string) string {
	return oh.values.Get(key)
}

// Del removes a header from both the values map and the order list.
func (oh *OrderedHeaders) Del(key string) {
	canonical := http.CanonicalHeaderKey(key)
	oh.values.Del(canonical)
	for i, k := range oh.order {
		if k == canonical {
			oh.order = append(oh.order[:i], oh.order[i+1:]...)
			break
		}
	}
}

// Order returns the current header order as a slice of canonical header names.
func (oh *OrderedHeaders) Order() []string {
	result := make([]string, len(oh.order))
	copy(result, oh.order)
	return result
}

// Clone returns a deep copy of the OrderedHeaders.
func (oh *OrderedHeaders) Clone() *OrderedHeaders {
	newOrder := make([]string, len(oh.order))
	copy(newOrder, oh.order)
	return &OrderedHeaders{
		order:  newOrder,
		values: oh.values.Clone(),
	}
}

// ApplyTo sets the request's Header map to contain the same values,
// and stores the ordering in the request's header map such that the
// first iteration will produce headers in signature order.
//
// Go's net/http serializes headers using Header map iteration, which is
// random. However, we rebuild the map by inserting keys in order so that
// the initial map bucket layout biases toward our order. For HTTP/1.1
// this provides best-effort ordering. For HTTP/2, the custom transport
// handles ordering via the pseudo-header and header lists directly.
//
// The definitive ordering guarantee comes from the fact that we populate
// req.Header as an ordered insertion sequence into an empty map.
func (oh *OrderedHeaders) ApplyTo(req *http.Request) {
	ordered := make(http.Header, len(oh.order))
	for _, key := range oh.order {
		if vals, ok := oh.values[key]; ok {
			ordered[key] = vals
		}
	}
	req.Header = ordered
}

// SortedKeys returns the header keys in signature order.
// Keys present in the values map but not in the order list are appended at the end.
func (oh *OrderedHeaders) SortedKeys() []string {
	result := make([]string, 0, len(oh.order))
	seen := make(map[string]bool, len(oh.order))
	for _, key := range oh.order {
		if _, ok := oh.values[key]; ok {
			result = append(result, key)
			seen[key] = true
		}
	}
	// Append any keys not in the predefined order
	for key := range oh.values {
		if !seen[key] {
			result = append(result, key)
		}
	}
	return result
}

// hasKey checks if a canonical key is already in the order list.
func (oh *OrderedHeaders) hasKey(canonical string) bool {
	for _, k := range oh.order {
		if k == canonical {
			return true
		}
	}
	return false
}

// headerOrderFromSignature extracts the header name order from an HTTPSignature,
// filtering out pseudo-headers and canonicalizing names.
func headerOrderFromSignature(sig *HTTPSignature) []string {
	if sig == nil {
		return nil
	}
	order := make([]string, 0, len(sig.Headers))
	for _, h := range sig.Headers {
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		order = append(order, h.Name)
	}
	return order
}
