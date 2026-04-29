package semantic

import (
	"encoding/json"
	"io"
)

func encodeJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeJSON(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}

func decodeJSONReader(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

func encodeToJSONBytes(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
