package engine

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type FormData map[string]string

func (f FormData) Encode() string {
	parts := make([]string, 0, len(f))
	for k, v := range f {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "&")
}

type FormRequest struct {
	*Request
	FormData FormData
}

func NewFormRequest(url string, formData FormData) *FormRequest {
	return &FormRequest{
		Request: &Request{
			Method:  "POST",
			URL:     url,
			Headers: map[string][]string{},
			Body:    []byte(formData.Encode()),
		},
		FormData: formData,
	}
}

func (r *FormRequest) SetFormData(data FormData) {
	r.FormData = data
	r.Body = []byte(data.Encode())
	r.Request.Headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
}

func (r *FormRequest) SetField(name, value string) {
	if r.FormData == nil {
		r.FormData = make(FormData)
	}
	r.FormData[name] = value
	r.Body = []byte(r.FormData.Encode())
}

type JsonRequest struct {
	*Request
	Data interface{}
}

func NewJsonRequest(url string, data interface{}) *JsonRequest {
	body, _ := json.Marshal(data)
	return &JsonRequest{
		Request: &Request{
			Method:  "POST",
			URL:     url,
			Headers: map[string][]string{},
			Body:    body,
		},
		Data: data,
	}
}

func (r *JsonRequest) SetData(data interface{}) error {
	r.Data = data
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	r.Body = body
	r.Request.Headers["Content-Type"] = []string{"application/json"}
	return nil
}

func (r *JsonRequest) SetJsonData(key string, value interface{}) error {
	if r.Data == nil {
		r.Data = make(map[string]interface{})
	}
	if m, ok := r.Data.(map[string]interface{}); ok {
		m[key] = value
		return r.SetData(m)
	}
	return fmt.Errorf("JsonRequest data is not a map")
}

type RequestWithCallback struct {
	*Request
	Callback func(*Response) ([]Request, error)
}

func NewRequestWithCallback(url string, callback func(*Response) ([]Request, error)) *RequestWithCallback {
	return &RequestWithCallback{
		Request: &Request{
			Method:  "GET",
			URL:     url,
			Headers: map[string][]string{},
		},
		Callback: callback,
	}
}
