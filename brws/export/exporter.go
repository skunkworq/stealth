package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Exporter interface {
	Export(items []map[string]any, w io.Writer) error
	Extension() string
}

type JsonExporter struct {
	Indent      bool
	EnsureASCII bool
}

func (e *JsonExporter) Export(items []map[string]any, w io.Writer) error {
	enc := json.NewEncoder(w)
	if e.Indent {
		enc.SetIndent("", "  ")
	}
	if e.EnsureASCII {
		enc.SetEscapeHTML(false)
	}
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

func (e *JsonExporter) Extension() string {
	return "json"
}

type JsonLinesExporter struct{}

func (e *JsonLinesExporter) Export(items []map[string]any, w io.Writer) error {
	for _, item := range items {
		data, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if _, err := w.Write(append(data, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func (e *JsonLinesExporter) Extension() string {
	return "jsonl"
}

type CsvExporter struct {
	IncludeHeaders bool
	Delimiter      rune
}

func (e *CsvExporter) Export(items []map[string]any, w io.Writer) error {
	if len(items) == 0 {
		return nil
	}

	writer := csv.NewWriter(w)
	if e.Delimiter != 0 {
		writer.Comma = e.Delimiter
	}
	defer writer.Flush()

	if e.IncludeHeaders {
		headers := getHeaders(items)
		if err := writer.Write(headers); err != nil {
			return err
		}
	}

	for _, item := range items {
		row := make([]string, 0)
		headers := getHeaders(items)
		for _, h := range headers {
			if val, ok := item[h]; ok {
				row = append(row, fmt.Sprintf("%v", val))
			} else {
				row = append(row, "")
			}
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (e *CsvExporter) Extension() string {
	return "csv"
}

func getHeaders(items []map[string]any) []string {
	headerSet := make(map[string]bool)
	for _, item := range items {
		for k := range item {
			headerSet[k] = true
		}
	}
	headers := make([]string, 0, len(headerSet))
	for k := range headerSet {
		headers = append(headers, k)
	}
	return headers
}

type XmlExporter struct{}

func (e *XmlExporter) Export(items []map[string]any, w io.Writer) error {
	_, err := w.Write([]byte("<items>\n"))
	if err != nil {
		return err
	}
	for _, item := range items {
		_, err := w.Write([]byte("  <item>\n"))
		if err != nil {
			return err
		}
		for k, v := range item {
			_, err := w.Write([]byte(fmt.Sprintf("    <%s>%v</%s>\n", k, v, k)))
			if err != nil {
				return err
			}
		}
		_, err = w.Write([]byte("  </item>\n"))
		if err != nil {
			return err
		}
	}
	_, err = w.Write([]byte("</items>\n"))
	return err
}

func (e *XmlExporter) Extension() string {
	return "xml"
}

func NewJsonExporter() Exporter {
	return &JsonExporter{Indent: true}
}

func NewJsonLinesExporter() Exporter {
	return &JsonLinesExporter{}
}

func NewCsvExporter() Exporter {
	return &CsvExporter{IncludeHeaders: true}
}

func NewXmlExporter() Exporter {
	return &XmlExporter{}
}

func ExportToFile(items []map[string]any, filename string) error {
	exporter := GetExporterForFile(filename)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return exporter.Export(items, f)
}

func GetExporterForFile(filename string) Exporter {
	switch {
	case hasSuffix(filename, ".jsonl"), hasSuffix(filename, ".ndjson"):
		return &JsonLinesExporter{}
	case hasSuffix(filename, ".csv"):
		return &CsvExporter{IncludeHeaders: true}
	case hasSuffix(filename, ".xml"):
		return &XmlExporter{}
	default:
		return &JsonExporter{Indent: true}
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
