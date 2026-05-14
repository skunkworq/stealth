package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type pythonDiffFixture struct {
	ParseResolveCases []pythonParseResolveCase `json:"parse_resolve_cases"`
	AlignCases        []pythonAlignCase        `json:"align_cases"`
	ChunkCases        []pythonChunkCase        `json:"chunk_cases"`
}

type pythonParseResolveCase struct {
	Name              string `json:"name"`
	FormatType        string `json:"format_type"`
	UseWrapper        bool   `json:"use_wrapper"`
	WrapperKey        string `json:"wrapper_key"`
	UseFences         bool   `json:"use_fences"`
	StrictFences      bool   `json:"strict_fences"`
	AllowTopLevelList bool   `json:"allow_top_level_list"`
	AttributeSuffix   string `json:"attribute_suffix"`
	IndexSuffix       string `json:"index_suffix"`
	Strict            bool   `json:"strict"`
	Input             string `json:"input"`
}

type pythonAlignCase struct {
	Name                    string                 `json:"name"`
	SourceText              string                 `json:"source_text"`
	EnableFuzzyAlignment    bool                   `json:"enable_fuzzy_alignment"`
	FuzzyAlignmentThreshold float64                `json:"fuzzy_alignment_threshold"`
	AcceptMatchLesser       bool                   `json:"accept_match_lesser"`
	Extractions             []pythonExtractionCase `json:"extractions"`
}

type pythonExtractionCase struct {
	Class string `json:"class"`
	Text  string `json:"text"`
}

type pythonChunkCase struct {
	Name          string `json:"name"`
	Text          string `json:"text"`
	MaxCharBuffer int    `json:"max_char_buffer"`
}

type parityExtraction struct {
	Class      string         `json:"class"`
	Text       string         `json:"text"`
	Index      int            `json:"index"`
	Group      int            `json:"group"`
	Attributes map[string]any `json:"attributes,omitempty"`

	Alignment  string `json:"alignment,omitempty"`
	TokenStart int    `json:"token_start"`
	TokenEnd   int    `json:"token_end"`
	CharStart  int    `json:"char_start"`
	CharEnd    int    `json:"char_end"`
}

type parityChunk struct {
	Text       string `json:"text"`
	TokenStart int    `json:"token_start"`
	TokenEnd   int    `json:"token_end"`
	CharStart  int    `json:"char_start"`
	CharEnd    int    `json:"char_end"`
}

type pythonDiffResult struct {
	ParseResolve map[string]struct {
		Extractions []parityExtraction `json:"extractions,omitempty"`
		Error       string             `json:"error,omitempty"`
	} `json:"parse_resolve"`
	Align map[string]struct {
		Extractions []parityExtraction `json:"extractions,omitempty"`
		Error       string             `json:"error,omitempty"`
	} `json:"align"`
	Chunk map[string]struct {
		Chunks []parityChunk `json:"chunks,omitempty"`
		Error  string        `json:"error,omitempty"`
	} `json:"chunk"`
}

func TestPythonParityContract(t *testing.T) {
	if os.Getenv("LANGEXTRACT_DIFF_PYTHON") != "1" {
		t.Skip("set LANGEXTRACT_DIFF_PYTHON=1 to run Python-vs-Go differential tests")
	}

	fixturePath := filepath.Join("testdata", "diff", "python_parity_cases.json")
	var fixture pythonDiffFixture
	loadJSONFixture(t, fixturePath, &fixture)

	pythonOut := runPythonDiff(t, fixture)

	t.Run("parse_resolve", func(t *testing.T) {
		for _, c := range fixture.ParseResolveCases {
			handler := buildGoldenHandler(t, goldenHandlerConfig{
				FormatType:        c.FormatType,
				UseWrapper:        c.UseWrapper,
				WrapperKey:        c.WrapperKey,
				UseFences:         c.UseFences,
				StrictFences:      c.StrictFences,
				AllowTopLevelList: c.AllowTopLevelList,
				AttributeSuffix:   c.AttributeSuffix,
			})
			resolver := NewResolver(handler)
			resolver.ExtractionIndexSuffix = c.IndexSuffix
			resolver.Strict = c.Strict

			goEntry := struct {
				Extractions []parityExtraction `json:"extractions,omitempty"`
				Error       string             `json:"error,omitempty"`
			}{}

			extractions, err := resolver.Resolve(c.Input, false)
			if err != nil {
				goEntry.Error = err.Error()
			} else {
				goEntry.Extractions = normalizeParseExtractions(extractions)
			}

			pyEntry, ok := pythonOut.ParseResolve[c.Name]
			if !ok {
				t.Fatalf("missing python parse_resolve case %q", c.Name)
			}
			if !jsonEqual(goEntry, pyEntry) {
				goJSON, _ := json.MarshalIndent(goEntry, "", "  ")
				pyJSON, _ := json.MarshalIndent(pyEntry, "", "  ")
				t.Fatalf("parse_resolve mismatch for case %q\nGo:\n%s\nPython:\n%s", c.Name, string(goJSON), string(pyJSON))
			}
		}
	})

	t.Run("align", func(t *testing.T) {
		for _, c := range fixture.AlignCases {
			extractions := make([]Extraction, 0, len(c.Extractions))
			for _, ex := range c.Extractions {
				extractions = append(extractions, Extraction{
					ExtractionClass: ex.Class,
					ExtractionText:  ex.Text,
				})
			}

			opts := DefaultAlignOptions()
			opts.EnableFuzzyAlignment = c.EnableFuzzyAlignment
			opts.FuzzyAlignmentThreshold = c.FuzzyAlignmentThreshold
			opts.AcceptMatchLesser = c.AcceptMatchLesser

			resolver := NewResolver(NewFormatHandler())
			aligned := resolver.Align(extractions, c.SourceText, 0, 0, opts)
			goEntry := struct {
				Extractions []parityExtraction `json:"extractions,omitempty"`
				Error       string             `json:"error,omitempty"`
			}{
				Extractions: normalizeAlignedExtractions(aligned),
			}

			pyEntry, ok := pythonOut.Align[c.Name]
			if !ok {
				t.Fatalf("missing python align case %q", c.Name)
			}
			if !jsonEqual(goEntry, pyEntry) {
				goJSON, _ := json.MarshalIndent(goEntry, "", "  ")
				pyJSON, _ := json.MarshalIndent(pyEntry, "", "  ")
				t.Fatalf("align mismatch for case %q\nGo:\n%s\nPython:\n%s", c.Name, string(goJSON), string(pyJSON))
			}
		}
	})

	t.Run("chunk", func(t *testing.T) {
		for _, c := range fixture.ChunkCases {
			iter, err := NewChunkIterator(c.Text, c.MaxCharBuffer, DefaultTokenizer, nil)
			if err != nil {
				t.Fatalf("failed to create chunk iterator for case %q: %v", c.Name, err)
			}

			chunks := make([]parityChunk, 0)
			for {
				ch, ok, err := iter.Next()
				if err != nil {
					t.Fatalf("chunk iteration failed for case %q: %v", c.Name, err)
				}
				if !ok {
					break
				}
				text, err := ch.ChunkText()
				if err != nil {
					t.Fatalf("chunk text failed for case %q: %v", c.Name, err)
				}
				ci, err := ch.CharInterval()
				if err != nil {
					t.Fatalf("chunk char interval failed for case %q: %v", c.Name, err)
				}
				chunks = append(chunks, parityChunk{
					Text:       text,
					TokenStart: ch.TokenInterval.StartIndex,
					TokenEnd:   ch.TokenInterval.EndIndex,
					CharStart:  ci.StartPos,
					CharEnd:    ci.EndPos,
				})
			}

			goEntry := struct {
				Chunks []parityChunk `json:"chunks,omitempty"`
				Error  string        `json:"error,omitempty"`
			}{
				Chunks: chunks,
			}

			pyEntry, ok := pythonOut.Chunk[c.Name]
			if !ok {
				t.Fatalf("missing python chunk case %q", c.Name)
			}
			if !jsonEqual(goEntry, pyEntry) {
				goJSON, _ := json.MarshalIndent(goEntry, "", "  ")
				pyJSON, _ := json.MarshalIndent(pyEntry, "", "  ")
				t.Fatalf("chunk mismatch for case %q\nGo:\n%s\nPython:\n%s", c.Name, string(goJSON), string(pyJSON))
			}
		}
	})
}

func normalizeParseExtractions(extractions []Extraction) []parityExtraction {
	out := make([]parityExtraction, 0, len(extractions))
	for _, ex := range extractions {
		out = append(out, parityExtraction{
			Class:      ex.ExtractionClass,
			Text:       ex.ExtractionText,
			Index:      ex.ExtractionIndex,
			Group:      ex.GroupIndex,
			Attributes: ex.Attributes,
			TokenStart: -1,
			TokenEnd:   -1,
			CharStart:  -1,
			CharEnd:    -1,
		})
	}
	return out
}

func normalizeAlignedExtractions(extractions []Extraction) []parityExtraction {
	out := make([]parityExtraction, 0, len(extractions))
	for _, ex := range extractions {
		item := parityExtraction{
			Class:      ex.ExtractionClass,
			Text:       ex.ExtractionText,
			Index:      ex.ExtractionIndex,
			Group:      ex.GroupIndex,
			Attributes: ex.Attributes,
			Alignment:  string(ex.Alignment),
			TokenStart: -1,
			TokenEnd:   -1,
			CharStart:  -1,
			CharEnd:    -1,
		}
		if ex.TokenInterval != nil {
			item.TokenStart = ex.TokenInterval.StartIndex
			item.TokenEnd = ex.TokenInterval.EndIndex
		}
		if ex.CharInterval != nil {
			item.CharStart = ex.CharInterval.StartPos
			item.CharEnd = ex.CharInterval.EndPos
		}
		out = append(out, item)
	}
	return out
}

func runPythonDiff(t *testing.T, fixture pythonDiffFixture) pythonDiffResult {
	t.Helper()

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("failed to locate repo root: %v", err)
	}

	pythonBin := os.Getenv("LANGEXTRACT_PYTHON")
	if strings.TrimSpace(pythonBin) == "" {
		pythonBin = "python3"
	}

	payloadBytes, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("failed to marshal python diff fixture: %v", err)
	}

	cmd := exec.Command(pythonBin, "-c", pythonDiffScript)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repoRoot, "docs", "langextract"))
	cmd.Stdin = bytes.NewReader(payloadBytes)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python diff execution failed: %v\noutput:\n%s", err, string(out))
	}

	var parsed pythonDiffResult
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to parse python diff output: %v\noutput:\n%s", err, string(out))
	}
	return parsed
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	current := wd
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", fmt.Errorf("go.mod not found from %s", wd)
}

const pythonDiffScript = `
import json
import os
import sys
import types

_allow_stubs = os.environ.get("LANGEXTRACT_DIFF_STRICT", "0") != "1"

# Avoid importing heavy optional modules through langextract/__init__.py.
if _allow_stubs and "langextract.visualization" not in sys.modules:
    sys.modules["langextract.visualization"] = types.ModuleType("langextract.visualization")
if _allow_stubs and "langextract.extraction" not in sys.modules:
    _extraction_stub = types.ModuleType("langextract.extraction")
    _extraction_stub.extract = lambda *args, **kwargs: None
    sys.modules["langextract.extraction"] = _extraction_stub

# Optional dependencies are not required for these differential tests.
if _allow_stubs and "absl" not in sys.modules:
    _absl = types.ModuleType("absl")
    _absl_logging = types.ModuleType("absl.logging")
    for _fn in ("debug", "info", "warning", "exception", "error"):
        setattr(_absl_logging, _fn, lambda *args, **kwargs: None)
    _absl.logging = _absl_logging
    sys.modules["absl"] = _absl
    sys.modules["absl.logging"] = _absl_logging

if _allow_stubs and "more_itertools" not in sys.modules:
    _mit = types.ModuleType("more_itertools")
    def _batched(iterable, n):
        batch = []
        for item in iterable:
            batch.append(item)
            if len(batch) == n:
                yield tuple(batch)
                batch = []
        if batch:
            yield tuple(batch)
    _mit.batched = _batched
    sys.modules["more_itertools"] = _mit

if _allow_stubs and "regex" not in sys.modules:
    import re as _re
    _regex = types.ModuleType("regex")

    _replacements = {
        r"\p{Is_Han}": r"[\u4e00-\u9fff]",
        r"\p{Is_Hiragana}": r"[\u3040-\u309f]",
        r"\p{Is_Katakana}": r"[\u30a0-\u30ff]",
        r"\p{Is_Hangul}": r"[\uac00-\ud7af]",
        r"\p{Is_Thai}": r"[\u0e00-\u0e7f]",
        r"\p{Is_Lao}": r"[\u0e80-\u0eff]",
        r"\p{Is_Khmer}": r"[\u1780-\u17ff]",
        r"\p{Is_Myanmar}": r"[\u1000-\u109f]",
    }

    def _sanitize_pattern(pattern):
        for key, value in _replacements.items():
            pattern = pattern.replace(key, value)
        pattern = _re.sub(r"\\p\{[^}]+\}", ".", pattern)
        pattern = pattern.replace(r"\X", ".")
        return pattern

    def _compile(pattern, flags=0):
        return _re.compile(_sanitize_pattern(pattern), flags)

    def _fullmatch(pattern, string, flags=0):
        if hasattr(pattern, "fullmatch"):
            return pattern.fullmatch(string)
        return _re.fullmatch(_sanitize_pattern(pattern), string, flags)

    _regex.compile = _compile
    _regex.fullmatch = _fullmatch
    _regex.MULTILINE = _re.MULTILINE
    _regex.DOTALL = _re.DOTALL
    _regex.IGNORECASE = _re.IGNORECASE
    sys.modules["regex"] = _regex

if _allow_stubs and "yaml" not in sys.modules:
    _yaml = types.ModuleType("yaml")
    class _YAMLError(Exception):
        pass
    def _safe_load(value):
        try:
            return json.loads(value)
        except Exception as exc:
            raise _YAMLError(str(exc))
    def _safe_dump(value, default_flow_style=False, sort_keys=False):
        return json.dumps(value, ensure_ascii=False)
    _yaml.safe_load = _safe_load
    _yaml.safe_dump = _safe_dump
    _yaml.YAMLError = _YAMLError
    sys.modules["yaml"] = _yaml

from langextract import chunking
from langextract import resolver as resolver_lib
from langextract.core import data
from langextract.core import format_handler as fh
from langextract.core import tokenizer as tokenizer_lib


def normalize_extraction(ex):
    token_start = -1
    token_end = -1
    char_start = -1
    char_end = -1
    if ex.token_interval is not None:
        token_start = ex.token_interval.start_index
        token_end = ex.token_interval.end_index
    if ex.char_interval is not None:
        char_start = ex.char_interval.start_pos
        char_end = ex.char_interval.end_pos
    return {
        "class": ex.extraction_class,
        "text": ex.extraction_text,
        "index": ex.extraction_index if ex.extraction_index is not None else 0,
        "group": ex.group_index if ex.group_index is not None else 0,
        "attributes": ex.attributes,
        "alignment": ex.alignment_status.value if ex.alignment_status else "",
        "token_start": token_start,
        "token_end": token_end,
        "char_start": char_start,
        "char_end": char_end,
    }


payload = json.load(sys.stdin)
result = {"parse_resolve": {}, "align": {}, "chunk": {}}

for case in payload.get("parse_resolve_cases", []):
    name = case["name"]
    try:
        format_type = data.FormatType.JSON if case["format_type"] == "json" else data.FormatType.YAML
        handler = fh.FormatHandler(
            format_type=format_type,
            use_wrapper=case["use_wrapper"],
            wrapper_key=case.get("wrapper_key"),
            use_fences=case["use_fences"],
            strict_fences=case["strict_fences"],
            allow_top_level_list=case["allow_top_level_list"],
            attribute_suffix=case.get("attribute_suffix", data.ATTRIBUTE_SUFFIX),
        )
        parsed = handler.parse_output(case["input"], strict=bool(case.get("strict", False)))
        suffix = case.get("index_suffix") or None
        resolver = resolver_lib.Resolver(format_handler=handler, extraction_index_suffix=suffix)
        extractions = resolver.extract_ordered_extractions(parsed)
        result["parse_resolve"][name] = {
            "extractions": [normalize_extraction(ex) for ex in extractions]
        }
    except Exception as exc:
        result["parse_resolve"][name] = {"error": str(exc)}

for case in payload.get("align_cases", []):
    name = case["name"]
    try:
        groups = []
        for ex in case["extractions"]:
            groups.append([data.Extraction(extraction_class=ex["class"], extraction_text=ex["text"])])
        aligner = resolver_lib.WordAligner()
        aligned = aligner.align_extractions(
            groups,
            case["source_text"],
            token_offset=0,
            char_offset=0,
            enable_fuzzy_alignment=bool(case.get("enable_fuzzy_alignment", True)),
            fuzzy_alignment_threshold=float(case.get("fuzzy_alignment_threshold", 0.75)),
            accept_match_lesser=bool(case.get("accept_match_lesser", True)),
        )
        flattened = []
        for grp in aligned:
            for ex in grp:
                flattened.append(normalize_extraction(ex))
        result["align"][name] = {"extractions": flattened}
    except Exception as exc:
        result["align"][name] = {"error": str(exc)}

for case in payload.get("chunk_cases", []):
    name = case["name"]
    try:
        tok = tokenizer_lib.tokenize(case["text"])
        it = chunking.ChunkIterator(
            text=tok,
            max_char_buffer=int(case["max_char_buffer"]),
            tokenizer_impl=tokenizer_lib.RegexTokenizer(),
        )
        chunks = []
        for chunk in it:
            ci = chunk.char_interval
            chunks.append({
                "text": chunk.chunk_text,
                "token_start": chunk.token_interval.start_index,
                "token_end": chunk.token_interval.end_index,
                "char_start": ci.start_pos,
                "char_end": ci.end_pos,
            })
        result["chunk"][name] = {"chunks": chunks}
    except Exception as exc:
        result["chunk"][name] = {"error": str(exc)}

sys.stdout.write(json.dumps(result, ensure_ascii=False))
`
