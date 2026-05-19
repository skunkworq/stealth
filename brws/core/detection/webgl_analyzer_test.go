package detection

import (
	"testing"
)

func TestWebGLAnalyzer_PlatformMismatch(t *testing.T) {
	wa := NewWebGLAnalyzer()

	// Apple GPU claimed on Windows
	data := &WebGLData{
		Renderer: "Apple M2",
		Platform: "Win32",
	}

	result := wa.Analyze(data)
	if !result.Detected {
		t.Error("expected Apple GPU on Windows to be detected")
	}

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "renderer_platform_mismatch" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'renderer_platform_mismatch' indicator")
	}
}

func TestWebGLAnalyzer_ValidPlatformMatch(t *testing.T) {
	wa := NewWebGLAnalyzer()

	// NVIDIA on Windows = valid
	data := &WebGLData{
		Renderer: "NVIDIA GeForce RTX 4070",
		Platform: "Win32",
	}

	result := wa.Analyze(data)
	for _, ind := range result.Indicators {
		if ind.Check == "renderer_platform_mismatch" {
			t.Error("NVIDIA on Windows should not trigger platform mismatch")
		}
	}
}

func TestWebGLAnalyzer_SoftwareRenderer(t *testing.T) {
	wa := NewWebGLAnalyzer()

	tests := []struct {
		name     string
		renderer string
		want     bool
	}{
		{"SwiftShader", "Google SwiftShader", true},
		{"llvmpipe", "llvmpipe (LLVM 15.0)", true},
		{"NVIDIA", "NVIDIA GeForce RTX 4090", false},
		{"Apple", "Apple M2 Pro", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &WebGLData{Renderer: tt.renderer}
			result := wa.Analyze(data)

			found := false
			for _, ind := range result.Indicators {
				if ind.Check == "software_renderer" {
					found = true
					break
				}
			}

			if found != tt.want {
				t.Errorf("software renderer detection for %q: got %v, want %v", tt.renderer, found, tt.want)
			}
		})
	}
}

func TestWebGLAnalyzer_SpoofedRenderer(t *testing.T) {
	wa := NewWebGLAnalyzer()

	// Unmasked reveals SwiftShader, masked claims NVIDIA
	data := &WebGLData{
		Renderer:         "NVIDIA GeForce RTX 4070",
		UnmaskedRenderer: "Google SwiftShader",
	}

	result := wa.Analyze(data)
	if !result.Detected {
		t.Error("expected spoofed renderer to be detected")
	}

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "spoofed_renderer" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'spoofed_renderer' indicator")
	}
}

func TestWebGLAnalyzer_MissingWebGL2ModernGPU(t *testing.T) {
	wa := NewWebGLAnalyzer()

	data := &WebGLData{
		Renderer:        "NVIDIA GeForce RTX 4070",
		WebGL2Supported: false,
	}

	result := wa.Analyze(data)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "missing_webgl2_modern_gpu" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'missing_webgl2_modern_gpu' indicator for RTX 4070 without WebGL2")
	}
}

func TestWebGLAnalyzer_NilData(t *testing.T) {
	wa := NewWebGLAnalyzer()

	result := wa.Analyze(nil)
	if result.Detected {
		t.Error("nil data should not be detected")
	}
}
