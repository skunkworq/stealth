package challenge

import "testing"

func TestClassifyChallenge_CloudflareTurnstile(t *testing.T) {
	html := `<html><head></head><body>
		<div class="cf-turnstile" data-sitekey="0x4AAAA">
			<iframe src="https://challenges.cloudflare.com/turnstile/v0/api.js"></iframe>
		</div>
	</body></html>`

	sig := ClassifyChallenge([]byte(html), map[string][]string{
		"Server": {"cloudflare"},
	})

	if sig.Provider != "cloudflare" {
		t.Errorf("provider = %s, want cloudflare", sig.Provider)
	}
	if sig.Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
	t.Logf("Turnstile: provider=%s interaction=%s confidence=%.2f indicators=%v",
		sig.Provider, sig.Interaction, sig.Confidence, sig.Indicators)
}

func TestClassifyChallenge_ReCaptchaV2Grid(t *testing.T) {
	html := `<html><body>
		<div class="g-recaptcha" data-sitekey="6Le-wvkS">
			<div class="rc-imageselect">
				<div class="rc-image-tile"></div>
				<div class="rc-image-tile"></div>
				<div class="rc-image-tile"></div>
				<div class="rc-image-tile"></div>
				<div class="rc-image-tile"></div>
				<div class="rc-image-tile"></div>
				<div class="rc-image-tile"></div>
				<div class="rc-image-tile"></div>
				<div class="rc-image-tile"></div>
			</div>
		</div>
	</body></html>`

	sig := ClassifyChallenge([]byte(html), nil)

	if sig.Provider != "recaptcha" {
		t.Errorf("provider = %s, want recaptcha", sig.Provider)
	}
	if sig.Interaction != InteractionGridSelect {
		t.Errorf("interaction = %s, want grid_select", sig.Interaction)
	}
	if sig.Confidence < 0.7 {
		t.Errorf("confidence = %.2f, want >= 0.7", sig.Confidence)
	}
	t.Logf("reCAPTCHA v2: interaction=%s confidence=%.2f indicators=%v",
		sig.Interaction, sig.Confidence, sig.Indicators)
}

func TestClassifyChallenge_ReCaptchaCheckbox(t *testing.T) {
	html := `<html><body>
		<div class="g-recaptcha" data-sitekey="6Le-wvkS">
			<div class="rc-anchor rc-anchor-checkbox">
				<div class="recaptcha-checkbox-border"></div>
			</div>
		</div>
	</body></html>`

	sig := ClassifyChallenge([]byte(html), nil)

	if sig.Provider != "recaptcha" {
		t.Errorf("provider = %s, want recaptcha", sig.Provider)
	}
	if sig.Interaction != InteractionCheckbox {
		t.Errorf("interaction = %s, want checkbox", sig.Interaction)
	}
	t.Logf("Checkbox: interaction=%s confidence=%.2f", sig.Interaction, sig.Confidence)
}

func TestClassifyChallenge_SliderDrag(t *testing.T) {
	html := `<html><body>
		<div class="captcha-container">
			<div class="slide-track">
				<div class="slider" draggable="true"></div>
			</div>
			<div class="slidecontainer">
				<input type="range" min="0" max="300">
			</div>
		</div>
	</body></html>`

	sig := ClassifyChallenge([]byte(html), nil)

	if sig.Interaction != InteractionDragHorizontal {
		t.Errorf("interaction = %s, want drag_horizontal", sig.Interaction)
	}
	if sig.Confidence < 0.5 {
		t.Errorf("confidence = %.2f, want >= 0.5", sig.Confidence)
	}
	t.Logf("Slider: interaction=%s confidence=%.2f indicators=%v",
		sig.Interaction, sig.Confidence, sig.Indicators)
}

func TestClassifyChallenge_RotateChallenge(t *testing.T) {
	html := `<html><body>
		<div class="challenge-container">
			<svg viewBox="0 0 300 300">
				<circle cx="150" cy="150" r="100" transform="rotate(45)"/>
				<text>Rotate to match the angle</text>
			</svg>
			<div class="dial-handle"></div>
		</div>
	</body></html>`

	sig := ClassifyChallenge([]byte(html), nil)

	if sig.Interaction != InteractionRotate {
		t.Errorf("interaction = %s, want rotate", sig.Interaction)
	}
	t.Logf("Rotate: interaction=%s confidence=%.2f indicators=%v",
		sig.Interaction, sig.Confidence, sig.Indicators)
}

func TestClassifyChallenge_ButtonOrientation(t *testing.T) {
	html := `<html><body>
		<div class="captcha">
			<img src="object.png"/>
			<button class="btn-left arrow">←</button>
			<button class="btn-right arrow">→</button>
		</div>
	</body></html>`

	sig := ClassifyChallenge([]byte(html), nil)

	if sig.Interaction != InteractionClickButtons {
		t.Errorf("interaction = %s, want click_buttons", sig.Interaction)
	}
	t.Logf("Buttons: interaction=%s confidence=%.2f indicators=%v",
		sig.Interaction, sig.Confidence, sig.Indicators)
}

func TestClassifyChallenge_CloudflareJSChallenge(t *testing.T) {
	html := `<html><head>
		<script>cf-chl-bypass</script>
	</head><body>
		<div id="challenge-platform">
			<noscript>Enable JavaScript</noscript>
			<div id="jschl-answer"></div>
		</div>
	</body></html>`

	sig := ClassifyChallenge([]byte(html), map[string][]string{
		"Server": {"cloudflare"},
	})

	if sig.Provider != "cloudflare" {
		t.Errorf("provider = %s, want cloudflare", sig.Provider)
	}
	if sig.Interaction != InteractionWait {
		t.Errorf("interaction = %s, want wait", sig.Interaction)
	}
	t.Logf("JS Challenge: interaction=%s confidence=%.2f indicators=%v",
		sig.Interaction, sig.Confidence, sig.Indicators)
}

func TestClassifyChallenge_UnknownProvider(t *testing.T) {
	html := `<html><body>
		<p>Please verify you are human</p>
		<div class="custom-captcha">
			<canvas id="puzzle"></canvas>
		</div>
	</body></html>`

	sig := ClassifyChallenge([]byte(html), nil)

	if sig.Provider != "unknown" {
		t.Errorf("provider = %s, want unknown", sig.Provider)
	}
	t.Logf("Unknown: provider=%s interaction=%s confidence=%.2f fingerprint=%s",
		sig.Provider, sig.Interaction, sig.Confidence, sig.Fingerprint)
}

func TestClassifyChallenge_StableFingerprint(t *testing.T) {
	html := `<div class="cf-turnstile" data-sitekey="abc"></div>`

	sig1 := ClassifyChallenge([]byte(html), nil)
	sig2 := ClassifyChallenge([]byte(html), nil)

	if sig1.Fingerprint != sig2.Fingerprint {
		t.Errorf("fingerprint not stable: %s != %s", sig1.Fingerprint, sig2.Fingerprint)
	}
}

func TestTraceVariantForInteraction_Coverage(t *testing.T) {
	// All interaction types except Unknown should have a variant mapping
	types := []InteractionType{
		InteractionClickButtons, InteractionDragHorizontal,
		InteractionDragFreeform, InteractionRotate,
		InteractionGridSelect, InteractionCheckbox, InteractionWait,
	}
	for _, it := range types {
		variants, ok := TraceVariantForInteraction[it]
		if !ok || len(variants) == 0 {
			t.Errorf("no variant mapping for %s", it)
		}
	}
}
