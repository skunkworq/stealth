package spoof

import (
	"encoding/json"
	"strings"

	"github.com/stealth/brwslab/brws/types"
)

// SignatureFromFingerprint converts a captured CompleteFingerprint into a BrowserSignature
// that can be played back by the SpoofEngine.
func SignatureFromFingerprint(fp *types.CompleteFingerprint) *BrowserSignature {
	if fp == nil {
		return nil
	}

	sig := &BrowserSignature{
		Name:        "dynamic-capture",
		Version:     "latest",
		OS:          "unknown",
		Description: "Dynamically captured signature from " + fp.SourceIP,
	}

	// 1. Translate TLS details
	if fp.TLS != nil {
		tlsSig := &TLSSignature{
			Version:         fp.TLS.Version,
			ALPN:            fp.TLS.ALPN,
			ALPS:            fp.TLS.ALPS,
			CertCompression: fp.TLS.CertCompression,
		}

		// Map CipherSuites
		for _, c := range fp.TLS.CipherSuites {
			tlsSig.CipherSuites = append(tlsSig.CipherSuites, CipherEntry{
				Value:    c.Value,
				Name:     c.Name,
				IsGREASE: c.IsGREASE,
			})
		}

		// Map Supported Groups
		tlsSig.SupportedGroups = append(tlsSig.SupportedGroups, fp.TLS.SupportedGroups...)

		// Map Key Shares
		tlsSig.KeyShareGroups = append(tlsSig.KeyShareGroups, fp.TLS.KeyShareGroups...)

		// Map Extensions
		for _, ext := range fp.TLS.Extensions {
			// Extract signature_algorithms directly if found
			//nolint:revive,staticcheck // Empty block with intentional comment - SpoofEngine falls back to defaults for 0x000d
			if ext.Type == 0x000d && len(ext.Data) > 2 {
				// Extension data format for signature_algorithms usually starts with length bytes
				// We won't perfectly reconstruct the raw array here without deep parsing,
				// but the SpoofEngine falls back to defaults for 0x000d anyway.
			}

			var data json.RawMessage

			if len(ext.Data) > 0 {
				d, err := json.Marshal(ext.Data)
				if err != nil {
					continue
				}
				data = d
			}

			tlsSig.Extensions = append(tlsSig.Extensions, ExtensionEntry{
				Type:     ext.Type,
				Name:     ext.Name,
				Data:     data,
				IsGREASE: ext.IsGREASE,
			})
		}

		sig.TLS = tlsSig
	}

	// 2. Translate HTTP/2 details
	if fp.HTTP2 != nil {
		h2Sig := &HTTP2Signature{
			InitialWindowSize: 65535, // Safe default fallback
			EnablePush:        false,
		}

		for _, s := range fp.HTTP2.Settings {
			h2Sig.Settings = append(h2Sig.Settings, HTTP2SettingEntry{
				ID:    s.ID,
				Name:  s.Name,
				Value: s.Value,
			})
			if s.ID == 4 { // INITIAL_WINDOW_SIZE
				h2Sig.InitialWindowSize = s.Value
			}
			if s.ID == 2 && s.Value == 1 { // ENABLE_PUSH
				h2Sig.EnablePush = true
			}
		}

		h2Sig.PseudoHeaders = append([]string{}, fp.HTTP2.PseudoHeaders...)

		if fp.HTTP2.StreamPriority != nil {
			h2Sig.HeaderPriority = &HeaderPriority{
				Weight:    fp.HTTP2.StreamPriority.Weight,
				Exclusive: fp.HTTP2.StreamPriority.Exclusive,
			}
		}

		sig.HTTP2 = h2Sig
	}

	// 3. Translate HTTP details
	if fp.HTTP != nil {
		httpSig := &HTTPSignature{
			UserAgent:      fp.HTTP.UserAgent,
			Accept:         fp.HTTP.Accept,
			AcceptLanguage: fp.HTTP.AcceptLang,
			AcceptEncoding: fp.HTTP.AcceptEnc,
			HTTPVersion:    fp.HTTP.Protocol,
		}

		for _, h := range fp.HTTP.Headers {
			httpSig.Headers = append(httpSig.Headers, HeaderEntry{
				Name:     strings.ToLower(h.Name),
				Value:    h.Value,
				Required: true,
			})
		}

		if fp.HTTP.ClientHints != nil && fp.HTTP.ClientHints.SecCHUA != "" {
			httpSig.ClientHints = &ClientHintsEntry{
				SecCHUA:         fp.HTTP.ClientHints.SecCHUA,
				SecCHUAMobile:   fp.HTTP.ClientHints.SecCHUAMobile,
				SecCHUAPlatform: fp.HTTP.ClientHints.SecCHUAPlatform,
			}
		}

		sig.HTTP = httpSig
	}

	return sig
}
