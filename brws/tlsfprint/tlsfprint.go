package tlsfprint

/*
#cgo LDFLAGS: -L${SRCDIR}/rust/target/release -ltlsfprint -lm
#cgo CFLAGS: -I${SRCDIR}/rust/target/release

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint64_t timestamp_ms;
    char* server_ip;
    uint16_t server_port;
    char* tls_version;
    char* ja3_string;
    char* ja3_hash;
    char* ja4;
    char* cipher_suites;
    size_t cipher_count;
    char* greases_in_ciphers;
    char* extensions;
    size_t extension_count;
    char* greases_in_extensions;
    char* alpn;
    bool has_http2;
    bool has_grease;
    char* grease_values;
    char* sni;
    char* detected_browser;
    char* anomalies;
    char* trace_id;
    char* raw_json;
} TLSFingerprint;

TLSFingerprint* connect_and_fingerprint(const char* host, int port);
void free_tls_fingerprint(TLSFingerprint* fp);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type Fingerprint struct {
	TimestampMs         uint64
	ServerIP            string
	ServerPort          uint16
	TLSVersion          string
	JA3String           string
	JA3Hash             string
	JA4                 string
	CipherSuites        string
	CipherCount         int
	GREASESInCiphers    string
	Extensions          string
	ExtensionCount      int
	GREASESInExtensions string
	ALPN                string
	HasHTTP2            bool
	HasGREASE           bool
	GREASEValues        string
	SNI                 string
	DetectedBrowser     string
	Anomalies           string
	TraceID             string
	RawJSON             string
}

func ConnectAndFingerprint(host string, port int) (*Fingerprint, error) {
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	fp := C.connect_and_fingerprint(cHost, C.int(port))
	if fp == nil {
		return nil, fmt.Errorf("failed to connect and fingerprint")
	}
	defer C.free_tls_fingerprint(fp)

	result := &Fingerprint{
		TimestampMs:    uint64(fp.timestamp_ms),
		ServerPort:     uint16(fp.server_port),
		CipherCount:    int(fp.cipher_count),
		ExtensionCount: int(fp.extension_count),
		HasHTTP2:       bool(fp.has_http2),
		HasGREASE:      bool(fp.has_grease),
	}

	// Convert C strings
	if fp.server_ip != nil {
		result.ServerIP = C.GoString(fp.server_ip)
	}
	if fp.tls_version != nil {
		result.TLSVersion = C.GoString(fp.tls_version)
	}
	if fp.ja3_string != nil {
		result.JA3String = C.GoString(fp.ja3_string)
	}
	if fp.ja3_hash != nil {
		result.JA3Hash = C.GoString(fp.ja3_hash)
	}
	if fp.ja4 != nil {
		result.JA4 = C.GoString(fp.ja4)
	}
	if fp.cipher_suites != nil {
		result.CipherSuites = C.GoString(fp.cipher_suites)
	}
	if fp.greases_in_ciphers != nil {
		result.GREASESInCiphers = C.GoString(fp.greases_in_ciphers)
	}
	if fp.extensions != nil {
		result.Extensions = C.GoString(fp.extensions)
	}
	if fp.greases_in_extensions != nil {
		result.GREASESInExtensions = C.GoString(fp.greases_in_extensions)
	}
	if fp.alpn != nil {
		result.ALPN = C.GoString(fp.alpn)
	}
	if fp.grease_values != nil {
		result.GREASEValues = C.GoString(fp.grease_values)
	}
	if fp.sni != nil {
		result.SNI = C.GoString(fp.sni)
	}
	if fp.detected_browser != nil {
		result.DetectedBrowser = C.GoString(fp.detected_browser)
	}
	if fp.anomalies != nil {
		result.Anomalies = C.GoString(fp.anomalies)
	}
	if fp.trace_id != nil {
		result.TraceID = C.GoString(fp.trace_id)
	}
	if fp.raw_json != nil {
		result.RawJSON = C.GoString(fp.raw_json)
	}

	return result, nil
}

func DetectBrowserFromJA4(ja4 string) string {
	if len(ja4) >= 4 {
		prefix := ja4[:4]
		if prefix == "t13d" || prefix == "t12d" {
			return "chrome"
		}
		if prefix == "t13_" || prefix == "t13" {
			return "safari"
		}
		if prefix == "t12_" || prefix == "t12" {
			return "firefox"
		}
	}
	return "unknown"
}
