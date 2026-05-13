// scanciphers - Extract cipher suites and TLS config from remote sites
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		host    = flag.String("host", "", "Target host (e.g., www.coles.com.au)")
		port    = flag.String("port", "443", "Target port")
		timeout = flag.Duration("timeout", 10*time.Second, "Connection timeout")
		jsonOut = flag.Bool("json", false, "Output as JSON")
	)

	flag.Parse()

	if *host == "" {
		//nolint:gosec // Test server output is controlled
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s -host <hostname> [-port <port>]\n", os.Args[0])

		flag.PrintDefaults()
		os.Exit(1)
	}

	addr := net.JoinHostPort(*host, *port)

	if !*jsonOut {
		_, _ = fmt.Fprintf(os.Stdout, "Scanning %s...\n\n", addr)
	}

	// Get supported cipher suites
	ciphers := scanCiphers(addr, *timeout)

	// Get TLS info
	tlsInfo := getTLSInfo(addr, *timeout)

	if *jsonOut {
		output := map[string]interface{}{
			"host":     *host,
			"port":     *port,
			"ciphers":  ciphers,
			"tls_info": tlsInfo,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		if err := enc.Encode(output); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)

			os.Exit(1)
		}
	} else {
		printResults(*host, ciphers, tlsInfo)
	}
}

// CipherInfo holds cipher suite information
type CipherInfo struct {
	Name      string `json:"name"`
	ID        uint16 `json:"id"`
	Version   string `json:"tls_version"`
	Supported bool   `json:"supported"`
}

// TLSInfo holds TLS connection information
type TLSInfo struct {
	Version            string `json:"version"`
	CipherSuite        string `json:"cipher_suite"`
	ServerName         string `json:"server_name"`
	NegotiatedProtocol string `json:"alpn"`
}

// Common cipher suites to test
var commonCiphers = []uint16{
	// TLS 1.3
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,

	// TLS 1.2 - ECDHE
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

	// TLS 1.2 - RSA
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,

	// Older
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
}

func scanCiphers(addr string, timeout time.Duration) []CipherInfo {
	var results []CipherInfo

	for _, cipher := range commonCiphers {
		config := &tls.Config{
			CipherSuites: []uint16{cipher},
			//nolint:gosec // InsecureSkipVerify required for cipher scanning tool
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, config)
		if err != nil {
			results = append(results, CipherInfo{
				Name:      tls.CipherSuiteName(cipher),
				ID:        cipher,
				Supported: false,
			})

			continue
		}

		_ = conn.Close()

		state := conn.ConnectionState()
		results = append(results, CipherInfo{
			Name:      tls.CipherSuiteName(cipher),
			ID:        cipher,
			Version:   tlsVersionName(state.Version),
			Supported: true,
		})
	}

	return results
}

func getTLSInfo(addr string, timeout time.Duration) *TLSInfo {
	config := &tls.Config{
		//nolint:gosec // InsecureSkipVerify required for TLS info scanning
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, config)
	if err != nil {
		return nil
	}
	_ = conn.Close()

	state := conn.ConnectionState()

	return &TLSInfo{
		Version:            tlsVersionName(state.Version),
		CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
		ServerName:         state.ServerName,
		NegotiatedProtocol: state.NegotiatedProtocol,
	}
}

func printResults(host string, ciphers []CipherInfo, tlsInfo *TLSInfo) {
	_, _ = fmt.Fprintf(os.Stdout, "Target: %s\n", host)
	_, _ = fmt.Fprintf(os.Stdout, "TLS Version: %s\n", tlsInfo.Version)
	_, _ = fmt.Fprintf(os.Stdout, "Cipher Suite: %s\n", tlsInfo.CipherSuite)
	_, _ = fmt.Fprintf(os.Stdout, "ALPN: %s\n", tlsInfo.NegotiatedProtocol)
	_, _ = fmt.Fprintln(os.Stdout)

	_, _ = fmt.Fprintf(os.Stdout, "Supported Cipher Suites:\n")
	_, _ = fmt.Fprintf(os.Stdout, "%-50s %-12s %s\n", "Name", "ID", "TLS Version")
	_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("-", 80))

	supported := 0

	for _, c := range ciphers {
		if c.Supported {
			_, _ = fmt.Fprintf(os.Stdout, "%-50s 0x%04x       %s\n", c.Name, c.ID, c.Version)
			supported++
		}
	}

	_, _ = fmt.Fprintf(os.Stdout, "\nTotal supported: %d/%d\n", supported, len(ciphers))
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", version)
	}
}
