// gencert - Generate platform-specific TLS certificates
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/skunkworq/stealth/brws/config"
)

func main() {
	var (
		platform = flag.String("platform", "windows", "Target platform: windows, macos, linux, ios, android")
		browser  = flag.String("browser", "chrome", "Target browser: chrome, firefox, safari, edge")
		host     = flag.String("host", "localhost", "Hostname for certificate")
		_        = flag.String("out", "./certs", "Output directory for certificates")
		list     = flag.Bool("list", false, "List available platforms")
	)
	flag.Parse()

	if *list {
		fmt.Println("Available platforms:")
		for _, p := range config.ListPlatforms() {
			fmt.Printf("  - %s\n", p)
		}
		return
	}

	// Get platform configuration
	rootConfig, ok := config.GetPlatformRootCA(*platform)
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: unknown platform '%s'\n", *platform)
		fmt.Fprintf(os.Stderr, "Use -list to see available platforms\n")
		os.Exit(1)
	}

	// Get browser intermediate CA
	intermediateConfig := config.BrowserIntermediateCAs[*browser]

	// Show configuration
	fmt.Printf("Certificate Configuration for %s/%s:\n", *platform, *browser)
	fmt.Printf("=====================================\n\n")
	fmt.Printf("Root CA:\n")
	fmt.Printf("  Common Name:   %s\n", rootConfig.CommonName)
	fmt.Printf("  Organization:  %s\n", rootConfig.Organization)
	fmt.Printf("  Country:       %s\n", rootConfig.Country)
	fmt.Printf("  Key Algorithm: %s\n", rootConfig.KeyAlgorithm)
	fmt.Printf("  Signature:     %s\n", rootConfig.SignatureAlgorithm)
	if len(rootConfig.OCSPServers) > 0 {
		fmt.Printf("  OCSP:          %s\n", strings.Join(rootConfig.OCSPServers, ", "))
	}
	fmt.Printf("\nIntermediate CA:\n")
	fmt.Printf("  Common Name:   %s\n", intermediateConfig.CommonName)
	fmt.Printf("  Organization:  %s\n", intermediateConfig.Organization)
	fmt.Printf("\nLeaf Certificate:\n")
	fmt.Printf("  Common Name:   %s\n", *host)
	fmt.Printf("\n")
}
