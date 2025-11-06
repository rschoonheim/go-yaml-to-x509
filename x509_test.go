package go_x509_factory

import (
	"crypto/x509"
	"fmt"
	"testing"
)

func TestX509FromYaml(t *testing.T) {
	yamlData := []byte(`
serial_number: "12345678901234567890"
subject:
  common_name: "example.com"
  organization: "Example Corp"
  country: "US"
issuer:
  common_name: "Example CA"
  organization: "Example Corp"
  country: "US"
not_before: "2025-01-01T00:00:00Z"
not_after: "2026-01-01T00:00:00Z"
key_usage:
  - digital_signature
  - key_encipherment
ext_key_usage:
  - server_auth
  - client_auth
dns_names:
  - "example.com"
  - "www.example.com"
email_addresses:
  - "admin@example.com"
ip_addresses:
  - "192.168.1.1"
  - "2001:db8::1"
uris:
  - "https://example.com"
is_ca: false
basic_constraints_valid: true
signature_algorithm: "SHA256WithRSA"
public_key_algorithm: "RSA"
`)

	cert, err := X509FromYaml(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	// Verify basic fields
	if cert.Subject.CommonName != "example.com" {
		t.Errorf("Expected CommonName 'example.com', got '%s'", cert.Subject.CommonName)
	}

	if cert.Issuer.CommonName != "Example CA" {
		t.Errorf("Expected Issuer CommonName 'Example CA', got '%s'", cert.Issuer.CommonName)
	}

	if len(cert.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(cert.DNSNames))
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}

	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("Expected KeyUsageKeyEncipherment to be set")
	}

	if len(cert.ExtKeyUsage) != 2 {
		t.Errorf("Expected 2 extended key usages, got %d", len(cert.ExtKeyUsage))
	}

	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("Expected SHA256WithRSA signature algorithm, got %v", cert.SignatureAlgorithm)
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("Expected RSA public key algorithm, got %v", cert.PublicKeyAlgorithm)
	}

	fmt.Printf("Successfully parsed certificate for: %s\n", cert.Subject.CommonName)
}

func ExampleX509FromYaml() {
	yamlData := []byte(`
serial_number: "123456"
subject:
  common_name: "test.example.com"
  organization: "Test Org"
issuer:
  common_name: "Test CA"
not_before: "2025-01-01T00:00:00Z"
not_after: "2026-01-01T00:00:00Z"
key_usage:
  - digital_signature
ext_key_usage:
  - server_auth
dns_names:
  - "test.example.com"
is_ca: false
basic_constraints_valid: true
`)

	cert, err := X509FromYaml(yamlData)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Certificate CN: %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer CN: %s\n", cert.Issuer.CommonName)
	fmt.Printf("DNS Names: %v\n", cert.DNSNames)
	// Output:
	// Certificate CN: test.example.com
	// Issuer CN: Test CA
	// DNS Names: [test.example.com]
}
