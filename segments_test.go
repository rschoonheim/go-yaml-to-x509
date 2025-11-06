package go_yaml_to_x509

import (
	"crypto/x509"
	"testing"
)

func TestX509FromYaml_WithSegments(t *testing.T) {
	yamlData := []byte(`
segments:
  defaults:
    issuer:
      common_name: "Default CA"
      organization: "Default Org"
      country: "US"
    key_usage:
      - digital_signature
    signature_algorithm: "SHA256WithRSA"
    public_key_algorithm: "RSA"
  
  web-server:
    key_usage:
      - key_encipherment
    ext_key_usage:
      - server_auth
      - client_auth

merge:
  - defaults
  - web-server

config:
  serial_number: "123456"
  subject:
    common_name: "example.com"
    organization: "Example Corp"
    country: "US"
  dns_names:
    - "example.com"
    - "www.example.com"
  not_before: "2025-01-01T00:00:00Z"
  not_after: "2026-01-01T00:00:00Z"
  basic_constraints_valid: true
  is_ca: false
`)

	cert, err := X509FromYaml(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse YAML with segments: %v", err)
	}

	// Verify subject from config
	if cert.Subject.CommonName != "example.com" {
		t.Errorf("Expected CommonName 'example.com', got '%s'", cert.Subject.CommonName)
	}

	// Verify issuer from defaults segment
	if cert.Issuer.CommonName != "Default CA" {
		t.Errorf("Expected Issuer CommonName 'Default CA', got '%s'", cert.Issuer.CommonName)
	}

	// Verify key_usage from both defaults and web-server segments (merged)
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature from defaults segment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("Expected KeyUsageKeyEncipherment from web-server segment")
	}

	// Verify ext_key_usage from web-server segment
	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("Expected ExtKeyUsageServerAuth from web-server segment")
	}
	if !hasClientAuth {
		t.Error("Expected ExtKeyUsageClientAuth from web-server segment")
	}

	// Verify DNS names from config
	if len(cert.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(cert.DNSNames))
	}

	// Verify algorithms from defaults segment
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("Expected SHA256WithRSA signature algorithm, got %v", cert.SignatureAlgorithm)
	}
}

func TestX509FromYaml_SegmentOverride(t *testing.T) {
	yamlData := []byte(`
segments:
  base:
    subject:
      organization: "Base Org"
      country: "US"
    key_usage:
      - digital_signature
  
  override:
    subject:
      organization: "Override Org"
    key_usage:
      - key_encipherment

merge:
  - base
  - override

config:
  subject:
    common_name: "test.com"
`)

	cert, err := X509FromYaml(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	// Organization should be from override segment (not base)
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Override Org" {
		t.Errorf("Expected organization 'Override Org', got %v", cert.Subject.Organization)
	}

	// Country should be from base segment (not overridden)
	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] != "US" {
		t.Errorf("Expected country 'US', got %v", cert.Subject.Country)
	}

	// CommonName should be from config (final override)
	if cert.Subject.CommonName != "test.com" {
		t.Errorf("Expected CommonName 'test.com', got '%s'", cert.Subject.CommonName)
	}

	// Key usage should include both (merged)
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature from base")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("Expected KeyUsageKeyEncipherment from override")
	}
}

func TestX509FromYaml_ConfigOnly(t *testing.T) {
	yamlData := []byte(`
config:
  serial_number: "789"
  subject:
    common_name: "config-only.com"
  key_usage:
    - digital_signature
`)

	cert, err := X509FromYaml(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse config-only YAML: %v", err)
	}

	if cert.Subject.CommonName != "config-only.com" {
		t.Errorf("Expected CommonName 'config-only.com', got '%s'", cert.Subject.CommonName)
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature")
	}
}

func TestX509FromYaml_MissingSegment(t *testing.T) {
	yamlData := []byte(`
segments:
  existing:
    subject:
      common_name: "test"

merge:
  - existing
  - nonexistent

config:
  subject:
    common_name: "example.com"
`)

	_, err := X509FromYaml(yamlData)
	if err == nil {
		t.Error("Expected error for missing segment, got nil")
	}
	if err != nil && err.Error() != "segment 'nonexistent' referenced in merge but not defined" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestX509FromYaml_BackwardCompatibility(t *testing.T) {
	// Test that old-style YAML (without segments) still works
	yamlData := []byte(`
serial_number: "12345"
subject:
  common_name: "legacy.com"
  organization: "Legacy Corp"
issuer:
  common_name: "Legacy CA"
key_usage:
  - digital_signature
  - key_encipherment
not_before: "2025-01-01T00:00:00Z"
not_after: "2026-01-01T00:00:00Z"
basic_constraints_valid: true
`)

	cert, err := X509FromYaml(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse legacy YAML: %v", err)
	}

	if cert.Subject.CommonName != "legacy.com" {
		t.Errorf("Expected CommonName 'legacy.com', got '%s'", cert.Subject.CommonName)
	}

	if cert.Issuer.CommonName != "Legacy CA" {
		t.Errorf("Expected Issuer CommonName 'Legacy CA', got '%s'", cert.Issuer.CommonName)
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature")
	}
}
