package internal

import (
	"testing"
)

func TestMergeSpecs_EmptyInput(t *testing.T) {
	result := MergeSpecs()

	if result == nil {
		t.Fatal("Expected non-nil result for empty input")
	}

	// Result should be an empty CertificateSpec
	if result.SerialNumber != "" {
		t.Error("Expected empty SerialNumber")
	}
	if result.Subject != nil {
		t.Error("Expected nil Subject")
	}
}

func TestMergeSpecs_NilSpecs(t *testing.T) {
	result := MergeSpecs(nil, nil, nil)

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Should skip all nil specs
	if result.SerialNumber != "" {
		t.Error("Expected empty result after merging only nil specs")
	}
}

func TestMergeSpecs_SingleSpec(t *testing.T) {
	spec := &CertificateSpec{
		SerialNumber: "12345",
		Subject: map[string]string{
			"common_name": "example.com",
			"country":     "US",
		},
		KeyUsage:   []string{"digital_signature"},
		DNSNames:   []string{"example.com"},
		IsCA:       true,
		MaxPathLen: 5,
	}

	result := MergeSpecs(spec)

	if result.SerialNumber != "12345" {
		t.Errorf("Expected SerialNumber '12345', got '%s'", result.SerialNumber)
	}
	if result.Subject["common_name"] != "example.com" {
		t.Error("Expected Subject common_name to be preserved")
	}
	if len(result.KeyUsage) != 1 || result.KeyUsage[0] != "digital_signature" {
		t.Error("Expected KeyUsage to be preserved")
	}
	if !result.IsCA {
		t.Error("Expected IsCA to be true")
	}
	if result.MaxPathLen != 5 {
		t.Errorf("Expected MaxPathLen 5, got %d", result.MaxPathLen)
	}
}

func TestMergeSpecs_StringFieldsOverride(t *testing.T) {
	spec1 := &CertificateSpec{
		SerialNumber:       "111",
		NotBefore:          "2025-01-01",
		SignatureAlgorithm: "SHA256",
	}

	spec2 := &CertificateSpec{
		SerialNumber: "222",
		NotAfter:     "2026-01-01",
	}

	spec3 := &CertificateSpec{
		SerialNumber:       "333",
		SignatureAlgorithm: "SHA512",
	}

	result := MergeSpecs(spec1, spec2, spec3)

	if result.SerialNumber != "333" {
		t.Errorf("Expected SerialNumber '333' (last value), got '%s'", result.SerialNumber)
	}
	if result.NotBefore != "2025-01-01" {
		t.Errorf("Expected NotBefore from spec1, got '%s'", result.NotBefore)
	}
	if result.NotAfter != "2026-01-01" {
		t.Errorf("Expected NotAfter from spec2, got '%s'", result.NotAfter)
	}
	if result.SignatureAlgorithm != "SHA512" {
		t.Errorf("Expected SignatureAlgorithm 'SHA512' (last value), got '%s'", result.SignatureAlgorithm)
	}
}

func TestMergeSpecs_MapsExtendAndOverride(t *testing.T) {
	spec1 := &CertificateSpec{
		Subject: map[string]string{
			"common_name":  "example.com",
			"country":      "US",
			"organization": "Example Corp",
		},
	}

	spec2 := &CertificateSpec{
		Subject: map[string]string{
			"country":  "UK",     // Override
			"locality": "London", // Add new
		},
	}

	result := MergeSpecs(spec1, spec2)

	if result.Subject["common_name"] != "example.com" {
		t.Error("Expected common_name from spec1")
	}
	if result.Subject["country"] != "UK" {
		t.Errorf("Expected country 'UK' (overridden), got '%s'", result.Subject["country"])
	}
	if result.Subject["organization"] != "Example Corp" {
		t.Error("Expected organization from spec1")
	}
	if result.Subject["locality"] != "London" {
		t.Errorf("Expected locality 'London' from spec2, got '%s'", result.Subject["locality"])
	}
}

func TestMergeSpecs_IssuerMapMerge(t *testing.T) {
	spec1 := &CertificateSpec{
		Issuer: map[string]string{
			"common_name": "CA 1",
			"country":     "US",
		},
	}

	spec2 := &CertificateSpec{
		Issuer: map[string]string{
			"organization": "CA Org",
		},
	}

	result := MergeSpecs(spec1, spec2)

	if len(result.Issuer) != 3 {
		t.Errorf("Expected 3 issuer fields, got %d", len(result.Issuer))
	}
	if result.Issuer["common_name"] != "CA 1" {
		t.Error("Expected issuer common_name from spec1")
	}
	if result.Issuer["organization"] != "CA Org" {
		t.Error("Expected issuer organization from spec2")
	}
}

func TestMergeSpecs_SlicesAppend(t *testing.T) {
	spec1 := &CertificateSpec{
		KeyUsage:       []string{"digital_signature"},
		ExtKeyUsage:    []string{"server_auth"},
		DNSNames:       []string{"example.com"},
		EmailAddresses: []string{"admin@example.com"},
		IPAddresses:    []string{"192.168.1.1"},
		URIs:           []string{"https://example.com"},
	}

	spec2 := &CertificateSpec{
		KeyUsage:       []string{"key_encipherment"},
		ExtKeyUsage:    []string{"client_auth"},
		DNSNames:       []string{"www.example.com"},
		EmailAddresses: []string{"user@example.com"},
		IPAddresses:    []string{"192.168.1.2"},
		URIs:           []string{"https://www.example.com"},
	}

	result := MergeSpecs(spec1, spec2)

	if len(result.KeyUsage) != 2 {
		t.Errorf("Expected 2 KeyUsage values, got %d", len(result.KeyUsage))
	}
	if result.KeyUsage[0] != "digital_signature" || result.KeyUsage[1] != "key_encipherment" {
		t.Error("KeyUsage values not appended correctly")
	}

	if len(result.ExtKeyUsage) != 2 {
		t.Errorf("Expected 2 ExtKeyUsage values, got %d", len(result.ExtKeyUsage))
	}

	if len(result.DNSNames) != 2 {
		t.Errorf("Expected 2 DNSNames, got %d", len(result.DNSNames))
	}

	if len(result.EmailAddresses) != 2 {
		t.Errorf("Expected 2 EmailAddresses, got %d", len(result.EmailAddresses))
	}

	if len(result.IPAddresses) != 2 {
		t.Errorf("Expected 2 IPAddresses, got %d", len(result.IPAddresses))
	}

	if len(result.URIs) != 2 {
		t.Errorf("Expected 2 URIs, got %d", len(result.URIs))
	}
}

func TestMergeSpecs_BooleanFieldsLastWins(t *testing.T) {
	spec1 := &CertificateSpec{
		IsCA:                  true,
		MaxPathLen:            5,
		MaxPathLenZero:        false,
		BasicConstraintsValid: true,
	}

	spec2 := &CertificateSpec{
		IsCA:                  false,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: false,
	}

	result := MergeSpecs(spec1, spec2)

	if result.IsCA != false {
		t.Error("Expected IsCA false (from spec2)")
	}
	if result.MaxPathLen != 0 {
		t.Errorf("Expected MaxPathLen 0 (from spec2), got %d", result.MaxPathLen)
	}
	if result.MaxPathLenZero != true {
		t.Error("Expected MaxPathLenZero true (from spec2)")
	}
	if result.BasicConstraintsValid != false {
		t.Error("Expected BasicConstraintsValid false (from spec2)")
	}
}

func TestMergeSpecs_ComplexMerge(t *testing.T) {
	// Simulate real-world scenario: defaults + role + specific config
	defaults := &CertificateSpec{
		SignatureAlgorithm: "SHA256WithRSA",
		PublicKeyAlgorithm: "RSA",
		Issuer: map[string]string{
			"common_name":  "Example CA",
			"organization": "Example Corp",
			"country":      "US",
		},
		KeyUsage: []string{"digital_signature"},
	}

	webServer := &CertificateSpec{
		KeyUsage:    []string{"key_encipherment"},
		ExtKeyUsage: []string{"server_auth", "client_auth"},
	}

	specific := &CertificateSpec{
		SerialNumber: "123456",
		Subject: map[string]string{
			"common_name":  "www.example.com",
			"organization": "Example Corp",
		},
		DNSNames: []string{"example.com", "www.example.com"},
	}

	result := MergeSpecs(defaults, webServer, specific)

	// Check all fields are properly merged
	if result.SerialNumber != "123456" {
		t.Error("Expected SerialNumber from specific")
	}
	if result.SignatureAlgorithm != "SHA256WithRSA" {
		t.Error("Expected SignatureAlgorithm from defaults")
	}
	if len(result.KeyUsage) != 2 {
		t.Errorf("Expected 2 KeyUsage values (merged), got %d", len(result.KeyUsage))
	}
	if len(result.ExtKeyUsage) != 2 {
		t.Errorf("Expected 2 ExtKeyUsage values, got %d", len(result.ExtKeyUsage))
	}
	if result.Issuer["common_name"] != "Example CA" {
		t.Error("Expected Issuer from defaults")
	}
	if result.Subject["common_name"] != "www.example.com" {
		t.Error("Expected Subject from specific")
	}
	if len(result.DNSNames) != 2 {
		t.Error("Expected DNSNames from specific")
	}
}

func TestResolveConfig_EmptyDocument(t *testing.T) {
	doc := &ConfigDocument{}

	result, err := ResolveConfig(doc)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for empty document")
	}
}

func TestResolveConfig_ConfigOnly(t *testing.T) {
	doc := &ConfigDocument{
		Config: &CertificateSpec{
			SerialNumber: "12345",
			Subject: map[string]string{
				"common_name": "example.com",
			},
		},
	}

	result, err := ResolveConfig(doc)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.SerialNumber != "12345" {
		t.Errorf("Expected SerialNumber '12345', got '%s'", result.SerialNumber)
	}
	if result.Subject["common_name"] != "example.com" {
		t.Error("Expected Subject to be preserved")
	}
}

func TestResolveConfig_WithSegments(t *testing.T) {
	doc := &ConfigDocument{
		Segments: map[string]*CertificateSpec{
			"defaults": {
				SignatureAlgorithm: "SHA256WithRSA",
				Issuer: map[string]string{
					"common_name": "Default CA",
				},
			},
			"web-server": {
				KeyUsage:    []string{"digital_signature", "key_encipherment"},
				ExtKeyUsage: []string{"server_auth"},
			},
		},
		Merge: []string{"defaults", "web-server"},
		Config: &CertificateSpec{
			SerialNumber: "123",
			Subject: map[string]string{
				"common_name": "www.example.com",
			},
		},
	}

	result, err := ResolveConfig(doc)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check merged values
	if result.SignatureAlgorithm != "SHA256WithRSA" {
		t.Error("Expected SignatureAlgorithm from defaults segment")
	}
	if result.Issuer["common_name"] != "Default CA" {
		t.Error("Expected Issuer from defaults segment")
	}
	if len(result.KeyUsage) != 2 {
		t.Errorf("Expected 2 KeyUsage values from web-server segment, got %d", len(result.KeyUsage))
	}
	if result.SerialNumber != "123" {
		t.Error("Expected SerialNumber from config")
	}
	if result.Subject["common_name"] != "www.example.com" {
		t.Error("Expected Subject from config")
	}
}

func TestResolveConfig_MissingSegment(t *testing.T) {
	doc := &ConfigDocument{
		Segments: map[string]*CertificateSpec{
			"existing": {
				SerialNumber: "123",
			},
		},
		Merge: []string{"existing", "nonexistent"},
	}

	result, err := ResolveConfig(doc)

	if err == nil {
		t.Fatal("Expected error for missing segment")
	}
	if result != nil {
		t.Error("Expected nil result on error")
	}
	expectedError := "segment 'nonexistent' referenced in merge but not defined"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestResolveConfig_MergeOrder(t *testing.T) {
	doc := &ConfigDocument{
		Segments: map[string]*CertificateSpec{
			"first": {
				Subject: map[string]string{
					"country": "US",
				},
				KeyUsage: []string{"digital_signature"},
			},
			"second": {
				Subject: map[string]string{
					"country": "UK", // Override
				},
				KeyUsage: []string{"key_encipherment"}, // Append
			},
		},
		Merge: []string{"first", "second"},
	}

	result, err := ResolveConfig(doc)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Later segment should override country
	if result.Subject["country"] != "UK" {
		t.Errorf("Expected country 'UK' (from second), got '%s'", result.Subject["country"])
	}

	// KeyUsage should be appended
	if len(result.KeyUsage) != 2 {
		t.Errorf("Expected 2 KeyUsage values, got %d", len(result.KeyUsage))
	}
}

func TestResolveConfig_NoMergeNoConfig(t *testing.T) {
	doc := &ConfigDocument{
		Segments: map[string]*CertificateSpec{
			"unused": {
				SerialNumber: "123",
			},
		},
	}

	result, err := ResolveConfig(doc)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result != nil {
		t.Error("Expected nil result when no merge or config specified")
	}
}

func TestResolveConfig_EmptyMergeList(t *testing.T) {
	doc := &ConfigDocument{
		Segments: map[string]*CertificateSpec{
			"unused": {
				SerialNumber: "123",
			},
		},
		Merge: []string{},
		Config: &CertificateSpec{
			SerialNumber: "456",
		},
	}

	result, err := ResolveConfig(doc)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Should return only the config
	if result.SerialNumber != "456" {
		t.Errorf("Expected SerialNumber '456', got '%s'", result.SerialNumber)
	}
}

func TestResolveConfig_MergeWithoutConfig(t *testing.T) {
	doc := &ConfigDocument{
		Segments: map[string]*CertificateSpec{
			"only": {
				SerialNumber: "789",
				Subject: map[string]string{
					"common_name": "test.com",
				},
			},
		},
		Merge: []string{"only"},
	}

	result, err := ResolveConfig(doc)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.SerialNumber != "789" {
		t.Errorf("Expected SerialNumber '789', got '%s'", result.SerialNumber)
	}
	if result.Subject["common_name"] != "test.com" {
		t.Error("Expected Subject from segment")
	}
}
