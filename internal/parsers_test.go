package internal

import (
	"crypto/x509"
	"testing"
)

// Tests for ParsePkixName

func TestParsePkixName_EmptyMap(t *testing.T) {
	result := ParsePkixName(nil)

	if result.CommonName != "" {
		t.Error("Expected empty CommonName")
	}
	if len(result.Country) != 0 {
		t.Error("Expected empty Country")
	}
	if len(result.Organization) != 0 {
		t.Error("Expected empty Organization")
	}
}

func TestParsePkixName_AllFields(t *testing.T) {
	nameMap := map[string]string{
		DNCommonName:         "example.com",
		DNCountry:            "US",
		DNOrganization:       "Example Corp",
		DNOrganizationalUnit: "IT Department",
		DNLocality:           "San Francisco",
		DNProvince:           "California",
		DNStreetAddress:      "123 Main St",
		DNPostalCode:         "94102",
		DNSerialNumber:       "12345",
	}

	result := ParsePkixName(nameMap)

	if result.CommonName != "example.com" {
		t.Errorf("Expected CommonName 'example.com', got '%s'", result.CommonName)
	}
	if len(result.Country) != 1 || result.Country[0] != "US" {
		t.Errorf("Expected Country ['US'], got %v", result.Country)
	}
	if len(result.Organization) != 1 || result.Organization[0] != "Example Corp" {
		t.Errorf("Expected Organization ['Example Corp'], got %v", result.Organization)
	}
	if len(result.OrganizationalUnit) != 1 || result.OrganizationalUnit[0] != "IT Department" {
		t.Errorf("Expected OrganizationalUnit ['IT Department'], got %v", result.OrganizationalUnit)
	}
	if len(result.Locality) != 1 || result.Locality[0] != "San Francisco" {
		t.Errorf("Expected Locality ['San Francisco'], got %v", result.Locality)
	}
	if len(result.Province) != 1 || result.Province[0] != "California" {
		t.Errorf("Expected Province ['California'], got %v", result.Province)
	}
	if len(result.StreetAddress) != 1 || result.StreetAddress[0] != "123 Main St" {
		t.Errorf("Expected StreetAddress ['123 Main St'], got %v", result.StreetAddress)
	}
	if len(result.PostalCode) != 1 || result.PostalCode[0] != "94102" {
		t.Errorf("Expected PostalCode ['94102'], got %v", result.PostalCode)
	}
	if result.SerialNumber != "12345" {
		t.Errorf("Expected SerialNumber '12345', got '%s'", result.SerialNumber)
	}
}

func TestParsePkixName_PartialFields(t *testing.T) {
	nameMap := map[string]string{
		DNCommonName:   "test.com",
		DNOrganization: "Test Org",
	}

	result := ParsePkixName(nameMap)

	if result.CommonName != "test.com" {
		t.Errorf("Expected CommonName 'test.com', got '%s'", result.CommonName)
	}
	if len(result.Organization) != 1 || result.Organization[0] != "Test Org" {
		t.Errorf("Expected Organization ['Test Org'], got %v", result.Organization)
	}
	// Other fields should be empty
	if len(result.Country) != 0 {
		t.Error("Expected empty Country")
	}
	if len(result.Locality) != 0 {
		t.Error("Expected empty Locality")
	}
}

func TestParsePkixName_UnknownFields(t *testing.T) {
	nameMap := map[string]string{
		DNCommonName:    "example.com",
		"unknown_field": "ignored_value",
	}

	result := ParsePkixName(nameMap)

	if result.CommonName != "example.com" {
		t.Errorf("Expected CommonName 'example.com', got '%s'", result.CommonName)
	}
	// Unknown fields should be ignored without error
}

// Tests for ParseKeyUsage

func TestParseKeyUsage_Empty(t *testing.T) {
	result := ParseKeyUsage(nil)

	if result != 0 {
		t.Errorf("Expected 0 (no flags), got %d", result)
	}

	result = ParseKeyUsage([]string{})
	if result != 0 {
		t.Errorf("Expected 0 (no flags) for empty slice, got %d", result)
	}
}

func TestParseKeyUsage_SingleValue(t *testing.T) {
	result := ParseKeyUsage([]string{KeyUsageDigitalSignature})

	if result&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}
	if result&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("Expected KeyUsageKeyEncipherment NOT to be set")
	}
}

func TestParseKeyUsage_MultipleValues(t *testing.T) {
	result := ParseKeyUsage([]string{
		KeyUsageDigitalSignature,
		KeyUsageKeyEncipherment,
		KeyUsageCertSign,
	})

	if result&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}
	if result&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("Expected KeyUsageKeyEncipherment to be set")
	}
	if result&x509.KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign to be set")
	}
	if result&x509.KeyUsageDataEncipherment != 0 {
		t.Error("Expected KeyUsageDataEncipherment NOT to be set")
	}
}

func TestParseKeyUsage_AllValues(t *testing.T) {
	allUsages := []string{
		KeyUsageDigitalSignature,
		KeyUsageContentCommitment,
		KeyUsageKeyEncipherment,
		KeyUsageDataEncipherment,
		KeyUsageKeyAgreement,
		KeyUsageCertSign,
		KeyUsageCRLSign,
		KeyUsageEncipherOnly,
		KeyUsageDecipherOnly,
	}

	result := ParseKeyUsage(allUsages)

	if result&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}
	if result&x509.KeyUsageContentCommitment == 0 {
		t.Error("Expected KeyUsageContentCommitment to be set")
	}
	if result&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("Expected KeyUsageKeyEncipherment to be set")
	}
	if result&x509.KeyUsageDataEncipherment == 0 {
		t.Error("Expected KeyUsageDataEncipherment to be set")
	}
	if result&x509.KeyUsageKeyAgreement == 0 {
		t.Error("Expected KeyUsageKeyAgreement to be set")
	}
	if result&x509.KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign to be set")
	}
	if result&x509.KeyUsageCRLSign == 0 {
		t.Error("Expected KeyUsageCRLSign to be set")
	}
	if result&x509.KeyUsageEncipherOnly == 0 {
		t.Error("Expected KeyUsageEncipherOnly to be set")
	}
	if result&x509.KeyUsageDecipherOnly == 0 {
		t.Error("Expected KeyUsageDecipherOnly to be set")
	}
}

func TestParseKeyUsage_UnknownValue(t *testing.T) {
	result := ParseKeyUsage([]string{
		KeyUsageDigitalSignature,
		"unknown_usage",
		KeyUsageKeyEncipherment,
	})

	// Should ignore unknown values and process valid ones
	if result&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Expected KeyUsageDigitalSignature to be set")
	}
	if result&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("Expected KeyUsageKeyEncipherment to be set")
	}
}

// Tests for ParseExtKeyUsage

func TestParseExtKeyUsage_Empty(t *testing.T) {
	result := ParseExtKeyUsage(nil)

	if len(result) != 0 {
		t.Errorf("Expected empty slice, got %d items", len(result))
	}

	result = ParseExtKeyUsage([]string{})
	if len(result) != 0 {
		t.Errorf("Expected empty slice, got %d items", len(result))
	}
}

func TestParseExtKeyUsage_SingleValue(t *testing.T) {
	result := ParseExtKeyUsage([]string{ExtKeyUsageServerAuth})

	if len(result) != 1 {
		t.Fatalf("Expected 1 item, got %d", len(result))
	}
	if result[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("Expected ExtKeyUsageServerAuth, got %v", result[0])
	}
}

func TestParseExtKeyUsage_MultipleValues(t *testing.T) {
	result := ParseExtKeyUsage([]string{
		ExtKeyUsageServerAuth,
		ExtKeyUsageClientAuth,
		ExtKeyUsageCodeSigning,
	})

	if len(result) != 3 {
		t.Fatalf("Expected 3 items, got %d", len(result))
	}

	expectedUsages := map[x509.ExtKeyUsage]bool{
		x509.ExtKeyUsageServerAuth:  true,
		x509.ExtKeyUsageClientAuth:  true,
		x509.ExtKeyUsageCodeSigning: true,
	}

	for _, usage := range result {
		if !expectedUsages[usage] {
			t.Errorf("Unexpected usage: %v", usage)
		}
	}
}

func TestParseExtKeyUsage_AllValues(t *testing.T) {
	allUsages := []string{
		ExtKeyUsageAny,
		ExtKeyUsageServerAuth,
		ExtKeyUsageClientAuth,
		ExtKeyUsageCodeSigning,
		ExtKeyUsageEmailProtection,
		ExtKeyUsageIPSECEndSystem,
		ExtKeyUsageIPSECTunnel,
		ExtKeyUsageIPSECUser,
		ExtKeyUsageTimeStamping,
		ExtKeyUsageOCSPSigning,
		ExtKeyUsageMicrosoftServerGatedCrypto,
		ExtKeyUsageNetscapeServerGatedCrypto,
		ExtKeyUsageMicrosoftCommercialCodeSigning,
		ExtKeyUsageMicrosoftKernelCodeSigning,
	}

	result := ParseExtKeyUsage(allUsages)

	if len(result) != 14 {
		t.Errorf("Expected 14 items, got %d", len(result))
	}

	// Verify all expected usages are present
	expectedCount := map[x509.ExtKeyUsage]int{
		x509.ExtKeyUsageAny:                            1,
		x509.ExtKeyUsageServerAuth:                     1,
		x509.ExtKeyUsageClientAuth:                     1,
		x509.ExtKeyUsageCodeSigning:                    1,
		x509.ExtKeyUsageEmailProtection:                1,
		x509.ExtKeyUsageIPSECEndSystem:                 1,
		x509.ExtKeyUsageIPSECTunnel:                    1,
		x509.ExtKeyUsageIPSECUser:                      1,
		x509.ExtKeyUsageTimeStamping:                   1,
		x509.ExtKeyUsageOCSPSigning:                    1,
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     1,
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      1,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: 1,
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     1,
	}

	for _, usage := range result {
		if count, ok := expectedCount[usage]; !ok {
			t.Errorf("Unexpected usage: %v", usage)
		} else if count != 1 {
			t.Errorf("Usage %v appears more than expected", usage)
		}
	}
}

func TestParseExtKeyUsage_UnknownValue(t *testing.T) {
	result := ParseExtKeyUsage([]string{
		ExtKeyUsageServerAuth,
		"unknown_ext_usage",
		ExtKeyUsageClientAuth,
	})

	// Should ignore unknown values and process valid ones
	if len(result) != 2 {
		t.Errorf("Expected 2 items (unknown should be ignored), got %d", len(result))
	}
}

// Tests for ParseSignatureAlgorithm

func TestParseSignatureAlgorithm_ValidRSAAlgorithms(t *testing.T) {
	tests := []struct {
		input    string
		expected x509.SignatureAlgorithm
	}{
		{SigAlgMD2WithRSA, x509.MD2WithRSA},
		{SigAlgMD5WithRSA, x509.MD5WithRSA},
		{SigAlgSHA1WithRSA, x509.SHA1WithRSA},
		{SigAlgSHA256WithRSA, x509.SHA256WithRSA},
		{SigAlgSHA384WithRSA, x509.SHA384WithRSA},
		{SigAlgSHA512WithRSA, x509.SHA512WithRSA},
	}

	for _, tt := range tests {
		result := ParseSignatureAlgorithm(tt.input)
		if result != tt.expected {
			t.Errorf("For input '%s', expected %v, got %v", tt.input, tt.expected, result)
		}
	}
}

func TestParseSignatureAlgorithm_ValidDSAAlgorithms(t *testing.T) {
	tests := []struct {
		input    string
		expected x509.SignatureAlgorithm
	}{
		{SigAlgDSAWithSHA1, x509.DSAWithSHA1},
		{SigAlgDSAWithSHA256, x509.DSAWithSHA256},
	}

	for _, tt := range tests {
		result := ParseSignatureAlgorithm(tt.input)
		if result != tt.expected {
			t.Errorf("For input '%s', expected %v, got %v", tt.input, tt.expected, result)
		}
	}
}

func TestParseSignatureAlgorithm_ValidECDSAAlgorithms(t *testing.T) {
	tests := []struct {
		input    string
		expected x509.SignatureAlgorithm
	}{
		{SigAlgECDSAWithSHA1, x509.ECDSAWithSHA1},
		{SigAlgECDSAWithSHA256, x509.ECDSAWithSHA256},
		{SigAlgECDSAWithSHA384, x509.ECDSAWithSHA384},
		{SigAlgECDSAWithSHA512, x509.ECDSAWithSHA512},
	}

	for _, tt := range tests {
		result := ParseSignatureAlgorithm(tt.input)
		if result != tt.expected {
			t.Errorf("For input '%s', expected %v, got %v", tt.input, tt.expected, result)
		}
	}
}

func TestParseSignatureAlgorithm_ValidRSAPSSAlgorithms(t *testing.T) {
	tests := []struct {
		input    string
		expected x509.SignatureAlgorithm
	}{
		{SigAlgSHA256WithRSAPSS, x509.SHA256WithRSAPSS},
		{SigAlgSHA384WithRSAPSS, x509.SHA384WithRSAPSS},
		{SigAlgSHA512WithRSAPSS, x509.SHA512WithRSAPSS},
	}

	for _, tt := range tests {
		result := ParseSignatureAlgorithm(tt.input)
		if result != tt.expected {
			t.Errorf("For input '%s', expected %v, got %v", tt.input, tt.expected, result)
		}
	}
}

func TestParseSignatureAlgorithm_Ed25519(t *testing.T) {
	result := ParseSignatureAlgorithm(SigAlgPureEd25519)
	if result != x509.PureEd25519 {
		t.Errorf("Expected PureEd25519, got %v", result)
	}
}

func TestParseSignatureAlgorithm_UnknownAlgorithm(t *testing.T) {
	result := ParseSignatureAlgorithm("UnknownAlgorithm")
	if result != x509.UnknownSignatureAlgorithm {
		t.Errorf("Expected UnknownSignatureAlgorithm, got %v", result)
	}
}

func TestParseSignatureAlgorithm_EmptyString(t *testing.T) {
	result := ParseSignatureAlgorithm("")
	if result != x509.UnknownSignatureAlgorithm {
		t.Errorf("Expected UnknownSignatureAlgorithm for empty string, got %v", result)
	}
}

// Tests for ParsePublicKeyAlgorithm

func TestParsePublicKeyAlgorithm_ValidAlgorithms(t *testing.T) {
	tests := []struct {
		input    string
		expected x509.PublicKeyAlgorithm
	}{
		{PubKeyAlgRSA, x509.RSA},
		{PubKeyAlgDSA, x509.DSA},
		{PubKeyAlgECDSA, x509.ECDSA},
		{PubKeyAlgEd25519, x509.Ed25519},
	}

	for _, tt := range tests {
		result := ParsePublicKeyAlgorithm(tt.input)
		if result != tt.expected {
			t.Errorf("For input '%s', expected %v, got %v", tt.input, tt.expected, result)
		}
	}
}

func TestParsePublicKeyAlgorithm_UnknownAlgorithm(t *testing.T) {
	result := ParsePublicKeyAlgorithm("UnknownAlgorithm")
	if result != x509.UnknownPublicKeyAlgorithm {
		t.Errorf("Expected UnknownPublicKeyAlgorithm, got %v", result)
	}
}

func TestParsePublicKeyAlgorithm_EmptyString(t *testing.T) {
	result := ParsePublicKeyAlgorithm("")
	if result != x509.UnknownPublicKeyAlgorithm {
		t.Errorf("Expected UnknownPublicKeyAlgorithm for empty string, got %v", result)
	}
}

func TestParsePublicKeyAlgorithm_CaseSensitivity(t *testing.T) {
	// Should not match due to case sensitivity
	result := ParsePublicKeyAlgorithm("rsa")
	if result != x509.UnknownPublicKeyAlgorithm {
		t.Errorf("Expected UnknownPublicKeyAlgorithm for lowercase 'rsa', got %v", result)
	}

	result = ParsePublicKeyAlgorithm("ecdsa")
	if result != x509.UnknownPublicKeyAlgorithm {
		t.Errorf("Expected UnknownPublicKeyAlgorithm for lowercase 'ecdsa', got %v", result)
	}
}

// Integration tests - combining multiple parsers

func TestParsers_IntegrationTest(t *testing.T) {
	// Test realistic combination of parsers
	nameMap := map[string]string{
		DNCommonName:   "www.example.com",
		DNOrganization: "Example Corp",
		DNCountry:      "US",
	}

	pkixName := ParsePkixName(nameMap)
	keyUsage := ParseKeyUsage([]string{
		KeyUsageDigitalSignature,
		KeyUsageKeyEncipherment,
	})
	extKeyUsage := ParseExtKeyUsage([]string{
		ExtKeyUsageServerAuth,
		ExtKeyUsageClientAuth,
	})
	sigAlg := ParseSignatureAlgorithm(SigAlgSHA256WithRSA)
	pubKeyAlg := ParsePublicKeyAlgorithm(PubKeyAlgRSA)

	// Verify all parsers worked correctly
	if pkixName.CommonName != "www.example.com" {
		t.Error("ParsePkixName failed in integration test")
	}
	if keyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("ParseKeyUsage failed in integration test")
	}
	if len(extKeyUsage) != 2 {
		t.Error("ParseExtKeyUsage failed in integration test")
	}
	if sigAlg != x509.SHA256WithRSA {
		t.Error("ParseSignatureAlgorithm failed in integration test")
	}
	if pubKeyAlg != x509.RSA {
		t.Error("ParsePublicKeyAlgorithm failed in integration test")
	}
}
