package go_yaml_to_x509

import (
	"crypto/x509"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/rschoonheim/go-yaml-to-x509/internal"

	"gopkg.in/yaml.v3"
)

// X509FromYaml parses YAML data and returns an x509.Certificate object.
// The YAML should conform to the CertificateSpec structure with fields like
// serial_number, subject, issuer, not_before, not_after, key_usage, etc.
//
// Example YAML:
//
//	serial_number: "12345"
//	subject:
//	  common_name: "example.com"
//	  organization: "Example Corp"
//	issuer:
//	  common_name: "Example CA"
//	not_before: "2025-01-01T00:00:00Z"
//	not_after: "2026-01-01T00:00:00Z"
//	key_usage:
//	  - digital_signature
//	  - key_encipherment
//	dns_names:
//	  - "example.com"
func X509FromYaml(yamlData []byte) (*x509.Certificate, error) {
	spec := &internal.CertificateSpec{}

	if err := yaml.Unmarshal(yamlData, spec); err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		Subject:               internal.ParsePkixName(spec.Subject),
		Issuer:                internal.ParsePkixName(spec.Issuer),
		DNSNames:              spec.DNSNames,
		EmailAddresses:        spec.EmailAddresses,
		IsCA:                  spec.IsCA,
		MaxPathLen:            spec.MaxPathLen,
		MaxPathLenZero:        spec.MaxPathLenZero,
		BasicConstraintsValid: spec.BasicConstraintsValid,
	}

	// Parse serial number
	if spec.SerialNumber != "" {
		serialNum := new(big.Int)
		serialNum.SetString(spec.SerialNumber, 10)
		cert.SerialNumber = serialNum
	}

	// Parse dates
	if spec.NotBefore != "" {
		if notBefore, err := time.Parse(time.RFC3339, spec.NotBefore); err == nil {
			cert.NotBefore = notBefore
		}
	}

	if spec.NotAfter != "" {
		if notAfter, err := time.Parse(time.RFC3339, spec.NotAfter); err == nil {
			cert.NotAfter = notAfter
		}
	}

	// Parse key usage flags
	cert.KeyUsage = internal.ParseKeyUsage(spec.KeyUsage)
	cert.ExtKeyUsage = internal.ParseExtKeyUsage(spec.ExtKeyUsage)

	// Parse IP addresses
	for _, ipStr := range spec.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		}
	}

	// Parse URIs
	for _, uriStr := range spec.URIs {
		if uri, err := url.Parse(uriStr); err == nil {
			cert.URIs = append(cert.URIs, uri)
		}
	}

	// Parse algorithms
	cert.SignatureAlgorithm = internal.ParseSignatureAlgorithm(spec.SignatureAlgorithm)
	cert.PublicKeyAlgorithm = internal.ParsePublicKeyAlgorithm(spec.PublicKeyAlgorithm)

	return cert, nil
}
