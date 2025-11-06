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
//
// Supports two formats:
//
//  1. Simple format (direct certificate fields):
//     serial_number: "12345"
//     subject:
//     common_name: "example.com"
//     ...
//
//  2. Config segments format (reusable configuration blocks):
//     segments:
//     defaults:
//     issuer:
//     common_name: "Example CA"
//     key_usage:
//     - digital_signature
//     web-server:
//     ext_key_usage:
//     - server_auth
//     merge:
//     - defaults
//     - web-server
//     config:
//     subject:
//     common_name: "example.com"
//
// When using segments, the 'merge' list specifies which segments to combine,
// and 'config' provides the final overrides. Later segments and config override earlier ones.
func X509FromYaml(yamlData []byte) (*x509.Certificate, error) {
	// First, try to parse as ConfigDocument (with segments support)
	doc := &internal.ConfigDocument{}
	if err := yaml.Unmarshal(yamlData, doc); err != nil {
		return nil, err
	}

	var spec *internal.CertificateSpec

	// Check if this is a segments-based config or simple config
	if doc.Segments != nil || doc.Merge != nil {
		// Process segments and merge
		resolvedSpec, err := internal.ResolveConfig(doc)
		if err != nil {
			return nil, err
		}
		spec = resolvedSpec
	} else if doc.Config != nil {
		// Only 'config' field is present
		spec = doc.Config
	} else {
		// Simple format - entire document is the spec
		spec = &internal.CertificateSpec{}
		if err := yaml.Unmarshal(yamlData, spec); err != nil {
			return nil, err
		}
	}

	return buildCertificate(spec)
}

// buildCertificate converts a CertificateSpec to an x509.Certificate
func buildCertificate(spec *internal.CertificateSpec) (*x509.Certificate, error) {
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
