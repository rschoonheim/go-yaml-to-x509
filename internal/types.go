package internal

// ConfigDocument represents a YAML document with optional config segments
type ConfigDocument struct {
	Config   *CertificateSpec            `yaml:"config,omitempty"`
	Merge    []string                    `yaml:"merge,omitempty"`
	Segments map[string]*CertificateSpec `yaml:"segments,omitempty"`
}

// CertificateSpec is an intermediate struct for YAML unmarshalling
type CertificateSpec struct {
	SerialNumber          string            `yaml:"serial_number,omitempty"`
	Subject               map[string]string `yaml:"subject,omitempty"`
	Issuer                map[string]string `yaml:"issuer,omitempty"`
	NotBefore             string            `yaml:"not_before,omitempty"`
	NotAfter              string            `yaml:"not_after,omitempty"`
	KeyUsage              []string          `yaml:"key_usage,omitempty"`
	ExtKeyUsage           []string          `yaml:"ext_key_usage,omitempty"`
	DNSNames              []string          `yaml:"dns_names,omitempty"`
	EmailAddresses        []string          `yaml:"email_addresses,omitempty"`
	IPAddresses           []string          `yaml:"ip_addresses,omitempty"`
	URIs                  []string          `yaml:"uris,omitempty"`
	IsCA                  bool              `yaml:"is_ca,omitempty"`
	MaxPathLen            int               `yaml:"max_path_len,omitempty"`
	MaxPathLenZero        bool              `yaml:"max_path_len_zero,omitempty"`
	BasicConstraintsValid bool              `yaml:"basic_constraints_valid,omitempty"`
	SignatureAlgorithm    string            `yaml:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm    string            `yaml:"public_key_algorithm,omitempty"`
}
