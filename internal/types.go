package internal

// CertificateSpec is an intermediate struct for YAML unmarshalling
type CertificateSpec struct {
	SerialNumber          string            `yaml:"serial_number"`
	Subject               map[string]string `yaml:"subject"`
	Issuer                map[string]string `yaml:"issuer"`
	NotBefore             string            `yaml:"not_before"`
	NotAfter              string            `yaml:"not_after"`
	KeyUsage              []string          `yaml:"key_usage"`
	ExtKeyUsage           []string          `yaml:"ext_key_usage"`
	DNSNames              []string          `yaml:"dns_names"`
	EmailAddresses        []string          `yaml:"email_addresses"`
	IPAddresses           []string          `yaml:"ip_addresses"`
	URIs                  []string          `yaml:"uris"`
	IsCA                  bool              `yaml:"is_ca"`
	MaxPathLen            int               `yaml:"max_path_len"`
	MaxPathLenZero        bool              `yaml:"max_path_len_zero"`
	BasicConstraintsValid bool              `yaml:"basic_constraints_valid"`
	SignatureAlgorithm    string            `yaml:"signature_algorithm"`
	PublicKeyAlgorithm    string            `yaml:"public_key_algorithm"`
}
