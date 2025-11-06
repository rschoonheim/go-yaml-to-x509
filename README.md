# Go - Yaml to x509 Certificate Factory
A simple wrapper around Go's standard `crypto/x509` package that transforms YAML configuration into `x509.Certificate` structures.

Nothing special - just a straightforward YAML-to-x509 transformer to make certificate configuration more readable and maintainable.

## What It Does

This library parses YAML data and transforms it into Go's `x509.Certificate` structures. It supports all common X.509 certificate fields:

- Serial numbers
- Subject and Issuer distinguished names
- Validity periods (NotBefore, NotAfter)
- Key usage and extended key usage
- Subject Alternative Names (DNS, IP, Email, URI)
- CA constraints
- Signature and public key algorithms

## Installation

```bash
go get -u github.com/rschoonheim/go-yaml-to-x509
```

## Usage

This is a simple transformer - you provide YAML, it returns an `x509.Certificate` struct. That's it.

### Basic Example

```go
package main

import (
    "fmt"
    "log"
    
    factory "go-x509-factory"
)

func main() {
    yamlData := []byte(`
serial_number: "123456789"
subject:
  common_name: "example.com"
  organization: "Example Corp"
  country: "US"
issuer:
  common_name: "Example CA"
  organization: "Example Corp"
not_before: "2025-01-01T00:00:00Z"
not_after: "2026-01-01T00:00:00Z"
key_usage:
  - digital_signature
  - key_encipherment
ext_key_usage:
  - server_auth
dns_names:
  - "example.com"
  - "*.example.com"
is_ca: false
basic_constraints_valid: true
signature_algorithm: "SHA256WithRSA"
public_key_algorithm: "RSA"
`)

    cert, err := factory.X509FromYaml(yamlData)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Certificate for: %s\n", cert.Subject.CommonName)
}
```

### Config Segments (Reusable Configuration)

Config segments allow you to define reusable configuration blocks that can be merged together. This is useful for maintaining DRY (Don't Repeat Yourself) configuration files.

```go
yamlData := []byte(`
segments:
  defaults:
    issuer:
      common_name: "Example Root CA"
      organization: "Example Corp"
      country: "US"
    key_usage:
      - digital_signature
    signature_algorithm: "SHA256WithRSA"
    public_key_algorithm: "RSA"
    not_before: "2025-01-01T00:00:00Z"
    not_after: "2026-01-01T00:00:00Z"
  
  web-server:
    key_usage:
      - key_encipherment
    ext_key_usage:
      - server_auth
      - client_auth
  
  email-protection:
    key_usage:
      - key_encipherment
    ext_key_usage:
      - email_protection

merge:
  - defaults
  - web-server

config:
  serial_number: "123456"
  subject:
    common_name: "www.example.com"
    organization: "Example Corp"
  dns_names:
    - "example.com"
    - "www.example.com"
  basic_constraints_valid: true
`)

cert, err := factory.X509FromYaml(yamlData)
```

**How it works:**

1. **segments**: Define reusable configuration blocks
2. **merge**: List which segments to combine (in order, later overrides earlier)
3. **config**: Final configuration that overrides merged segments

**Merge behavior:**
- String fields: Later values override earlier ones
- Maps (subject/issuer): Later values extend/override earlier keys
- Slices (key_usage, dns_names, etc.): Later values are appended
- Boolean/int fields: Last value wins

This allows you to:
- Define common defaults once
- Create role-based segments (web-server, email-protection, code-signing)
- Mix and match segments per certificate
- Override specific fields as needed

## YAML Schema

### Subject/Issuer Fields

The `subject` and `issuer` fields accept the following distinguished name components:

- `common_name`: Common Name (CN)
- `country`: Country (C)
- `organization`: Organization (O)
- `organizational_unit`: Organizational Unit (OU)
- `locality`: Locality/City (L)
- `province`: State/Province (ST)
- `street_address`: Street Address
- `postal_code`: Postal Code
- `serial_number`: Serial Number

### Key Usage

Supported key usage values:

- `digital_signature`
- `content_commitment`
- `key_encipherment`
- `data_encipherment`
- `key_agreement`
- `cert_sign`
- `crl_sign`
- `encipher_only`
- `decipher_only`

### Extended Key Usage

Supported extended key usage values:

- `any`
- `server_auth`
- `client_auth`
- `code_signing`
- `email_protection`
- `ipsec_end_system`
- `ipsec_tunnel`
- `ipsec_user`
- `time_stamping`
- `ocsp_signing`
- `microsoft_server_gated_crypto`
- `netscape_server_gated_crypto`
- `microsoft_commercial_code_signing`
- `microsoft_kernel_code_signing`

### Signature Algorithms

Supported signature algorithms:

- `MD2WithRSA`, `MD5WithRSA`
- `SHA1WithRSA`, `SHA256WithRSA`, `SHA384WithRSA`, `SHA512WithRSA`
- `DSAWithSHA1`, `DSAWithSHA256`
- `ECDSAWithSHA1`, `ECDSAWithSHA256`, `ECDSAWithSHA384`, `ECDSAWithSHA512`
- `SHA256WithRSAPSS`, `SHA384WithRSAPSS`, `SHA512WithRSAPSS`
- `PureEd25519`

### Public Key Algorithms

Supported public key algorithms:

- `RSA`
- `DSA`
- `ECDSA`
- `Ed25519`

## Complete YAML Examples

### Simple Format

```yaml
serial_number: "12345678901234567890"
subject:
  common_name: "example.com"
  organization: "Example Corp"
  organizational_unit: "IT Department"
  country: "US"
  province: "California"
  locality: "San Francisco"
issuer:
  common_name: "Example Root CA"
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
  - "*.example.com"
email_addresses:
  - "admin@example.com"
ip_addresses:
  - "192.168.1.1"
  - "2001:db8::1"
uris:
  - "https://example.com"
is_ca: false
max_path_len: 0
max_path_len_zero: false
basic_constraints_valid: true
signature_algorithm: "SHA256WithRSA"
public_key_algorithm: "RSA"
```

### Config Segments Format

```yaml
segments:
  # Common defaults for all certificates
  defaults:
    issuer:
      common_name: "Example Root CA"
      organization: "Example Corp"
      country: "US"
    signature_algorithm: "SHA256WithRSA"
    public_key_algorithm: "RSA"
    not_before: "2025-01-01T00:00:00Z"
    not_after: "2026-01-01T00:00:00Z"
    basic_constraints_valid: true
    key_usage:
      - digital_signature
  
  # Segment for web server certificates
  web-server:
    key_usage:
      - key_encipherment
    ext_key_usage:
      - server_auth
      - client_auth
  
  # Segment for code signing certificates
  code-signing:
    key_usage:
      - digital_signature
    ext_key_usage:
      - code_signing
  
  # Segment for CA certificates
  certificate-authority:
    is_ca: true
    max_path_len: 0
    key_usage:
      - cert_sign
      - crl_sign

# Merge defaults and web-server segments
merge:
  - defaults
  - web-server

# Final configuration (overrides merged segments)
config:
  serial_number: "123456789"
  subject:
    common_name: "www.example.com"
    organization: "Example Corp"
    organizational_unit: "Web Services"
    country: "US"
  dns_names:
    - "example.com"
    - "www.example.com"
    - "*.example.com"
  email_addresses:
    - "webmaster@example.com"
```

## Testing

Run the tests:

```bash
go test -v
```

## License

This project is provided as-is for educational and development purposes.

