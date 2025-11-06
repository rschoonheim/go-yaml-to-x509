package internal

import "fmt"

// MergeSpecs merges multiple CertificateSpec objects, with later specs overriding earlier ones
func MergeSpecs(specs ...*CertificateSpec) *CertificateSpec {
	result := &CertificateSpec{}

	for _, spec := range specs {
		if spec == nil {
			continue
		}

		// Merge simple string fields (later values override)
		if spec.SerialNumber != "" {
			result.SerialNumber = spec.SerialNumber
		}
		if spec.NotBefore != "" {
			result.NotBefore = spec.NotBefore
		}
		if spec.NotAfter != "" {
			result.NotAfter = spec.NotAfter
		}
		if spec.SignatureAlgorithm != "" {
			result.SignatureAlgorithm = spec.SignatureAlgorithm
		}
		if spec.PublicKeyAlgorithm != "" {
			result.PublicKeyAlgorithm = spec.PublicKeyAlgorithm
		}

		// Merge maps (later values extend/override)
		if spec.Subject != nil {
			if result.Subject == nil {
				result.Subject = make(map[string]string)
			}
			for k, v := range spec.Subject {
				result.Subject[k] = v
			}
		}
		if spec.Issuer != nil {
			if result.Issuer == nil {
				result.Issuer = make(map[string]string)
			}
			for k, v := range spec.Issuer {
				result.Issuer[k] = v
			}
		}

		// Merge slices (later values extend)
		if len(spec.KeyUsage) > 0 {
			result.KeyUsage = append(result.KeyUsage, spec.KeyUsage...)
		}
		if len(spec.ExtKeyUsage) > 0 {
			result.ExtKeyUsage = append(result.ExtKeyUsage, spec.ExtKeyUsage...)
		}
		if len(spec.DNSNames) > 0 {
			result.DNSNames = append(result.DNSNames, spec.DNSNames...)
		}
		if len(spec.EmailAddresses) > 0 {
			result.EmailAddresses = append(result.EmailAddresses, spec.EmailAddresses...)
		}
		if len(spec.IPAddresses) > 0 {
			result.IPAddresses = append(result.IPAddresses, spec.IPAddresses...)
		}
		if len(spec.URIs) > 0 {
			result.URIs = append(result.URIs, spec.URIs...)
		}

		// Boolean and int fields - last one wins
		// Note: We can't distinguish between "not set" and "false/0" for non-pointer fields
		// So we apply them unconditionally
		result.IsCA = spec.IsCA
		result.MaxPathLen = spec.MaxPathLen
		result.MaxPathLenZero = spec.MaxPathLenZero
		result.BasicConstraintsValid = spec.BasicConstraintsValid
	}

	return result
}

// ResolveConfig processes a ConfigDocument and returns the final merged CertificateSpec
func ResolveConfig(doc *ConfigDocument) (*CertificateSpec, error) {
	if doc.Config == nil && len(doc.Merge) == 0 {
		// No segments, treat the entire document as a spec
		return doc.Config, nil
	}

	var specsToMerge []*CertificateSpec

	// First, merge all segments referenced in 'merge'
	for _, segmentName := range doc.Merge {
		segment, exists := doc.Segments[segmentName]
		if !exists {
			return nil, fmt.Errorf("segment '%s' referenced in merge but not defined", segmentName)
		}
		specsToMerge = append(specsToMerge, segment)
	}

	// Finally, apply the main config (which overrides segments)
	if doc.Config != nil {
		specsToMerge = append(specsToMerge, doc.Config)
	}

	if len(specsToMerge) == 0 {
		return &CertificateSpec{}, nil
	}

	return MergeSpecs(specsToMerge...), nil
}
