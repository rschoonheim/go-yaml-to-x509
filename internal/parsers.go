package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

// ParsePkixName converts a map of distinguished name components to pkix.Name
func ParsePkixName(nameMap map[string]string) pkix.Name {
	name := pkix.Name{}

	if cn, ok := nameMap[DNCommonName]; ok {
		name.CommonName = cn
	}
	if country, ok := nameMap[DNCountry]; ok {
		name.Country = []string{country}
	}
	if org, ok := nameMap[DNOrganization]; ok {
		name.Organization = []string{org}
	}
	if ou, ok := nameMap[DNOrganizationalUnit]; ok {
		name.OrganizationalUnit = []string{ou}
	}
	if locality, ok := nameMap[DNLocality]; ok {
		name.Locality = []string{locality}
	}
	if province, ok := nameMap[DNProvince]; ok {
		name.Province = []string{province}
	}
	if street, ok := nameMap[DNStreetAddress]; ok {
		name.StreetAddress = []string{street}
	}
	if postal, ok := nameMap[DNPostalCode]; ok {
		name.PostalCode = []string{postal}
	}
	if serial, ok := nameMap[DNSerialNumber]; ok {
		name.SerialNumber = serial
	}

	return name
}

// ParseKeyUsage converts string representations to x509.KeyUsage
func ParseKeyUsage(usages []string) x509.KeyUsage {
	var keyUsage x509.KeyUsage

	for _, usage := range usages {
		switch usage {
		case KeyUsageDigitalSignature:
			keyUsage |= x509.KeyUsageDigitalSignature
		case KeyUsageContentCommitment:
			keyUsage |= x509.KeyUsageContentCommitment
		case KeyUsageKeyEncipherment:
			keyUsage |= x509.KeyUsageKeyEncipherment
		case KeyUsageDataEncipherment:
			keyUsage |= x509.KeyUsageDataEncipherment
		case KeyUsageKeyAgreement:
			keyUsage |= x509.KeyUsageKeyAgreement
		case KeyUsageCertSign:
			keyUsage |= x509.KeyUsageCertSign
		case KeyUsageCRLSign:
			keyUsage |= x509.KeyUsageCRLSign
		case KeyUsageEncipherOnly:
			keyUsage |= x509.KeyUsageEncipherOnly
		case KeyUsageDecipherOnly:
			keyUsage |= x509.KeyUsageDecipherOnly
		}
	}

	return keyUsage
}

// ParseExtKeyUsage converts string representations to []x509.ExtKeyUsage
func ParseExtKeyUsage(usages []string) []x509.ExtKeyUsage {
	var extKeyUsage []x509.ExtKeyUsage

	for _, usage := range usages {
		switch usage {
		case ExtKeyUsageAny:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageAny)
		case ExtKeyUsageServerAuth:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
		case ExtKeyUsageClientAuth:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
		case ExtKeyUsageCodeSigning:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageCodeSigning)
		case ExtKeyUsageEmailProtection:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageEmailProtection)
		case ExtKeyUsageIPSECEndSystem:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageIPSECEndSystem)
		case ExtKeyUsageIPSECTunnel:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageIPSECTunnel)
		case ExtKeyUsageIPSECUser:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageIPSECUser)
		case ExtKeyUsageTimeStamping:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageTimeStamping)
		case ExtKeyUsageOCSPSigning:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageOCSPSigning)
		case ExtKeyUsageMicrosoftServerGatedCrypto:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
		case ExtKeyUsageNetscapeServerGatedCrypto:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageNetscapeServerGatedCrypto)
		case ExtKeyUsageMicrosoftCommercialCodeSigning:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
		case ExtKeyUsageMicrosoftKernelCodeSigning:
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
		}
	}

	return extKeyUsage
}

// ParseSignatureAlgorithm converts string representation to x509.SignatureAlgorithm
func ParseSignatureAlgorithm(alg string) x509.SignatureAlgorithm {
	switch alg {
	case SigAlgMD2WithRSA:
		return x509.MD2WithRSA
	case SigAlgMD5WithRSA:
		return x509.MD5WithRSA
	case SigAlgSHA1WithRSA:
		return x509.SHA1WithRSA
	case SigAlgSHA256WithRSA:
		return x509.SHA256WithRSA
	case SigAlgSHA384WithRSA:
		return x509.SHA384WithRSA
	case SigAlgSHA512WithRSA:
		return x509.SHA512WithRSA
	case SigAlgDSAWithSHA1:
		return x509.DSAWithSHA1
	case SigAlgDSAWithSHA256:
		return x509.DSAWithSHA256
	case SigAlgECDSAWithSHA1:
		return x509.ECDSAWithSHA1
	case SigAlgECDSAWithSHA256:
		return x509.ECDSAWithSHA256
	case SigAlgECDSAWithSHA384:
		return x509.ECDSAWithSHA384
	case SigAlgECDSAWithSHA512:
		return x509.ECDSAWithSHA512
	case SigAlgSHA256WithRSAPSS:
		return x509.SHA256WithRSAPSS
	case SigAlgSHA384WithRSAPSS:
		return x509.SHA384WithRSAPSS
	case SigAlgSHA512WithRSAPSS:
		return x509.SHA512WithRSAPSS
	case SigAlgPureEd25519:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// ParsePublicKeyAlgorithm converts string representation to x509.PublicKeyAlgorithm
func ParsePublicKeyAlgorithm(alg string) x509.PublicKeyAlgorithm {
	switch alg {
	case PubKeyAlgRSA:
		return x509.RSA
	case PubKeyAlgDSA:
		return x509.DSA
	case PubKeyAlgECDSA:
		return x509.ECDSA
	case PubKeyAlgEd25519:
		return x509.Ed25519
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}
