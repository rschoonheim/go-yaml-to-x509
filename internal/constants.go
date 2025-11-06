package internal

// Distinguished Name field constants
const (
	DNCommonName         = "common_name"
	DNCountry            = "country"
	DNOrganization       = "organization"
	DNOrganizationalUnit = "organizational_unit"
	DNLocality           = "locality"
	DNProvince           = "province"
	DNStreetAddress      = "street_address"
	DNPostalCode         = "postal_code"
	DNSerialNumber       = "serial_number"
)

// Key Usage constants
const (
	KeyUsageDigitalSignature  = "digital_signature"
	KeyUsageContentCommitment = "content_commitment"
	KeyUsageKeyEncipherment   = "key_encipherment"
	KeyUsageDataEncipherment  = "data_encipherment"
	KeyUsageKeyAgreement      = "key_agreement"
	KeyUsageCertSign          = "cert_sign"
	KeyUsageCRLSign           = "crl_sign"
	KeyUsageEncipherOnly      = "encipher_only"
	KeyUsageDecipherOnly      = "decipher_only"
)

// Extended Key Usage constants
const (
	ExtKeyUsageAny                            = "any"
	ExtKeyUsageServerAuth                     = "server_auth"
	ExtKeyUsageClientAuth                     = "client_auth"
	ExtKeyUsageCodeSigning                    = "code_signing"
	ExtKeyUsageEmailProtection                = "email_protection"
	ExtKeyUsageIPSECEndSystem                 = "ipsec_end_system"
	ExtKeyUsageIPSECTunnel                    = "ipsec_tunnel"
	ExtKeyUsageIPSECUser                      = "ipsec_user"
	ExtKeyUsageTimeStamping                   = "time_stamping"
	ExtKeyUsageOCSPSigning                    = "ocsp_signing"
	ExtKeyUsageMicrosoftServerGatedCrypto     = "microsoft_server_gated_crypto"
	ExtKeyUsageNetscapeServerGatedCrypto      = "netscape_server_gated_crypto"
	ExtKeyUsageMicrosoftCommercialCodeSigning = "microsoft_commercial_code_signing"
	ExtKeyUsageMicrosoftKernelCodeSigning     = "microsoft_kernel_code_signing"
)

// Signature Algorithm constants
const (
	SigAlgMD2WithRSA       = "MD2WithRSA"
	SigAlgMD5WithRSA       = "MD5WithRSA"
	SigAlgSHA1WithRSA      = "SHA1WithRSA"
	SigAlgSHA256WithRSA    = "SHA256WithRSA"
	SigAlgSHA384WithRSA    = "SHA384WithRSA"
	SigAlgSHA512WithRSA    = "SHA512WithRSA"
	SigAlgDSAWithSHA1      = "DSAWithSHA1"
	SigAlgDSAWithSHA256    = "DSAWithSHA256"
	SigAlgECDSAWithSHA1    = "ECDSAWithSHA1"
	SigAlgECDSAWithSHA256  = "ECDSAWithSHA256"
	SigAlgECDSAWithSHA384  = "ECDSAWithSHA384"
	SigAlgECDSAWithSHA512  = "ECDSAWithSHA512"
	SigAlgSHA256WithRSAPSS = "SHA256WithRSAPSS"
	SigAlgSHA384WithRSAPSS = "SHA384WithRSAPSS"
	SigAlgSHA512WithRSAPSS = "SHA512WithRSAPSS"
	SigAlgPureEd25519      = "PureEd25519"
)

// Public Key Algorithm constants
const (
	PubKeyAlgRSA     = "RSA"
	PubKeyAlgDSA     = "DSA"
	PubKeyAlgECDSA   = "ECDSA"
	PubKeyAlgEd25519 = "Ed25519"
)
