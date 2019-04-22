package cmd

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var rootCmd = &cobra.Command{
	Use:   "tlstool",
	Short: "TLSTool is a cli tool to easily generate TLS certificates",
	Long:  "TLSTool is a cli tool to easily generate TLS certificates without configuration files or having to setup a full PKI infrastructure",
	RunE:  genCertificate,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

const dateFormat = "15:04:05 02-01-2006"

var (
	//Private key variables
	KeyType    string
	ECKeySize  int
	RSAKeySize int

	KeyUsage = []struct {
		Enabled bool
		Bit     x509.KeyUsage
	}{
		{Bit: x509.KeyUsageDigitalSignature},
		{Bit: x509.KeyUsageContentCommitment},
		{Bit: x509.KeyUsageKeyEncipherment},
		{Bit: x509.KeyUsageDataEncipherment},
		{Bit: x509.KeyUsageKeyAgreement},
		{Bit: x509.KeyUsageCertSign},
		{Bit: x509.KeyUsageCRLSign},
		{Bit: x509.KeyUsageEncipherOnly},
		{Bit: x509.KeyUsageDecipherOnly},
	}

	ExtendedKeyUsage = []struct {
		Enabled bool
		Usage   x509.ExtKeyUsage
	}{
		{Usage: x509.ExtKeyUsageAny},
		{Usage: x509.ExtKeyUsageServerAuth},
		{Usage: x509.ExtKeyUsageClientAuth},
		{Usage: x509.ExtKeyUsageCodeSigning},
		{Usage: x509.ExtKeyUsageEmailProtection},
		{Usage: x509.ExtKeyUsageIPSECEndSystem},
		{Usage: x509.ExtKeyUsageIPSECTunnel},
		{Usage: x509.ExtKeyUsageIPSECUser},
		{Usage: x509.ExtKeyUsageTimeStamping},
		{Usage: x509.ExtKeyUsageOCSPSigning},
		{Usage: x509.ExtKeyUsageMicrosoftServerGatedCrypto},
		{Usage: x509.ExtKeyUsageNetscapeServerGatedCrypto},
		{Usage: x509.ExtKeyUsageMicrosoftCommercialCodeSigning},
		{Usage: x509.ExtKeyUsageMicrosoftKernelCodeSigning},
	}

	//Certificate variables
	ValidFrom              string
	ValidFor               int
	isCA                   bool
	maxPathLength          int
	ocspServers            []string
	issuingCertificateURLs []string
	crlDistributionPoints  []string

	Country, Organization, OrganizationalUnit []string
	Locality, Province                        []string
	StreetAddress, PostalCode                 []string
	SerialNumber, CommonName                  string

	ipAddresses    []net.IP
	emailAddresses []string
	domainNames    []string
	uris           []string

	CertificateFilename string
	KeyFilename         string

	ParentCertificate string
	ParentPrivateKey  string
)

func init() {
	flags := rootCmd.Flags()

	keyFlags := pflag.NewFlagSet("key-flags", pflag.ContinueOnError)
	keyFlags.StringVar(&KeyType, "key-type", "RSA", "The type of private key to be generated. Can be RSA or EC")
	keyFlags.IntVar(&ECKeySize, "ec-key-size", 256, "The bit size of the EC key. Allowed values: 224, 256, 384 and 521")
	keyFlags.IntVar(&RSAKeySize, "rsa-key-size", 4096, "The bit size of the RSA key. Allowed values: 1024, 2048, 4096, 8192")
	keyFlags.StringVar(&KeyFilename, "key-output", "certificate.key", "The path and filename where the key will be writen to")
	flags.AddFlagSet(keyFlags)

	keyUsageFlags := pflag.NewFlagSet("key-usage-flags", pflag.ContinueOnError)
	keyUsageFlags.BoolVar(&KeyUsage[0].Enabled, "key-usage-digital-signature", false, "Use when the public key is used with a digital signature mechanism to support security services other than non-repudiation, certificate signing, or CRL signing. A digital signature is often used for entity authentication and data origin authentication with integrity.")
	keyUsageFlags.BoolVar(&KeyUsage[1].Enabled, "key-usage-content-commitment", false, "Use when the public key is used to verify digital signatures used to provide a non-repudiation service. Non-repudiation protects against the signing entity falsely denying some action (excluding certificate or CRL signing).")
	keyUsageFlags.BoolVar(&KeyUsage[2].Enabled, "key-usage-key-encipherment", false, "Use when a certificate will be used with a protocol that encrypts keys. An example is S/MIME enveloping, where a fast (symmetric) key is encrypted with the public key from the certificate. SSL protocol also performs key encipherment.")
	keyUsageFlags.BoolVar(&KeyUsage[3].Enabled, "key-usage-data-encipherment", false, "Use when the public key is used for encrypting user data, other than cryptographic keys.")
	keyUsageFlags.BoolVar(&KeyUsage[4].Enabled, "key-usage-key-agreement", false, "Use when the sender and receiver of the public key need to derive the key without using encryption. This key can then can be used to encrypt messages between the sender and receiver. Key agreement is typically used with Diffie-Hellman ciphers.")
	keyUsageFlags.BoolVar(&KeyUsage[5].Enabled, "key-usage-cert-sign", false, "Use when the subject public key is used to verify a signature on certificates. This extension can be used only in CA certificates.")
	keyUsageFlags.BoolVar(&KeyUsage[6].Enabled, "key-usage-crl-sign", false, "Use when the subject public key is to verify a signature on revocation information, such as a CRL.")
	keyUsageFlags.BoolVar(&KeyUsage[7].Enabled, "key-usage-encipher-only", false, "Use only when key agreement is also enabled. This enables the public key to be used only for enciphering data while performing key agreement.")
	keyUsageFlags.BoolVar(&KeyUsage[8].Enabled, "key-usage-decipher-only", false, "Use only when key agreement is also enabled. This enables the public key to be used only for deciphering data while performing key agreement.")
	flags.AddFlagSet(keyUsageFlags)

	extendedKeyUsageFlags := pflag.NewFlagSet("extended-key-usage-flags", pflag.ContinueOnError)
	//TODO add description
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[0].Enabled, "ext-key-usage-any", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[1].Enabled, "ext-key-usage-server-auth", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[2].Enabled, "ext-key-usage-client-auth", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[3].Enabled, "ext-key-usage-code-signing", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[4].Enabled, "ext-key-usage-email-protection", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[5].Enabled, "ext-key-usage-ipsec-end-system", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[6].Enabled, "ext-key-usage-ipsec-tunnel", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[7].Enabled, "ext-key-usage-ipsec-user", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[8].Enabled, "ext-key-usage-time-stamping", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[9].Enabled, "ext-key-usage-ocsp-signing", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[10].Enabled, "ext-key-usage-microsoft-server-gated-crypto", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[11].Enabled, "ext-key-usage-netscape-server-gated-crypto", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[12].Enabled, "ext-key-usage-microsoft-commercial-code-signing", false, "")
	extendedKeyUsageFlags.BoolVar(&ExtendedKeyUsage[13].Enabled, "ext-key-usage-microsoft-kernel-code-signing", false, "")
	flags.AddFlagSet(extendedKeyUsageFlags)

	certFlags := pflag.NewFlagSet("cert-flags", pflag.ContinueOnError)
	certFlags.StringVar(&CertificateFilename, "cert-output", "certificate.crt", "The path and filename where the certificate will be writen to")
	certFlags.StringVar(&ValidFrom, "valid-from", time.Now().Format(dateFormat), "The date and time after which the certificate is valid")
	certFlags.IntVar(&ValidFor, "valid-for", 365*5, "For how many days the certificate is valid")
	certFlags.StringVar(&ParentCertificate, "parent-cert", "", "The path to the parent certificate which will be used to sign the generated certificate")
	certFlags.StringVar(&ParentPrivateKey, "parent-key", "", "The path to the private key of the certificate which will be used to sign the generated certificate")
	certFlags.BoolVar(&isCA, "is-ca", false, "If set a CA certificate will be created, meaning it can sign other certificates")
	certFlags.IntVar(&maxPathLength, "max-path-length", -1, "The maximum size of the subtree of this certificate. https://stackoverflow.com/questions/6616470/certificates-basic-constraints-path-length")
	certFlags.StringSliceVar(&ocspServers, "ocsp-server", []string{}, "The OCSP URI for this certificate. https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol")
	certFlags.StringSliceVar(&issuingCertificateURLs, "issuing-cert-uri", []string{}, "A URI where the issuing certificate can be downloaded from")
	certFlags.StringSliceVar(&crlDistributionPoints, "crl-distribution-point", []string{}, "A URI where a CRL can be requested")
	flags.AddFlagSet(certFlags)

	certSubjectFlags := pflag.NewFlagSet("cert-subject-flags", pflag.ContinueOnError)
	certSubjectFlags.StringSliceVar(&Country, "country", []string{}, "The country(s) of the subject of the certificate")
	certSubjectFlags.StringSliceVar(&Organization, "organization", []string{}, "The organization(s) of the subject of the certificate")
	certSubjectFlags.StringSliceVar(&OrganizationalUnit, "organizational-unit", []string{}, "The organizational units(s) of the subject of the certificate")
	certSubjectFlags.StringSliceVar(&Locality, "locality", []string{}, "The locality(s) of the subject of the certificate")
	certSubjectFlags.StringSliceVar(&Province, "province", []string{}, "The province(s) of the subject of the certificate")
	certSubjectFlags.StringSliceVar(&StreetAddress, "street-address", []string{}, "The street address(s) of the subject of the certificate")
	certSubjectFlags.StringSliceVar(&PostalCode, "postal-code", []string{}, "The postal code(s) of the subject of the certificate")
	certSubjectFlags.StringVar(&SerialNumber, "subject-serial-number", "", "The serial number of the subject of the certificate")
	certSubjectFlags.StringVar(&CommonName, "common-name", "", "The common name of the certificate")
	flags.AddFlagSet(certSubjectFlags)

	certUsageFlags := pflag.NewFlagSet("cert-usage-flags", pflag.ContinueOnError)
	certUsageFlags.IPSliceVar(&ipAddresses, "ip", []net.IP{}, "IP addresses allowed to use the generated certificate")
	certUsageFlags.StringSliceVar(&emailAddresses, "email", []string{}, "Email addresses allowed to use the generated certificate")
	certUsageFlags.StringSliceVar(&domainNames, "domain", []string{}, "Domain names allowed to use the generated certificate")
	certUsageFlags.StringSliceVar(&uris, "uri", []string{}, "URI's allowed to use the generated certificate")
	flags.AddFlagSet(certUsageFlags)

	cobra.AddTemplateFunc("printFlags", func() string {
		sb := strings.Builder{}

		sb.WriteString(fmt.Sprintln("Private key flags:"))
		sb.WriteString(keyFlags.FlagUsages())

		sb.WriteRune('\n')

		sb.WriteString(fmt.Sprintln("Certificate flags:"))
		sb.WriteString(certFlags.FlagUsages())

		sb.WriteRune('\n')

		sb.WriteString(fmt.Sprintln("Certificate subject flags:"))
		sb.WriteString(certSubjectFlags.FlagUsages())

		sb.WriteRune('\n')

		sb.WriteString(fmt.Sprintln("Certificate usage flags:"))
		sb.WriteString(certUsageFlags.FlagUsages())

		sb.WriteRune('\n')

		sb.WriteString(fmt.Sprintln("Key usage flags:"))
		sb.WriteString(keyUsageFlags.FlagUsages())

		sb.WriteRune('\n')

		sb.WriteString(fmt.Sprintln("Extended key usage flags:"))
		sb.WriteString(extendedKeyUsageFlags.FlagUsages())

		return sb.String()
	})

	rootCmd.SetUsageTemplate(usageTemplate)
}

func genCertificate(cmd *cobra.Command, args []string) error {

	var (
		err               error
		parentCertificate *x509.Certificate
		parentKey         interface{}
		hasParent         bool
	)

	if ParentCertificate != "" && ParentPrivateKey != "" {
		parentCertificate, err = pemFileToCert(ParentCertificate)
		if err != nil {
			return err
		}

		parentKey, err = pemFileToKey(ParentPrivateKey)
		if err != nil {
			return err
		}

		hasParent = true
	} else if ParentCertificate != "" || ParentPrivateKey != "" {
		return errors.New("Both parent-cert and parent-key should be set or neither should be set")
	}

	keyType := strings.ToLower(KeyType)

	var (
		ecKey  *ecdsa.PrivateKey
		rsaKey *rsa.PrivateKey
	)

	if keyType == "ec" {
		ecKey, err = generateECPrivateKey(ECKeySize)
		if err != nil {
			return err
		}

		if err := ecKeyToFile(KeyFilename, ecKey); err != nil {
			return err
		}
	} else if keyType == "rsa" {
		rsaKey, err = generateRSAPriveKey(RSAKeySize)

		if err := rsaKeyToFile(KeyFilename, rsaKey); err != nil {
			return err
		}
	} else {
		return errors.Errorf("%s is not a valid value for key-type, valid values: RSA and EC\n", KeyType)
	}

	notBefore, err := time.Parse(dateFormat, ValidFrom)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.Errorf("failed to generate serial number: %s", err)
	}

	var keyUsageCompiled x509.KeyUsage
	for _, flag := range KeyUsage {
		if flag.Enabled {
			keyUsageCompiled |= flag.Bit
		}
	}

	var extendedKeyUsageCompiled []x509.ExtKeyUsage
	for _, flag := range ExtendedKeyUsage {
		if flag.Enabled {
			extendedKeyUsageCompiled = append(extendedKeyUsageCompiled, flag.Usage)
		}
	}

	var urisCompiled []*url.URL
	for _, uri := range uris {
		newURI, err := url.Parse(uri)
		if err != nil {
			return err
		}

		urisCompiled = append(urisCompiled, newURI)
	}

	intermediateTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            Country,
			Organization:       Organization,
			OrganizationalUnit: OrganizationalUnit,
			Locality:           Locality,
			Province:           Province,
			StreetAddress:      StreetAddress,
			SerialNumber:       SerialNumber,
			CommonName:         CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, ValidFor),
		KeyUsage:              keyUsageCompiled,
		ExtKeyUsage:           extendedKeyUsageCompiled,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		MaxPathLen:            maxPathLength,
		MaxPathLenZero:        true,
		IPAddresses:           ipAddresses,
		DNSNames:              domainNames,
		EmailAddresses:        emailAddresses,
		URIs:                  urisCompiled,
		OCSPServer:            ocspServers,
		IssuingCertificateURL: issuingCertificateURLs,
		CRLDistributionPoints: crlDistributionPoints,
	}

	if !hasParent {
		parentCertificate = &intermediateTemplate

		if keyType == "ec" {
			parentKey = ecKey
		} else {
			parentKey = rsaKey
		}
	}

	var derBytes []byte
	if keyType == "ec" {
		derBytes, err = x509.CreateCertificate(rand.Reader, &intermediateTemplate, parentCertificate, &ecKey.PublicKey, parentKey)
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, &intermediateTemplate, parentCertificate, rsaKey.Public(), parentKey)
	}

	if err != nil {
		return err
	}

	if err := certToFile(CertificateFilename, derBytes); err != nil {
		return err
	}

	return nil
}

var usageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{printFlags | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
