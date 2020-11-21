package cmd

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
)

func newGenCertCmd() *cobra.Command {
	genCertCmd := &generateCertificateCommand{}
	return genCertCmd.GetCobraCommand()
}

type generateCertificateCommand struct {
	// The path where the certificate will be written to
	OutputPath string
	// The path to the private key used to create the certificate
	PrivateKeyPath string
	// The password to the private key used to create the certifcate
	PrivateKeyPassword string

	// The certificate used to sign the certificate we are generating
	ParentCertificate string
	// The private key of the parent certificate
	ParentPrivateKey string
	// The password of the parent private key
	ParentPrivateKeyPassword string

	// Preset specifies which defaults to use for a number of common certificate types
	Preset string

	// The key usage of the certificate to be generated
	KeyUsage []string
	// The extended key usage of the certificate to be generated
	ExtendedKeyUsage []string

	// The not before date of the certificate
	NotBefore string
	// The not after date of the certificate
	NotAfter string
	// The amount of days the certificate is valid for (excludes the usage of NotAfter)
	ValidFor time.Duration

	// True, if the certifcate is a certificate authority
	IsCA bool
	// The maximum length of the certificate chain below this certificate
	MaxPathLength int

	// The subject of the certifcate
	Subject pkix.Name

	SerialNumber int64

	IPAddresses    []net.IP
	EmailAddresses []string
	DomainNames    []string
	URIs           []string
}

const dateFormat = "15:04:05 02-01-2006"

func (gcc *generateCertificateCommand) GetCobraCommand() *cobra.Command {
	cobraCommand := &cobra.Command{
		Use: "cert",
		Aliases: []string{
			"certificate",
		},
		Short: "Generate a X.509 certificate",
		RunE:  gcc.Run,
	}

	flags := cobraCommand.Flags()
	flags.StringVarP(&gcc.OutputPath, "output", "o", "", "Path where the certificate will be written to.")
	flags.StringVarP(&gcc.PrivateKeyPath, "private-key", "k", "", "The path of the private key used to generate the certificate")
	flags.StringVarP(&gcc.PrivateKeyPassword, "private-key-password", "P", "", "The password (if any) of the private key")
	flags.StringVar(&gcc.ParentCertificate, "parent-certificate", "", "The path to the certificate which will sign this new certificate")
	flags.StringVar(&gcc.ParentPrivateKey, "parent-private-key", "", "The path to the private key of the parent certificate")
	flags.StringVar(&gcc.ParentPrivateKeyPassword, "parent-private-key-password", "", "The password (if any) of the private key of the parent certificate")
	flags.StringVarP(&gcc.Preset, "preset", "p", "", "The preset to use, sane defaults per certificate type.\n"+
		"Allowed values: (\n"+
		"\t'none' - No default values, all up to you\n"+
		"\t'server-leaf-certificate' - Leaf certificate for use as a server certificate\n"+
		"\t'client-leaf-certificate' - Leaf certificate for use as a client certificate\n"+
		"\t'root-ca' - Root certificate authority certificate\n"+
		"\t'intermediate-ca' - Intermediate certificate authority\n"+
		")",
	)
	flags.StringArrayVarP(&gcc.KeyUsage, "usage", "u", []string{}, "The allowed uses of the certificate.\n"+
		"Allowed values: (\n"+
		"\t'digital-signature' - This certificate may be used to create digital signatures other than signing X.509 certs and CRLs\n"+
		"\t'content-commitment' - This certificate may be used to created digital signatures for the purposes of\n\t  non-repudiation(preventing data change) on data other than X.509 certs and CRLs\n"+
		"\t'key-encipherment' - This certificate may be used to encrypt private keys like during the transport of\n\t  symmetric keys of a TLS Cipher\n"+
		"\t'data-encipherment' - This certificate may be used to encrypt data directly\n"+
		"\t'key-agreement' - This certificate may be used for key agreement (only use by DH public keys)\n"+
		"\t'cert-sign' - This certificate may be used to sign other X.509 certificates\n"+
		"\t'crl-sign' - This certificate may be used to sign CRls (certificate revocation lists)\n"+
		"\t'encipher-only' - This certificate may be used, only to encipher data during key agreement\n"+
		"\t'decipher-only' - This certificate may be used, only to decipher data during key agreement\n"+
		")",
	)
	flags.StringArrayVarP(&gcc.ExtendedKeyUsage, "ext-usage", "e", []string{}, "The allowed extended uses of the certificate.\n"+
		"Allowed values: (\n"+
		"\t'any' - This certificate may be used for for multiple extended usage,\n\t  applications should not reject this certificate if is has to many usages\n"+
		"\t'server-auth' - This certificate may be used for TLS WWW server authentication\n"+
		"\t'client-auth' - This certificate may be used for TLS WWW client authentication\n"+
		"\t'code-signing' - This certificate may be used to sign executable code\n"+
		"\t'email-protection' - This certificate may be used to sign emails\n"+
		"\t'time-stamping' - This certificate may be used to bind a hash of a object to a time\n"+
		"\t'ocsp-signing' - This certificate may be used sign OSCP responses\n"+
		"\t'x.x.x.x.x.x.x.x.x' - Specify any OID you want to add to the extended-key-usage of the certificate\n"+
		")",
	)

	flags.StringVar(&gcc.NotBefore, "not-before", "now", "The date and time after which the certificate is valid (hh:mm:ss dd:mm:yyyy)")
	flags.StringVar(&gcc.NotAfter, "not-after", "", "The date and time after which this certificate is no longer valid (hh:mm:ss dd:mm:yyyy)")
	flags.DurationVar(&gcc.ValidFor, "valid-for", 0, "The amount of time the certificate is valid for since valid-after ([xxd][xxh][xxm][xxs], 1d2h3m3s, 120m)")

	flags.BoolVar(&gcc.IsCA, "is-ca", false, "This certificate may be used as a CA")
	flags.IntVar(&gcc.MaxPathLength, "max-path-length", -1, "The maximum length of the certificate chain below this certificate")

	// TODO add remaining extension fields (OCSP, Issuing URI, CRL)

	flags.Int64Var(&gcc.SerialNumber, "serial-number", -1, "The serial number of the certificate, random by default")

	flags.StringArrayVar(&gcc.Subject.Country, "subject-country", []string{}, "The county field of the subject")
	flags.StringArrayVar(&gcc.Subject.Organization, "subject-organization", []string{}, "The organization field of the subject")
	flags.StringArrayVar(&gcc.Subject.OrganizationalUnit, "subject-organizational-unit", []string{}, "The organizational unit field of the subject")
	flags.StringArrayVar(&gcc.Subject.Locality, "subject-locality", []string{}, "The locality field of the subject")
	flags.StringArrayVar(&gcc.Subject.Province, "subject-provice", []string{}, "The province unit field of the subject")
	flags.StringArrayVar(&gcc.Subject.StreetAddress, "subject-street-address", []string{}, "The street address field of the subject")
	flags.StringArrayVar(&gcc.Subject.PostalCode, "subject-postal-code", []string{}, "The postal code field of the subject")
	flags.StringVar(&gcc.Subject.CommonName, "subject-common-name", "", "The common name field of the subject")
	flags.StringVar(&gcc.Subject.SerialNumber, "subject-serial-number", "", "The serial number field of the subject")

	//TODO add custom OID option for subject

	flags.IPSliceVar(&gcc.IPAddresses, "san-ip", []net.IP{}, "Subject alternative name - IP addresses allowed to use the generated certificate")
	flags.StringSliceVar(&gcc.EmailAddresses, "san-email", []string{}, "Subject alternative name - email addresses allowed to use the generated certificate")
	flags.StringSliceVar(&gcc.DomainNames, "san-domain", []string{}, "Subject alternative name - domain names allowed to use the generated certificate")
	flags.StringSliceVar(&gcc.URIs, "san-uri", []string{}, "Subject alternative name - URIs allowed to use the generated certificate")

	return cobraCommand
}

func (gcc *generateCertificateCommand) checkFlags(command *cobra.Command) error {
	nonInteractive, err := command.Flags().GetBool(nonInteractiveFlag)
	if err != nil {
		panic(err)
	}

	err = gcc.setPreset(nonInteractive, command)
	if err != nil {
		return err
	}

	if err = gcc.checkFlagOutput(nonInteractive); err != nil {
		return err
	}

	if err = gcc.checkFlagPrivateKey(nonInteractive); err != nil {
		return err
	}

	if err = gcc.checkFlagParent(nonInteractive); err != nil {
		return err
	}

	if err = gcc.checkFlagKeyUsage(nonInteractive); err != nil {
		return err
	}

	if err = gcc.checkFlagExtendedKeyUsage(nonInteractive); err != nil {
		return err
	}

	if err = gcc.checkFlagValidity(nonInteractive); err != nil {
		return err
	}

	if err = gcc.checkFlagMaxCAPath(nonInteractive); err != nil {
		return err
	}

	if err = gcc.checkFlagsSubject(nonInteractive); err != nil {
		return err
	}

	if err = gcc.checkFlagSerialNumber(nonInteractive); err != nil {
		return err
	}

	// TODO check SAN flags

	return nil
}

func (gcc *generateCertificateCommand) checkFlagsSubject(nonInteractiveFlag bool) error {
	subjectCount := len(gcc.Subject.Country) +
		len(gcc.Subject.Organization) +
		len(gcc.Subject.OrganizationalUnit) +
		len(gcc.Subject.Locality) +
		len(gcc.Subject.Province) +
		len(gcc.Subject.StreetAddress) +
		len(gcc.Subject.PostalCode)

	// is at least one subject flag is set?
	subjectFlagSet := gcc.Subject.CommonName != "" ||
		gcc.Subject.SerialNumber != "" ||
		subjectCount > 0

	// If nonInteractive mode, don't prompt
	if nonInteractiveFlag {
		if !subjectFlagSet {
			// TODO warn user if no subject flags are set
		}

		return nil
	}

	var wantSubject bool
	err := survey.AskOne(&survey.Confirm{
		Message: "Do you want to set a subject?",
		Default: !subjectFlagSet,
	}, &wantSubject,
		survey.WithValidator(survey.Required),
	)
	if err != nil {
		return err
	}
	if !wantSubject {
		return nil
	}

	splitStr := func(ans string) []string {
		if strings.TrimSpace(ans) == "" {
			return nil
		}

		split := strings.Split(ans, ",")
		for i, str := range split {
			split[i] = strings.TrimSpace(str)
		}
		return split
	}

	qs := []*survey.Question{
		&survey.Question{
			Name: "CommonName",
			Prompt: &survey.Input{
				Message: "Common name:",
				Default: gcc.Subject.CommonName,
			},
		},
		&survey.Question{
			Name: "Organization",
			Prompt: &survey.Input{
				Message: "Organization:",
				Default: strings.Join(gcc.Subject.Organization, ","),
				Help:    "Comma seperated list",
			},
		},
		&survey.Question{
			Name: "OrganizationalUnit",
			Prompt: &survey.Input{
				Message: "Organizational unit:",
				Default: strings.Join(gcc.Subject.OrganizationalUnit, ","),
				Help:    "Comma seperated list",
			},
		},
		&survey.Question{
			Name: "Country",
			Prompt: &survey.Input{
				Message: "Country:",
				Default: strings.Join(gcc.Subject.Country, ","),
				Help:    "Comma seperated list",
			},
		},
		&survey.Question{
			Name: "Province",
			Prompt: &survey.Input{
				Message: "Province:",
				Default: strings.Join(gcc.Subject.Province, ","),
				Help:    "Comma seperated list",
			},
		},
		&survey.Question{
			Name: "Locality",
			Prompt: &survey.Input{
				Message: "Locality:",
				Default: strings.Join(gcc.Subject.Locality, ","),
				Help:    "Comma seperated list",
			},
		},
		&survey.Question{
			Name: "PostalCode",
			Prompt: &survey.Input{
				Message: "Postal code:",
				Default: strings.Join(gcc.Subject.PostalCode, ","),
				Help:    "Comma seperated list",
			},
		},
		&survey.Question{
			Name: "StreetAddress",
			Prompt: &survey.Input{
				Message: "Street address:",
				Default: strings.Join(gcc.Subject.StreetAddress, ","),
				Help:    "Comma seperated list",
			},
		},
		&survey.Question{
			Name: "SerialNumber",
			Prompt: &survey.Input{
				Message: "Serial number:",
				Default: gcc.Subject.SerialNumber,
			},
		},
	}

	answers := struct {
		CommonName         string
		Organization       string
		OrganizationalUnit string
		Country            string
		Province           string
		Locality           string
		PostalCode         string
		StreetAddress      string
		SerialNumber       string
	}{}

	err = survey.Ask(qs, &answers)
	if err != nil {
		return err
	}

	gcc.Subject = pkix.Name{
		CommonName:         answers.CommonName,
		Organization:       splitStr(answers.Organization),
		OrganizationalUnit: splitStr(answers.OrganizationalUnit),
		Country:            splitStr(answers.Country),
		Province:           splitStr(answers.Province),
		Locality:           splitStr(answers.Locality),
		PostalCode:         splitStr(answers.PostalCode),
		StreetAddress:      splitStr(answers.StreetAddress),
		SerialNumber:       answers.SerialNumber,
	}

	return nil
}

func validateDate(val interface{}) error {
	date, ok := val.(string)
	if !ok {
		return fmt.Errorf("Input is not a string")
	}

	_, err := time.Parse(dateFormat, date)
	return err
}

func validateDuration(val interface{}) error {
	str, ok := val.(string)
	if !ok {
		return fmt.Errorf("Input is not a string")
	}

	_, err := ParseDuration(str)
	return err
}

func validatePositiveInt64(val interface{}) error {
	str, ok := val.(string)
	if !ok {
		return fmt.Errorf("Input is not a string")
	}

	i, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return err
	}
	if i < 0 {
		return fmt.Errorf("Input must be a positive integer")
	}
	return err
}

func (gcc *generateCertificateCommand) checkFlagSerialNumber(nonInteractiveFlag bool) error {
	if gcc.SerialNumber < -1 {
		return fmt.Errorf("'%d' is not a valid value for --serial-number", gcc.SerialNumber)
	}

	// If the serial number is set, or we can't prompt. Use a random number
	if gcc.SerialNumber != -1 || nonInteractiveFlag {
		return nil
	}

	var wantRandom bool
	err := survey.AskOne(&survey.Confirm{
		Message: "Do you want a random serial number?",
		Default: true,
	}, &wantRandom,
		survey.WithValidator(survey.Required),
	)
	if err != nil {
		return err
	}

	if wantRandom {
		return nil
	}

	var serialNumberStr string
	err = survey.AskOne(&survey.Input{
		Message: "Serial number: ",
	}, serialNumberStr,
		survey.WithValidator(survey.Required),
		survey.WithValidator(validatePositiveInt64),
	)
	if err != nil {
		return err
	}

	gcc.SerialNumber, err = strconv.ParseInt(serialNumberStr, 10, 64)
	if err != nil {
		return err
	}

	return nil
}

func (gcc *generateCertificateCommand) checkFlagValidity(nonInteractiveFlag bool) error {
	if gcc.NotBefore == "now" || gcc.NotBefore == "" {
		gcc.NotBefore = time.Now().Format(dateFormat)
	}

	_, err := time.Parse(dateFormat, gcc.NotBefore)
	if err != nil {
		if nonInteractiveFlag {
			return fmt.Errorf("'%s' is an invalid value for --not-before", gcc.NotBefore)
		}

		fmt.Printf("'%s' is an invalid value for --not-before, please input a correct date-time\n", gcc.NotBefore)

		err := survey.AskOne(&survey.Input{
			Message: "Not before date-time:",
		}, &gcc.NotBefore,
			survey.WithValidator(survey.Required),
			survey.WithValidator(validateDate),
		)
		if err != nil {
			return err
		}
	}

	if gcc.NotAfter == "" && gcc.ValidFor == 0 {
		if nonInteractiveFlag {
			return fmt.Errorf("Either --not-after or --valid-for must be set")
		}

		var validFor string

		err := survey.AskOne(&survey.Input{
			Message: "For how long is the certificate valid? (format: 1y2d3m4s) ",
		}, &validFor,
			survey.WithValidator(survey.Required),
			survey.WithValidator(validateDuration),
		)
		if err != nil {
			return err
		}

		gcc.ValidFor, err = ParseDuration(validFor)
		if err != nil {
			return err
		}
	}

	if gcc.NotAfter != "" {
		_, err := time.Parse(dateFormat, gcc.NotAfter)
		if err != nil {
			if nonInteractiveFlag {
				return fmt.Errorf("'%s' is an invalid value for --not-after", gcc.NotAfter)
			}

			fmt.Printf("'%s' is an invalid value for --not-after, please input a correct date-time\n", gcc.NotAfter)

			err := survey.AskOne(&survey.Input{
				Message: "Not after date-time:",
			}, &gcc.NotAfter,
				survey.WithValidator(survey.Required),
				survey.WithValidator(validateDate),
			)
			if err != nil {
				return err
			}
		}
	}

	if gcc.ValidFor != 0 {
		if gcc.NotAfter != "" {
			return fmt.Errorf("Either --not-after or --valid-for must be set, not both")
		}

		if gcc.ValidFor < 0 {
			return fmt.Errorf("--valid-for must be a positive duration")
		}
	}

	return nil
}

// privateKeyValidator validates that a given value is a path to a valid private key
func privateKeyValidator(val interface{}) error {
	path, ok := val.(string)
	if !ok {
		return fmt.Errorf("Input is not a string")
	}

	_, err := fileToPrivateKey(path, []byte{})
	if err != nil && err != errKeyEncrypted {
		return err
	}

	return nil
}

func (gcc *generateCertificateCommand) privateKeyPasswordValidator(val interface{}) error {
	password, ok := val.(string)
	if !ok {
		return fmt.Errorf("Input is not a string")
	}

	_, err := fileToPrivateKey(gcc.PrivateKeyPath, []byte(password))
	if err != nil {
		if err == errKeyEncrypted {
			return fmt.Errorf("incorrect password")
		}

		return err
	}

	return nil
}

func (gcc *generateCertificateCommand) checkFlagParent(nonInteractiveFlag bool) error {
	certSet := gcc.ParentCertificate != ""
	keySet := gcc.ParentPrivateKey != ""
	passwordSet := gcc.PrivateKeyPassword != ""

	// If all paths are set, all is good.
	if certSet && keySet && passwordSet {
		return nil
	}

	// If no flags are set, and the preset is root-ca, this is normal behavior
	if !certSet && !keySet && !passwordSet && gcc.Preset == "root-ca" {
		return nil
	}

	askCert := func() error {
		err := survey.AskOne(&survey.Input{
			Message: "Parent certificate path:",
		}, &gcc.ParentCertificate,
			survey.WithValidator(survey.Required),
		)
		if err != nil {
			return err
		}

		return nil
	}

	askKey := func() error {
		err := survey.AskOne(&survey.Input{
			Message: "Parent private key path:",
		}, &gcc.ParentPrivateKey,
			survey.WithValidator(survey.Required),
			survey.WithValidator(privateKeyValidator),
		)
		if err != nil {
			return err
		}

		return nil
	}

	askPassword := func() error {
		err := survey.AskOne(&survey.Password{
			Message: "Parent private key password:",
		}, &gcc.ParentPrivateKeyPassword)
		//TODO make parent key validator
		if err != nil {
			return err
		}

		return nil
	}

	// At least one flag is set, but not the others
	if certSet || keySet || passwordSet {
		if !certSet {
			if nonInteractiveFlag {
				return fmt.Errorf("The --parent-certificate flag must be set if " +
					"the --parent-private-key or --parent-private-key-password flags are set")
			}

			if err := askCert(); err != nil {
				return err
			}
		}

		if !keySet {
			if nonInteractiveFlag {
				return fmt.Errorf("The --parent-private-key flag must be set if " +
					"the --parent-certificate or --parent-private-key-password flags are set")
			}

			if err := askKey(); err != nil {
				return err
			}
		}

		if !passwordSet {
			if nonInteractiveFlag {
				return fmt.Errorf("The --parent-private-key-password flag must be set if " +
					"the --parent-certificate or --parent-private-key flags are set")
			}

			if err := askPassword(); err != nil {
				return err
			}
		}
	} else {
		if nonInteractiveFlag {
			return nil
		}

		var askVars bool
		survey.AskOne(&survey.Confirm{
			Message: "Would you like to sign this certificate with a parent certificate",
		}, &askVars)
		if askVars {
			if err := askCert(); err != nil {
				return err
			}
			if err := askKey(); err != nil {
				return err
			}
			if err := askPassword(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (gcc *generateCertificateCommand) checkFlagPrivateKey(nonInteractiveFlag bool) error {
	if gcc.PrivateKeyPath == "" {
		if nonInteractiveFlag {
			return fmt.Errorf("The --private-key flag must be set")
		}

		fmt.Println("No private key path specified, please specify one")

		err := survey.AskOne(&survey.Input{
			Message: "Private key path:",
		}, &gcc.PrivateKeyPath,
			survey.WithValidator(survey.Required),
			survey.WithValidator(privateKeyValidator),
		)
		if err != nil {
			return err
		}

		if _, err = fileToPrivateKey(gcc.PrivateKeyPath, []byte(gcc.PrivateKeyPassword)); err == errKeyEncrypted {
			if nonInteractiveFlag {
				return fmt.Errorf("the private key is encrypted and the supplied password is incorrect")
			}

			fmt.Println("Password for the private key is incorrect, input the correct password")

			err := survey.AskOne(&survey.Password{
				Message: "Private key password:",
			}, &gcc.PrivateKeyPassword,
				survey.WithValidator(survey.Required),
				survey.WithValidator(gcc.privateKeyPasswordValidator),
			)
			if err != nil {
				return err
			}

		}
	}

	return nil
}

func (gcc *generateCertificateCommand) checkFlagOutput(nonInteractive bool) error {
	if gcc.OutputPath != "" {
		//TODO validate that we can create a file at that path
		return nil
	}

	if nonInteractive {
		return fmt.Errorf("The --output flag must be set")
	}

	fmt.Println("No certificate output path specified, please specify one")

	err := survey.AskOne(&survey.Input{
		Message: "Output path:",
	}, &gcc.OutputPath, survey.WithValidator(survey.Required))
	//TODO validate that we can create a file at that path
	if err != nil {
		return err
	}

	return nil
}

var (
	keyUsageStrings = []string{
		"digital-signature",
		"content-commitment",
		"key-encipherment",
		"key-agreement",
		"cert-sign",
		"crl-sign",
		"encipher-only",
		"decipher-only",
	}
	keyUsageTranslation = map[string]x509.KeyUsage{
		keyUsageStrings[0]: x509.KeyUsageDigitalSignature,
		keyUsageStrings[1]: x509.KeyUsageContentCommitment,
		keyUsageStrings[2]: x509.KeyUsageKeyEncipherment,
		keyUsageStrings[3]: x509.KeyUsageKeyAgreement,
		keyUsageStrings[4]: x509.KeyUsageCertSign,
		keyUsageStrings[5]: x509.KeyUsageCRLSign,
		keyUsageStrings[6]: x509.KeyUsageEncipherOnly,
		keyUsageStrings[7]: x509.KeyUsageDecipherOnly,
	}
)

func (gcc *generateCertificateCommand) checkFlagKeyUsage(nonInteractive bool) error {
	if len(gcc.KeyUsage) == 0 {
		if nonInteractive {
			return fmt.Errorf("At least one --key-usage flag must be set")
		}

		fmt.Println("No key usage specified")

		err := survey.AskOne(&survey.MultiSelect{
			Message: "Key usage:",
			Options: keyUsageStrings,
		}, &gcc.KeyUsage)
		if err != nil {
			return err
		}

	} else {
		for _, keyUsage := range gcc.KeyUsage {
			if _, found := keyUsageTranslation[keyUsage]; !found {
				return fmt.Errorf("'%s', is not a valid value for the --key-usage flag", keyUsage)
			}
		}
	}

	return nil
}

func validateOID(val interface{}) error {
	if err := survey.Required(val); err != nil {
		return err
	}

	strVal := val.(string)
	strParts := strings.Split(strVal, ".")
	for _, p := range strParts {
		i, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("'%s' is not a valid OID", strVal)
		}
		if i < 0 {
			return fmt.Errorf("'%s' is not a valid OID", strVal)
		}
	}

	return nil
}

var (
	extendedKeyUsageStrings = []string{
		"any",
		"server-auth",
		"client-auth",
		"code-signing",
		"time-stamping",
		"ocsp-signing",
	}
	extendedKeyUsageTranslation = map[string]x509.ExtKeyUsage{
		extendedKeyUsageStrings[0]: x509.ExtKeyUsageAny,
		extendedKeyUsageStrings[1]: x509.ExtKeyUsageServerAuth,
		extendedKeyUsageStrings[2]: x509.ExtKeyUsageClientAuth,
		extendedKeyUsageStrings[3]: x509.ExtKeyUsageCodeSigning,
		extendedKeyUsageStrings[4]: x509.ExtKeyUsageTimeStamping,
		extendedKeyUsageStrings[5]: x509.ExtKeyUsageOCSPSigning,
	}
)

func (gcc *generateCertificateCommand) checkFlagExtendedKeyUsage(nonInteractive bool) error {
	const customExtKeyOID = "custom extended key usage OID"

	validExtKeyUsage := make([]string, 0, len(extendedKeyUsageStrings)+1)
	validExtKeyUsage = append(validExtKeyUsage, extendedKeyUsageStrings...)
	validExtKeyUsage = append(validExtKeyUsage, customExtKeyOID)

	if len(gcc.ExtendedKeyUsage) != 0 {
		for _, extKeyUsage := range gcc.ExtendedKeyUsage {
			if _, found := extendedKeyUsageTranslation[extKeyUsage]; !found {
				return fmt.Errorf("'%s', is not a valid value for the --ext-key-usage flag", extKeyUsage)
			}
		}

		return nil
	}

	if nonInteractive || gcc.Preset == "root-ca" || gcc.Preset == "intermediate-ca" {
		return nil
	}

	fmt.Println("No extended key usage specified")

	addExtKey := false
	err := survey.AskOne(&survey.Confirm{
		Message: "Would you like to specify extended key usage?",
		Default: true,
	}, &addExtKey, survey.WithValidator(survey.Required))
	if err != nil {
		return err
	}

	if !addExtKey {
		return nil
	}

	err = survey.AskOne(&survey.MultiSelect{
		Message: "Extended key usage:",
		Options: validExtKeyUsage,
	}, &gcc.ExtendedKeyUsage)
	if err != nil {
		return err
	}

	addCustom := false
	for _, v := range gcc.ExtendedKeyUsage {
		if v == customExtKeyOID {
			addCustom = true
			break
		}
	}

	if !addCustom {
		return nil
	}

	addAnother := true
	for addAnother {
		var newExtKey string

		err = survey.AskOne(&survey.Input{
			Message: "Extended key usage OID:",
		}, &newExtKey, survey.WithValidator(validateOID))
		if err != nil {
			return err
		}

		gcc.ExtendedKeyUsage = append(gcc.ExtendedKeyUsage, newExtKey)

		err = survey.AskOne(&survey.Confirm{
			Message: "Do you want to add another extended key usage?",
		}, &addAnother)
		if err != nil {
			return err
		}
	}

	return nil
}

func (gcc *generateCertificateCommand) checkFlagMaxCAPath(nonInteractive bool) error {
	if gcc.MaxPathLength < -1 {
		return fmt.Errorf("'%d' is a invalid value for --max-path-length", gcc.MaxPathLength)
	}

	return nil
}

func (gcc *generateCertificateCommand) setPreset(nonInteractive bool, command *cobra.Command) error {
	if gcc.Preset == "" {
		if nonInteractive {
			gcc.Preset = "none"
		} else {
			err := survey.AskOne(&survey.Select{
				Message: "Certificate preset:",
				Default: "server-leaf-certificate",
				Options: []string{
					"none",
					"server-leaf-certificate",
					"client-leaf-certificate",
					"root-ca",
					"intermediate-ca",
				},
			}, &gcc.Preset, survey.WithValidator(survey.Required))
			if err != nil {
				return err
			}
		}
	}

	switch gcc.Preset {
	case "none":
		return nil
	case "server-leaf-certificate":
		// TODO, throw warning if values will produce a incorrect certificate for the preset
		if len(gcc.KeyUsage) == 0 {
			gcc.KeyUsage = []string{"digital-signature", "key-encipherment"}
		}

		// TODO, throw warning if values will produce a incorrect certificate for the preset
		if len(gcc.ExtendedKeyUsage) == 0 {
			gcc.ExtendedKeyUsage = []string{"server-auth"}
		}

		if gcc.NotAfter == "" && gcc.ValidFor == 0 {
			gcc.ValidFor = 365 * 24 * time.Hour
		}

		// TODO, throw warning if is-ca is true
	case "client-leaf-certificate":
		// TODO, throw warning if values will produce a incorrect certificate for the preset
		if len(gcc.KeyUsage) == 0 {
			gcc.KeyUsage = []string{"digital-signature"}
		}

		// TODO, throw warning if values will produce a incorrect certificate for the preset
		if len(gcc.ExtendedKeyUsage) == 0 {
			gcc.ExtendedKeyUsage = []string{"client-auth"}
		}

		if gcc.NotAfter == "" && gcc.ValidFor == 0 {
			gcc.ValidFor = 365 * 24 * time.Hour
		}

		// TODO, throw warning if is-ca is true
	case "root-ca":
		// TODO, throw warning if values will produce a incorrect certificate for the preset
		if len(gcc.KeyUsage) == 0 {
			gcc.KeyUsage = []string{"cert-sign", "crl-sign"}
		}

		if gcc.NotAfter == "" && gcc.ValidFor == 0 {
			gcc.ValidFor = 5 * 365 * 24 * time.Hour
		}

		// TODO, throw warning if is-ca is false
		if !command.Flags().Changed("is-ca") {
			gcc.IsCA = true
		}
	case "intermediate-ca":
		// TODO, throw warning if values will produce a incorrect certificate for the preset
		if len(gcc.KeyUsage) == 0 {
			gcc.KeyUsage = []string{"cert-sign", "crl-sign"}
		}

		if gcc.NotAfter == "" && gcc.ValidFor == 0 {
			gcc.ValidFor = 3 * 365 * 24 * time.Hour
		}

		// TODO, throw warning if is-ca is false
		if !command.Flags().Changed("is-ca") {
			gcc.IsCA = true
		}

		if !command.Flags().Changed("max-path-length") {
			gcc.MaxPathLength = 1
		}
	default:
		return fmt.Errorf("'%s' is not a valid value for --preset", gcc.Preset)
	}

	return nil
}

func (gcc *generateCertificateCommand) Run(command *cobra.Command, args []string) error {
	if err := gcc.checkFlags(command); err != nil {
		return err
	}

	pkey, err := fileToPrivateKey(gcc.PrivateKeyPath, []byte(gcc.PrivateKeyPassword))
	if err != nil {
		return err
	}

	var notAfter time.Time
	if gcc.NotAfter == "" {
		notAfter = time.Now().Add(gcc.ValidFor)
	} else {
		notAfter, err = time.Parse(dateFormat, gcc.NotAfter)
		if err != nil {
			return err
		}
	}

	notBefore, err := time.Parse(dateFormat, gcc.NotBefore)
	if err != nil {
		return err
	}

	var keyUsage x509.KeyUsage
	for _, usage := range gcc.KeyUsage {
		keyUsage |= keyUsageTranslation[usage]
	}

	var extKeyUsage []x509.ExtKeyUsage
	for _, usage := range gcc.ExtendedKeyUsage {
		extKeyUsage = append(extKeyUsage, extendedKeyUsageTranslation[usage])
	}

	var uris []*url.URL
	for _, uriStr := range gcc.URIs {
		uri, err := url.Parse(uriStr)
		if err != nil {
			return err
		}

		uris = append(uris, uri)
	}

	// Use the provided serial number, or generate a randome one between 0 and 1<<128
	serialNumber := big.NewInt(gcc.SerialNumber)
	if gcc.SerialNumber == -1 {
		serialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return err
		}
	}

	// TODO add remaining extension fields (OCSP, Issuing URI, CRL)
	template := x509.Certificate{
		Subject:        gcc.Subject,
		DNSNames:       gcc.DomainNames,
		EmailAddresses: gcc.EmailAddresses,
		IPAddresses:    gcc.IPAddresses,
		URIs:           uris,

		SerialNumber: serialNumber,

		BasicConstraintsValid: gcc.IsCA,
		IsCA:                  gcc.IsCA,
		MaxPathLen:            gcc.MaxPathLength,
		MaxPathLenZero:        gcc.MaxPathLength == 0,

		NotAfter:  notAfter,
		NotBefore: notBefore,

		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,
	}

	parentCertificate := &template
	if gcc.ParentCertificate != "" {
		parentCertificate, err = fileToCert(gcc.ParentCertificate)
		if err != nil {
			return err
		}
	}

	parentKey := pkey
	if gcc.ParentCertificate != "" {
		parentKey, err = fileToPrivateKey(gcc.ParentPrivateKey, []byte(gcc.ParentPrivateKeyPassword))
		if err != nil {
			return err
		}
	}

	newCert, err := x509.CreateCertificate(rand.Reader, &template, parentCertificate, pkey.Public(), parentKey)
	if err != nil {
		return err
	}

	err = certToFile(gcc.OutputPath, newCert)
	if err != nil {
		return err
	}

	return nil
}
