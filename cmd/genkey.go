package cmd

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newGenKeyCmd() *cobra.Command {
	genKeyCmd := &generatePrivateKeyCommand{}
	return genKeyCmd.GetCobraCommand()
}

type generatePrivateKeyCommand struct {
	// The path where the private key will be written to
	OutputPath string
	// The key type (RSA, EC, ED)
	KeyType string
	// The bit size of the generated key
	KeySize int
	// The format of the key on disk(PEM or DER)
	KeyFormat string
	// The cypher used to encrypt the private key(if a passphase is supplied)
	KeyEncryptionCipher string
	// The passphrase used to encrypt the private key(if the format allows it)
	KeyPassphrase string
}

func (gpk *generatePrivateKeyCommand) GetCobraCommand() *cobra.Command {
	cobraCommand := &cobra.Command{
		Use: "key",
		Aliases: []string{
			"private-key",
		},
		Short: "Generate a private key",
		RunE:  gpk.Run,
	}

	flags := cobraCommand.Flags()
	flags.StringVarP(&gpk.OutputPath, "output", "o", "", "Path where the private key will be written to.")
	flags.StringVarP(&gpk.KeyType, "key-type", "t", "", "The type of private key to generated (allowed: RSA(default), EC, ED)")
	flags.IntVarP(&gpk.KeySize, "key-size", "s", 0, "The size of the key in bits."+
		" (RSA: 1024, 2048(default), 4096, 8192) (EC: 224, 256(default), 384, 521) (ED: 32(default))")
	flags.StringVarP(&gpk.KeyFormat, "key-format", "f", "", "The format of the key on disk(PEM or DER)")
	flags.StringVarP(&gpk.KeyEncryptionCipher, "encryption-cipher", "c", "AES256", "The cipher used to encrypt the private key (allowed: DES, 3DES, AES128, AES192, AES256(default))")
	flags.StringVarP(&gpk.KeyPassphrase, "passphrase", "p", "", "The passphrase used to encrypt the private key")

	return cobraCommand
}

func (gpk *generatePrivateKeyCommand) checkFlags(command *cobra.Command) error {
	nonInteractive, err := command.Flags().GetBool(nonInteractiveFlag)
	if err != nil {
		panic(err)
	}

	if err = gpk.checkFlagOutput(nonInteractive); err != nil {
		return err
	}

	if err = gpk.checkFlagKeyType(nonInteractive); err != nil {
		return err
	}

	if err = gpk.checkFlagKeySize(nonInteractive); err != nil {
		return err
	}

	if err = gpk.checkFlagKeyFormat(nonInteractive); err != nil {
		return err
	}

	if err = gpk.checkFlagKeyPassphrase(nonInteractive); err != nil {
		return err
	}

	if err = gpk.checkFlagKeyEncryptionCipher(nonInteractive); err != nil {
		return err
	}

	return nil
}

func (gpk *generatePrivateKeyCommand) checkFlagKeyPassphrase(nonInteractive bool) error {
	if gpk.KeyPassphrase != "" {
		return nil
	}

	if nonInteractive {
		return nil
	}

	fmt.Println("No passphrase specified, input one or just press enter to leave key unencrypted")

	err := survey.AskOne(&survey.Password{
		Message: "Passphrase:",
	}, &gpk.KeyPassphrase)
	if err != nil {
		return err
	}

	return nil
}

func (gpk *generatePrivateKeyCommand) checkFlagKeyEncryptionCipher(nonInteractive bool) error {
	// If there is no passphrase, no need to worry about the cipher
	if gpk.KeyPassphrase == "" {
		return nil
	}

	gpk.KeyEncryptionCipher = strings.ToUpper(gpk.KeyEncryptionCipher)

	switch gpk.KeyEncryptionCipher {
	case "":
		if nonInteractive {
			gpk.KeyEncryptionCipher = "AES256"
			return nil
		}
		fmt.Println("No key encryption cipher specified")
	case "DES", "3DES", "AES128", "AES192", "AES256":
		return nil
	}

	err := survey.AskOne(&survey.Select{
		Message: "Private encryption cipher:",
		Default: "AES256",
		Options: []string{
			"DES", "3DES", "AES128", "AES192", "AES256",
		},
	}, &gpk.KeyEncryptionCipher, survey.WithValidator(survey.Required))
	if err != nil {
		return err
	}

	return nil
}

func (gpk *generatePrivateKeyCommand) checkFlagKeyFormat(nonInteractive bool) error {
	gpk.KeyFormat = strings.ToUpper(gpk.KeyFormat)
	if gpk.KeyFormat == "PEM" || gpk.KeyFormat == "DER" {
		return nil
	}

	if nonInteractive {
		if gpk.KeyFormat == "" {
			return fmt.Errorf("The --key-format flag is required")
		} else {
			return fmt.Errorf("'%s' is not a valid value for --key-format, allowed: PEM or DER", gpk.KeyFormat)
		}
	}

	fmt.Println("No private key format specified, please specify one")

	err := survey.AskOne(&survey.Select{
		Message: "Private key format:",
		Default: "PEM",
		Options: []string{
			"PEM", "DER",
		},
	}, &gpk.KeyFormat, survey.WithValidator(survey.Required))
	if err != nil {
		return err
	}

	return nil
}

func (gpk *generatePrivateKeyCommand) checkFlagOutput(nonInteractive bool) error {
	if gpk.OutputPath != "" {
		//TODO validate that we can create a file at that path
		return nil
	}

	if nonInteractive {
		return fmt.Errorf("The --output flag must be set")
	}

	fmt.Println("No private key output path specified, please specify one")

	err := survey.AskOne(&survey.Input{
		Message: "Output path:",
	}, &gpk.OutputPath, survey.WithValidator(survey.Required))
	//TODO validate that we can create a file at that path
	if err != nil {
		return err
	}

	return nil
}

func (gpk *generatePrivateKeyCommand) checkFlagKeyType(nonInteractive bool) error {
	gpk.KeyType = strings.ToUpper(gpk.KeyType)

	if gpk.KeyType == "RSA" || gpk.KeyType == "EC" || gpk.KeyType == "ED" {
		return nil
	}

	// ECDSA is a valid alias
	if gpk.KeyType == "ECDSA" {
		gpk.KeyType = "EC"
		return nil
	}

	// ED25519 is a valid alias
	if gpk.KeyType == "ED25519" {
		gpk.KeyType = "ED"
		return nil
	}

	if nonInteractive {
		if gpk.KeyType == "" {
			return fmt.Errorf("The --key-type flag must be set")
		}
		return fmt.Errorf("The --key-type flag must be: rsa, ec or ed")
	}

	if gpk.KeyType == "" {
		fmt.Println("No private key type specified, specify one please")
	} else {
		fmt.Println("Invalid private key type specified, please pick one")
	}

	err := survey.AskOne(&survey.Select{
		Message: "Private key type:",
		Options: []string{
			"RSA", "EC", "ED",
		},
		Default: "RSA",
	}, &gpk.KeyType, survey.WithValidator(survey.Required))
	if err != nil {
		return err
	}

	return nil
}

func (gpk *generatePrivateKeyCommand) checkFlagKeySize(nonInteractive bool) error {
	var (
		choices       []string
		defaultChoice string
	)

	// allowed sizes is dependant on key type
	switch gpk.KeyType {
	case "RSA":
		choices = []string{"1024", "2048", "4096", "8192"}
		defaultChoice = "2048"
		switch gpk.KeySize {
		case 0:
			// If no size is specified, use the default for non-interactive execution
			if nonInteractive {
				gpk.KeySize = 2048
				return nil
			}
		case 1024, 2048, 4096, 8192:
			// If already an allows value, don't prompt
			return nil
		}
	case "EC":
		choices = []string{"224", "256", "384", "521"}
		defaultChoice = "256"
		switch gpk.KeySize {
		case 0:
			// If no size is specified, use the default for non-interactive execution
			if nonInteractive {
				gpk.KeySize = 256
				return nil
			}
		case 224, 256, 384, 521:
			return nil
		}
	case "ED":
		choices = []string{"32"}
		defaultChoice = "32"
		switch gpk.KeySize {
		case 0:
			// If no size is specified, use the default for non-interactive execution
			if nonInteractive {
				gpk.KeySize = 32
				return nil
			}
		case 32:
			return nil
		}
	}

	if nonInteractive {
		return fmt.Errorf(
			"'%d' is not a valid keysize for '%s' key type, allowed: (%s)",
			gpk.KeySize,
			gpk.KeyType,
			strings.Join(choices, ", "),
		)
	}

	if gpk.KeySize == 0 {
		fmt.Println("No key size specified, pick one")
	} else {
		fmt.Println("Invalid key size specified, pick a valid one")
	}

	var keySizeString string
	err := survey.AskOne(&survey.Select{
		Message: "Private key size:",
		Options: choices,
		Default: defaultChoice,
	}, &keySizeString, survey.WithValidator(survey.Required))
	if err != nil {
		return err
	}

	gpk.KeySize, err = strconv.Atoi(keySizeString)
	if err != nil {
		return err
	}

	return nil
}

func (gpk *generatePrivateKeyCommand) Run(command *cobra.Command, args []string) error {
	err := gpk.checkFlags(command)
	if err != nil {
		return err
	}

	var encryptionCipher x509.PEMCipher

	switch gpk.KeyEncryptionCipher {
	case "DES":
		encryptionCipher = x509.PEMCipherDES
	case "3DES":
		encryptionCipher = x509.PEMCipher3DES
	case "AES128":
		encryptionCipher = x509.PEMCipherAES128
	case "AES192":
		encryptionCipher = x509.PEMCipherAES192
	case "AES256":
		encryptionCipher = x509.PEMCipherAES256
	default:
		return errors.Errorf("Unknown encryption type: %s", gpk.KeyEncryptionCipher)
	}

	var pkey crypto.PrivateKey

	switch gpk.KeyType {
	case "RSA":
		pkey, err = generateRSAPriveKey(gpk.KeySize)
		if err != nil {
			return err
		}
	case "EC":
		pkey, err = generateECPrivateKey(gpk.KeySize)
		if err != nil {
			return err
		}
	case "ED":
		pkey, err = generateEDPrivateKey()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported key type '%s'", gpk.KeyType)
	}

	switch gpk.KeyFormat {
	case "PEM":
		err = keyToPEMFile(gpk.OutputPath, pkey, []byte(gpk.KeyPassphrase), encryptionCipher)
		if err != nil {
			return err
		}
	case "DER":
		err = keyToDERFile(gpk.OutputPath, pkey)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported key format '%s'", gpk.KeyType)
	}

	return nil
}
