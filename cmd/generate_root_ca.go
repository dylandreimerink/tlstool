package cmd

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const dateFormat = "15:04:05 02-01-2006"

var generateRootCACmd = &cobra.Command{
	Use:     "generate-ca [FLAGS]",
	Aliases: []string{"gen-ca"},
	Short:   "Generates a root Certificate Authority private key and certificate",
	RunE:    genRootCA,
}

func init() {
	flags := generateRootCACmd.Flags()

	flags.AddFlagSet(gfKeyFlags)

	flags.AddFlagSet(gfCertFlags)
	if err := generateRootCACmd.MarkFlagRequired("organization"); err != nil {
		panic(err)
	}

	if err := generateRootCACmd.MarkFlagRequired("common-name"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(generateRootCACmd)
}

func genRootCA(cmd *cobra.Command, args []string) error {
	keyType := strings.ToLower(gfKeyType)

	var (
		ecKey  *ecdsa.PrivateKey
		rsaKey *rsa.PrivateKey
		err    error
	)

	if keyType == "ec" {
		ecKey, err = generateECPrivateKey(gfECKeySize)
		if err != nil {
			return err
		}

		if err := ecKeyToFile(gfKeyFilename, ecKey); err != nil {
			return err
		}
	} else if keyType == "rsa" {
		rsaKey, err = generateRSAPriveKey(gfRSAKeySize)

		if err := rsaKeyToFile(gfKeyFilename, rsaKey); err != nil {
			return err
		}
	} else {
		return errors.Errorf("%s is not a valid value for key-type, valid values: RSA and EC\n", gfKeyType)
	}

	notBefore, err := time.Parse(dateFormat, gfValidFrom)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: gfOrganizations,
			//TODO add rest of subject fields
			CommonName: gfCommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, gfValidFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,

		//TODO add fields for OCSP ect.
	}

	var derBytes []byte
	if keyType == "ec" {
		derBytes, err = x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &ecKey.PublicKey, ecKey)
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, rsaKey.Public(), rsaKey)
	}

	if err != nil {
		return err
	}

	if err := certToFile(gfCertificateFilename, derBytes); err != nil {
		return err
	}

	return nil
}
