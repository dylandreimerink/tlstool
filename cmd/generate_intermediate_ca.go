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

var generateIntermediateCACmd = &cobra.Command{
	Use:     "generate-intermediate [FLAGS]",
	Aliases: []string{"gen-int"},
	Short:   "Generate a intermediate Certificate Authority private key and certificate",
	RunE:    genIntermediateCA,
}

func init() {
	flags := generateIntermediateCACmd.Flags()

	flags.AddFlagSet(gfKeyFlags)
	flags.Lookup("key-output").DefValue = "intermediateCA.key"

	flags.AddFlagSet(gfCertFlags)
	flags.Lookup("cert-output").DefValue = "intermediateCA.key"
	if err := generateIntermediateCACmd.MarkFlagRequired("organization"); err != nil {
		panic(err)
	}

	if err := generateIntermediateCACmd.MarkFlagRequired("common-name"); err != nil {
		panic(err)
	}

	flags.AddFlagSet(gfParentFlags)

	if err := generateIntermediateCACmd.MarkFlagRequired("parent-cert"); err != nil {
		panic(err)
	}

	if err := generateIntermediateCACmd.MarkFlagRequired("parent-key"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(generateIntermediateCACmd)
}

func genIntermediateCA(cmd *cobra.Command, args []string) error {

	rootCertificate, err := pemFileToCert(gfParentCertificate)
	if err != nil {
		return err
	}

	rootKey, err := pemFileToKey(gfParentPrivateKey)
	if err != nil {
		return err
	}

	keyType := strings.ToLower(gfKeyType)

	var (
		ecKey  *ecdsa.PrivateKey
		rsaKey *rsa.PrivateKey
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

	intermediateTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: gfOrganizations,
			//TODO add rest of subject fields
			CommonName: gfCommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, gfValidFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,

		//TODO add fields for OCSP, CRL, ect.
	}

	var derBytes []byte
	if keyType == "ec" {
		derBytes, err = x509.CreateCertificate(rand.Reader, &intermediateTemplate, rootCertificate, &ecKey.PublicKey, rootKey)
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, &intermediateTemplate, rootCertificate, rsaKey.Public(), rootKey)
	}

	if err != nil {
		return err
	}

	if err := certToFile(gfCertificateFilename, derBytes); err != nil {
		return err
	}

	return nil
}
