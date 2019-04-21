package cmd

import (
	"time"

	"github.com/spf13/pflag"
)

//This file contains common flags which can be used by the different commands

func init() {
	initKeyFlags()
	initCertFlags()
	initParentFlags()
}

var (
	//Private key variables
	gfKeyType     string
	gfECKeySize   int
	gfRSAKeySize  int
	gfKeyFilename string

	gfKeyFlags *pflag.FlagSet
)

func initKeyFlags() {
	gfKeyFlags = pflag.NewFlagSet("key-flags", pflag.ExitOnError)

	gfKeyFlags.StringVar(&gfKeyType, "key-type", "RSA", "The type of private key to be generated. Can be RSA or EC")
	gfKeyFlags.IntVar(&gfECKeySize, "ec-key-size", 256, "The bit size of the EC key. Allowed values: 224, 256, 384 and 521")
	gfKeyFlags.IntVar(&gfRSAKeySize, "rsa-key-size", 4096, "The bit size of the RSA key. Allowed values: 1024, 2048, 4096, 8192")
	gfKeyFlags.StringVar(&gfKeyFilename, "key-output", "rootCA.key", "The path and filename where the key will be writen to")
}

var (
	//Certificate variables
	gfValidFrom           string
	gfValidFor            int
	gfOrganizations       []string
	gfCommonName          string
	gfCertificateFilename string

	gfCertFlags *pflag.FlagSet
)

func initCertFlags() {
	gfCertFlags = pflag.NewFlagSet("cert-flags", pflag.ExitOnError)

	gfCertFlags.StringVar(&gfCertificateFilename, "cert-output", "rootCA.crt", "The path and filename where the certificate will be writen to")
	gfCertFlags.StringVar(&gfValidFrom, "valid-from", time.Now().Format(dateFormat), "The date and time after which the certificate is valid")
	gfCertFlags.IntVar(&gfValidFor, "valid-for", 365*5, "For how many days the certificate is valid")
	gfCertFlags.StringSliceVar(&gfOrganizations, "organization", []string{}, "The organization(s) on the certificate")
	gfCertFlags.StringVar(&gfCommonName, "common-name", "", "The common name of the certificate")
}

var (
	gfParentCertificate string
	gfParentPrivateKey  string

	gfParentFlags *pflag.FlagSet
)

func initParentFlags() {
	gfParentFlags = pflag.NewFlagSet("parent-flags", pflag.ExitOnError)

	gfParentFlags.StringVar(&gfParentCertificate, "parent-cert", "", "The path to the parent certificate which will be used to sign the generated certificate")
	gfParentFlags.StringVar(&gfParentPrivateKey, "parent-key", "", "The path to the private key of the certificate which will be used to sign the generated certificate")
}
