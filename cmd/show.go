package cmd

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/pkcs12"

	"github.com/spf13/cobra"
)

/*
TODOs:
- Normalize verbosity levels(Define what they are, and apply them across all file formats)
- Replace printf + prefix solution with a dedicated output formatting lib/functions.
	This is not maintainable for long.
- Add CSR support
- Add password prompting(to allow hidden passwords)(unless --not-interactive is specified)
*/

func newShowCmd() *cobra.Command {
	showCmd := &showCommand{}
	return showCmd.GetCobraCommand()
}

type showCommand struct {
	password  string
	verbosity int
}

func (csh *showCommand) GetCobraCommand() *cobra.Command {
	cobraCommand := &cobra.Command{
		Use:   "show",
		Short: "Displays verbose information about a given file",
		RunE:  csh.Run,
	}
	cobraCommand.Flags().StringVar(&csh.password, "password", "", "The password use to decrypt any specified files")
	cobraCommand.Flags().IntVarP(&csh.verbosity, "verbosity", "v", 0, "The verbosity level of the output (0-3)")

	return cobraCommand
}

func (csh *showCommand) Run(command *cobra.Command, args []string) error {
	for _, path := range args {
		if err := csh.showFile(path); err != nil {
			return err
		}
	}

	return nil
}

func (csh *showCommand) showFile(path string) error {
	// Open the input file
	inFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("os.Open: %w", err)
	}
	defer inFile.Close()

	// Read the contents of the file into memory, any crypto file should not large enough to cause issues
	inBytes, err := ioutil.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("io.Copy: %w", err)
	}

	filePrinter, err := csh.parseFile(inBytes)
	if err != nil {
		return fmt.Errorf("parseFile: %w", err)
	}

	fmt.Printf("%s:\n", path)

	if err := filePrinter.Print("  ", csh.verbosity); err != nil {
		return fmt.Errorf("print(): %w", err)
	}

	return nil
}

// A FilePrinter can print information about the file to standard output
type FilePrinter interface {
	Print(prefix string, verbosity int) error
}

var errUnknownFileFormat = errors.New("unknown file format")

// parseFile parses the top level file format but no second or third level encoding
// Currently supported formats are:
//  - PEM(wrapper around other supported file types)
//  - PKCS#1 public key
//  - PKCS#1 private key
//  - DER EC private key
//  - PKCS#8 wrapped RSA, ECDSA, ED25519 private key
//  - (Concatinated) DER X.509 certificates
//  - PKCS#12 archive
func (csh *showCommand) parseFile(data []byte) (FilePrinter, error) {
	// Attempt to decode as PEM file
	pemFile, err := csh.attemptParsePEM(data)
	if pemFile != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: file was parsed as PEM but also returned an error: %v\n", err)
		}

		return pemFile, nil
	}

	// Attempt to decode as PKCS#1 Public key
	if rsaPubKey, err := x509.ParsePKCS1PublicKey(data); rsaPubKey != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: file was parsed as PKCS#1 public key but also returned an error: %v\n", err)
		}

		return &PKCS1PublicKey{
			key: rsaPubKey,
		}, nil
	}

	// Attempt to decode as PKCS#1 Private key
	if rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(data); rsaPrivateKey != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: file was parsed as PKCS#1 private key but also returned an error: %v\n", err)
		}

		return &PKCS1PrivateKey{
			key: rsaPrivateKey,
		}, nil
	}

	// Attempt to decode as EC Private key
	if ecPrivKey, err := x509.ParseECPrivateKey(data); ecPrivKey != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: file was parsed as ECDSA private key but also returned an error: %v\n", err)
		}

		return &ECPrivateKey{
			key: ecPrivKey,
		}, nil
	}

	// Attempt to decode as PKCS#8 Private key
	if pkcs8PrivKey, err := x509.ParsePKCS8PrivateKey(data); pkcs8PrivKey != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: file was parsed as PKCS#8 private key but also returned an error: %v\n", err)
		}

		return &PKCS8PrivateKey{
			key: pkcs8PrivKey,
		}, nil
	}

	// Attempt to decode as PKIX Public key
	if pkixPubKey, err := x509.ParsePKIXPublicKey(data); pkixPubKey != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: file was parsed as PKIX public key but also returned an error: %v\n", err)
		}

		return &PKIXPublicKey{
			key: pkixPubKey,
		}, nil
	}

	// Attempt to decode as (concatinated) DER X.509 certificate(s)
	if certs, err := x509.ParseCertificates(data); len(certs) > 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: file was parsed as X.509 certificate but also returned an error: %v\n", err)
		}

		return &X509Certificates{
			certs: certs,
		}, nil
	}

	// Attempt to decode as pkcs12
	if pemBlocks, err := pkcs12.ToPEM(data, csh.password); err == nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: file was parsed as PKCS#12 archive but also returned an error: %v\n", err)
		}

		return &PKCS12Archive{
			pemFile: &PEMFile{
				csh:    csh,
				blocks: pemBlocks,
			},
		}, nil
	}

	return nil, errUnknownFileFormat
}

type PEMFile struct {
	csh    *showCommand
	blocks []*pem.Block
}

func (pf *PEMFile) Print(prefix string, verbosity int) error {
	for i, block := range pf.blocks {
		fmt.Printf("%sPEM Block Nr. %d:\n", prefix, i)
		fmt.Printf("%s  Type      : %s\n", prefix, block.Type)
		if len(block.Headers) > 0 {
			fmt.Printf("%s  headers:\n", prefix)
			maxLen := 0
			for key := range block.Headers {
				if len(key) > maxLen {
					maxLen = len(key)
				}
			}
			for key, value := range block.Headers {
				fmt.Printf("%s    %-"+strconv.Itoa(maxLen+1)+"s: %v\n", prefix, key, value)
			}
		}

		blockBytes := block.Bytes
		// If DEK-Info is present in the headers, this is most likely an encrypted PEM block
		if _, ok := block.Headers["DEK-Info"]; ok {
			var err error
			blockBytes, err = x509.DecryptPEMBlock(block, []byte(pf.csh.password))
			if err != nil {
				return fmt.Errorf("unable to decrypt PEM contents: %w", err)
			}
		}

		subFile, err := pf.csh.parseFile(blockBytes)
		if err != nil {
			return fmt.Errorf("unable to parse PEM contents: %w", err)
		}

		err = subFile.Print(fmt.Sprintf("%s  ", prefix), verbosity)
		if err != nil {
			return err
		}
	}
	return nil
}

var (
	errUnableToParsePEM = errors.New("unable to parse file as PEM")
	errPEMTrailingData  = errors.New("file contains trailing non-PEM data")
)

func (csh *showCommand) attemptParsePEM(data []byte) (*PEMFile, error) {
	file := PEMFile{
		csh: csh,
	}

	var block *pem.Block
	rest := data

	for len(rest) != 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		file.blocks = append(file.blocks, block)
	}

	if len(file.blocks) == 0 {
		return nil, errUnableToParsePEM
	}

	var err error
	if len(rest) > 0 {
		err = errPEMTrailingData
	}

	return &file, err
}

type PKCS1PublicKey struct {
	key *rsa.PublicKey
}

func (ppk *PKCS1PublicKey) Print(prefix string, verbosity int) error {
	// Conbine both parts of the public key, this is assuming the exponent can never be negative
	pkBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pkBytes, uint64(ppk.key.E))
	pkBytes = append(pkBytes, ppk.key.N.Bytes()...)
	fmt.Printf("%sMD5 fingerprint : %X\n", prefix, md5.Sum(pkBytes))
	fmt.Printf("%sSHA1 fingerprint: %X\n", prefix, sha1.Sum(pkBytes))
	if verbosity >= 1 {
		fmt.Printf("%sPublic exponent : %d\n", prefix, ppk.key.E)
		fmt.Printf("%sModulus:\n", prefix)
		printBinary(ppk.key.N.Bytes(), fmt.Sprintf("%s  ", prefix))
	}

	return nil
}

type PKCS1PrivateKey struct {
	key *rsa.PrivateKey
}

func (ppk *PKCS1PrivateKey) Print(prefix string, verbosity int) error {
	if verbosity >= 1 {
		fmt.Printf("%sPrivate exponent:\n", prefix)
		printBinary(ppk.key.D.Bytes(), fmt.Sprintf("%s  ", prefix))
	}
	if verbosity >= 2 {
		fmt.Printf("%sPrimes:\n", prefix)
		for i, prime := range ppk.key.Primes {
			fmt.Printf("%s  %d:\n", prefix, i)
			printBinary(prime.Bytes(), fmt.Sprintf("%s    ", prefix))
		}
	}

	// Conbine both parts of the public key, this is assuming the exponent can never be negative
	pkBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pkBytes, uint64(ppk.key.PublicKey.E))
	pkBytes = append(pkBytes, ppk.key.PublicKey.N.Bytes()...)

	fmt.Printf("%sPublic key:\n", prefix)
	fmt.Printf("%s  MD5 fingerprint : %X\n", prefix, md5.Sum(pkBytes))
	fmt.Printf("%s  SHA1 fingerprint: %X\n", prefix, sha1.Sum(pkBytes))
	if verbosity >= 1 {
		fmt.Printf("%s  Public exponent : %d\n", prefix, ppk.key.PublicKey.E)
		fmt.Printf("%s  Modulus:\n", prefix)
		printBinary(ppk.key.PublicKey.N.Bytes(), fmt.Sprintf("%s    ", prefix))
	}

	if verbosity >= 3 {
		fmt.Printf("%sPrecomputed:\n", prefix)
		fmt.Printf("%s  Dp:\n", prefix)
		printBinary(ppk.key.Precomputed.Dp.Bytes(), fmt.Sprintf("%s    ", prefix))

		fmt.Printf("%s  Dq:\n", prefix)
		printBinary(ppk.key.Precomputed.Dq.Bytes(), fmt.Sprintf("%s    ", prefix))

		fmt.Printf("%s  Qinv:\n", prefix)
		printBinary(ppk.key.Precomputed.Qinv.Bytes(), fmt.Sprintf("%s    ", prefix))
	}
	return nil
}

type ECPublicKey struct {
	key *ecdsa.PublicKey
}

func (epk *ECPublicKey) Print(prefix string, verbosity int) error {
	// Conbine X, Y, and the bitsize. The curve params don't change for the same bitsize.
	bitSizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bitSizeBytes, uint64(epk.key.Curve.Params().BitSize))

	xBytes := epk.key.X.Bytes()
	yBytes := epk.key.Y.Bytes()
	pkBytes := append(append(xBytes, yBytes...), bitSizeBytes...)

	fmt.Printf("%sCurve name      : %s\n", prefix, epk.key.Curve.Params().Name)
	fmt.Printf("%sMD5 fingerprint : %X\n", prefix, md5.Sum(pkBytes))
	fmt.Printf("%sSHA1 fingerprint: %X\n", prefix, sha1.Sum(pkBytes))

	if verbosity >= 1 {
		fmt.Printf("%sCoordinates:\n", prefix)
		fmt.Printf("%s  X:\n", prefix)
		printBinary(epk.key.X.Bytes(), fmt.Sprintf("%s    ", prefix))
		fmt.Printf("%s  Y:\n", prefix)
		printBinary(epk.key.Y.Bytes(), fmt.Sprintf("%s    ", prefix))
	}

	return nil
}

type ECPrivateKey struct {
	key *ecdsa.PrivateKey
}

func (epk *ECPrivateKey) Print(prefix string, verbosity int) error {
	if verbosity >= 1 {
		fmt.Printf("%sPrivate key:\n", prefix)
		printBinary(epk.key.D.Bytes(), fmt.Sprintf("%s  ", prefix))
	}

	fmt.Printf("%sPublic key:\n", prefix)
	pkey := &ECPublicKey{
		key: &epk.key.PublicKey,
	}
	if err := pkey.Print(fmt.Sprintf("%s  ", prefix), verbosity); err != nil {
		return err
	}

	return nil
}

type PKCS8PrivateKey struct {
	key interface{}
}

func (ppk *PKCS8PrivateKey) Print(prefix string, verbosity int) error {
	fmt.Printf("%sPKCS#1 Private key:\n", prefix)
	switch key := ppk.key.(type) {
	case *rsa.PrivateKey:
		fmt.Printf("%sAlgorithm: RSA\n", prefix)
		fmt.Printf("%sDetails:\n", prefix)
		printer := &PKCS1PrivateKey{
			key: key,
		}
		return printer.Print(fmt.Sprintf("%s  ", prefix), verbosity)
	case *ecdsa.PrivateKey:
		fmt.Printf("%sAlgorithm: ECDSA\n", prefix)
		fmt.Printf("%sDetails:\n", prefix)
		printer := &ECPrivateKey{
			key: key,
		}
		return printer.Print(fmt.Sprintf("%s  ", prefix), verbosity)
	case ed25519.PrivateKey:
		fmt.Print("Algorithm: ED25519\n")
		fmt.Printf("%sDetails:\n", prefix)
		printer := &ED25519PrivateKey{
			key: &key,
		}
		return printer.Print(fmt.Sprintf("%s  ", prefix), verbosity)
	default:
		return fmt.Errorf("unknown key format '%t' found within PKCS#8 object", key)
	}
}

type DSAPrivateKey struct {
	key *dsa.PrivateKey
}

func (dpk *DSAPrivateKey) Print(prefix string, verbosity int) error {
	if verbosity >= 1 {
		fmt.Printf("%sPrivate key:\n", prefix)
		printBinary(dpk.key.X.Bytes(), fmt.Sprintf("%s  ", prefix))
	}

	fmt.Printf("%sPublic key:\n", prefix)
	pkey := &DSAPublicKey{
		key: &dpk.key.PublicKey,
	}
	if err := pkey.Print(fmt.Sprintf("%s  ", prefix), verbosity); err != nil {
		return err
	}

	return nil
}

type DSAPublicKey struct {
	key *dsa.PublicKey
}

func (dpk *DSAPublicKey) Print(prefix string, verbosity int) error {

	yBytes := dpk.key.Y.Bytes()

	params := dpk.key.Parameters
	pBytes := params.P.Bytes()
	gBytes := params.G.Bytes()
	qBytes := params.Q.Bytes()
	pkBytes := append(append(append(yBytes, pBytes...), gBytes...), qBytes...)

	n := params.Q.BitLen()
	l := params.P.BitLen()

	var paramSizeString string
	if l == 1024 && n == 160 {
		paramSizeString = "L1024N160"
	}
	if l == 2048 {
		if n == 224 {
			paramSizeString = "L2048N224"
		} else {
			paramSizeString = "L2048N256"
		}
	}
	if l == 3072 && n == 256 {
		paramSizeString = "L3072N256"
	}

	fmt.Printf("%sParameter sizes : %s\n", prefix, paramSizeString)
	fmt.Printf("%sMD5 fingerprint : %X\n", prefix, md5.Sum(pkBytes))
	fmt.Printf("%sSHA1 fingerprint: %X\n", prefix, sha1.Sum(pkBytes))

	if verbosity >= 1 {
		fmt.Printf("%sPublic key:\n", prefix)
		printBinary(yBytes, fmt.Sprintf("%s  ", prefix))
	}
	if verbosity >= 2 {
		fmt.Printf("%sDomain parameters:\n", prefix)
		fmt.Printf("%s  P:\n", prefix)
		printBinary(params.P.Bytes(), fmt.Sprintf("%s    ", prefix))
		fmt.Printf("%s  Q:\n", prefix)
		printBinary(params.Q.Bytes(), fmt.Sprintf("%s    ", prefix))
		fmt.Printf("%s  G:\n", prefix)
		printBinary(params.G.Bytes(), fmt.Sprintf("%s    ", prefix))
	}

	return nil
}

type ED25519PrivateKey struct {
	key *ed25519.PrivateKey
}

func (epk *ED25519PrivateKey) Print(prefix string, verbosity int) error {
	fmt.Printf("%sED25519 Private key:\n", prefix)

	fmt.Printf("%s  Private key:\n", prefix)
	printBinary(epk.key.Seed(), fmt.Sprintf("%s    ", prefix))

	edPkey := epk.key.Public().(ed25519.PublicKey)
	pkey := &ED25519PublicKey{
		key: &edPkey,
	}

	return pkey.Print(fmt.Sprintf("%s  ", prefix), verbosity)
}

type ED25519PublicKey struct {
	key *ed25519.PublicKey
}

func (epk *ED25519PublicKey) Print(prefix string, verbosity int) error {
	fmt.Printf("%sED25519 Public key:\n", prefix)
	fmt.Printf("%s  MD5 fingerprint : %X\n", prefix, md5.Sum(*epk.key))
	fmt.Printf("%s  SHA1 fingerprint: %X\n", prefix, sha1.Sum(*epk.key))

	if verbosity >= 1 {
		fmt.Printf("%s  Raw:\n", prefix)
		printBinary(*epk.key, fmt.Sprintf("%s    ", prefix))
	}

	return nil
}

type X509Certificates struct {
	certs []*x509.Certificate
}

var keyUsageToString = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  keyUsageStrings[0],
	x509.KeyUsageContentCommitment: keyUsageStrings[1],
	x509.KeyUsageKeyEncipherment:   keyUsageStrings[2],
	x509.KeyUsageKeyAgreement:      keyUsageStrings[3],
	x509.KeyUsageCertSign:          keyUsageStrings[4],
	x509.KeyUsageCRLSign:           keyUsageStrings[5],
	x509.KeyUsageEncipherOnly:      keyUsageStrings[6],
	x509.KeyUsageDecipherOnly:      keyUsageStrings[7],
}

var extendedKeyUsageToString = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:          extendedKeyUsageStrings[0],
	x509.ExtKeyUsageServerAuth:   extendedKeyUsageStrings[1],
	x509.ExtKeyUsageClientAuth:   extendedKeyUsageStrings[2],
	x509.ExtKeyUsageCodeSigning:  extendedKeyUsageStrings[3],
	x509.ExtKeyUsageTimeStamping: extendedKeyUsageStrings[4],
	x509.ExtKeyUsageOCSPSigning:  extendedKeyUsageStrings[5],
}

func unpackKeyUsage(usage x509.KeyUsage) []x509.KeyUsage {
	var separate []x509.KeyUsage
	// Attempt every flag
	for i := x509.KeyUsageDecipherOnly; i > 0; i = i / 2 {
		if usage&i > 0 {
			separate = append(separate, i)
		}
	}

	return separate
}

func (ppk *X509Certificates) Print(prefix string, verbosity int) error {
	fmt.Printf("%sX.509 Certificates: \n", prefix)
	for i, cert := range ppk.certs {
		fmt.Printf("%s  %d: # X.509v%d Certificate\n", prefix, i, cert.Version)
		fmt.Printf("%s   Issuer:\n", prefix)
		fmt.Printf("%s     Subject : %s\n", prefix, cert.Issuer)
		fmt.Printf("%s   Subject   : %s\n", prefix, cert.Subject)
		fmt.Printf("%s   Not Before: %s\n", prefix, cert.NotBefore)
		fmt.Printf("%s   Not After : %s\n", prefix, cert.NotAfter)
		fmt.Printf("%s   Serial Nr.: %s\n", prefix, cert.SerialNumber)
		fmt.Printf("%s   Is CA     : %v", prefix, cert.IsCA)
		if cert.IsCA {
			if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
				fmt.Printf("   (Max path length: %d)", cert.MaxPathLen)
			}
		}
		fmt.Print("\n")

		var usageStrings []string
		for _, usage := range unpackKeyUsage(cert.KeyUsage) {
			usageStrings = append(usageStrings, keyUsageToString[usage])
		}
		fmt.Printf("%s   %s: %s\n", prefix, "Usage     ", strings.Join(usageStrings, ", "))

		if len(cert.ExtKeyUsage) > 0 {
			var extUsageStrings []string
			for _, extUsage := range cert.ExtKeyUsage {
				extUsageStrings = append(extUsageStrings, extendedKeyUsageToString[extUsage])
			}
			fmt.Printf("%s   %s: %s\n", prefix, "Extended key usage", strings.Join(extUsageStrings, ", "))
		}

		sanCount := len(cert.IPAddresses) +
			len(cert.DNSNames) +
			len(cert.EmailAddresses) +
			len(cert.URIs)

		if sanCount > 0 {
			fmt.Printf("%s   Subject alterative names(SAN):\n", prefix)

			if len(cert.IPAddresses) > 0 {
				fmt.Printf("%s     IP Addresses:\n", prefix)
				for _, ip := range cert.IPAddresses {
					fmt.Printf("%s        - %s\n", prefix, ip)
				}
			}

			if len(cert.DNSNames) > 0 {
				fmt.Printf("%s     DNS names:\n", prefix)
				for _, dnsName := range cert.DNSNames {
					fmt.Printf("%s      - %s\n", prefix, dnsName)
				}
			}

			if len(cert.EmailAddresses) > 0 {
				fmt.Printf("%s     Email addresses:\n", prefix)
				for _, email := range cert.EmailAddresses {
					fmt.Printf("%s        - %s\n", prefix, email)
				}
			}

			if len(cert.URIs) > 0 {
				fmt.Printf("%s     URIs:\n", prefix)
				for _, uri := range cert.URIs {
					fmt.Printf("%s        - %s\n", prefix, uri)
				}
			}
		}

		var pkeyPrinter FilePrinter
		switch pubKey := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			pkeyPrinter = &PKCS1PublicKey{
				key: pubKey,
			}
		case *ecdsa.PublicKey:
			pkeyPrinter = &ECPublicKey{
				key: pubKey,
			}
		case *ed25519.PublicKey:
			pkeyPrinter = &ED25519PublicKey{
				key: pubKey,
			}
		}
		if pkeyPrinter != nil {
			fmt.Printf("%s   Public key:\n", prefix)
			fmt.Printf("%s     Algorithm: %s\n", prefix, cert.PublicKeyAlgorithm)
			fmt.Printf("%s     Details:\n", prefix)
			err := pkeyPrinter.Print(fmt.Sprintf("%s       ", prefix), verbosity)
			if err != nil {
				return err
			}
		}

		fmt.Printf("%s   Signature algorithm: %s\n", prefix, cert.SignatureAlgorithm.String())
		fmt.Printf("%s   Signature:\n", prefix)
		printBinary(cert.Signature, fmt.Sprintf("%s     ", prefix))
	}
	return nil
}

type PKIXPublicKey struct {
	key interface{}
}

func (ppk *PKIXPublicKey) Print(prefix string, verbosity int) error {
	switch key := ppk.key.(type) {
	case *rsa.PublicKey:
		fmt.Printf("%sAlgorithm: RSA\n", prefix)
		fmt.Printf("%sDetails  :\n", prefix)
		printer := &PKCS1PublicKey{
			key: key,
		}
		return printer.Print(fmt.Sprintf("%s  ", prefix), verbosity)
	case *ecdsa.PublicKey:
		fmt.Printf("%sAlgorithm: ECDSA\n", prefix)
		fmt.Printf("%sDetails  :\n", prefix)
		printer := &ECPublicKey{
			key: key,
		}
		return printer.Print(fmt.Sprintf("%s  ", prefix), verbosity)
	case *dsa.PublicKey:
		fmt.Printf("%sAlgorithm: DSA\n", prefix)
		fmt.Printf("%sDetails  :\n", prefix)
		printer := &DSAPublicKey{
			key: key,
		}

		return printer.Print(fmt.Sprintf("%s  ", prefix), verbosity)
	case *ed25519.PublicKey:
		fmt.Printf("%sAlgorithm: ED25519\n", prefix)
		fmt.Printf("%sDetails  :\n", prefix)
		printer := &ED25519PublicKey{
			key: key,
		}

		return printer.Print(fmt.Sprintf("%s  ", prefix), verbosity)
	default:
		return fmt.Errorf("unknown key format '%t' found within PKCS#8 object", key)
	}
}

type PKCS12Archive struct {
	pemFile *PEMFile
}

func (pka *PKCS12Archive) Print(prefix string, verbosity int) error {
	fmt.Printf("%sPKCS#12 File:\n", prefix)
	return pka.pemFile.Print(fmt.Sprintf("%s  ", prefix), verbosity)
}

func printBinary(b []byte, prefix string) {
	const width = 32
	for i := 0; i < len(b); i += width {
		end := i + width
		if end > len(b) {
			end = len(b)
		}
		fmt.Printf("%s%X\n", prefix, b[i:end])
	}
}
