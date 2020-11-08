package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

var (
	errUnableToReadPEM      = errors.New("can't read PEM data")
	errKeyEncrypted         = errors.New("key file is encrypted but no passphrase provided")
	errPrivateKeyUnparsable = errors.New("unable to parse private key")
)

func keyToPEMFile(filename string, key crypto.PrivateKey, passphrase []byte, encryptionAlgorithm x509.PEMCipher) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	asn1, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: asn1}

	if len(passphrase) > 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", asn1, passphrase, encryptionAlgorithm)
		if err != nil {
			return err
		}
	}

	if err := pem.Encode(file, block); err != nil {
		return err
	}

	return nil
}

func keyToDERFile(filename string, key crypto.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	asn1, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	_, err = file.Write(asn1)
	if err != nil {
		return err
	}

	return nil
}

func certToFile(filename string, derBytes []byte) error {
	certOut, err := os.Create(filename)
	if err != nil {
		return errors.Errorf("failed to open cert.pem for writing: %s", err)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return errors.Errorf("failed to write data to cert.pem: %s", err)
	}

	if err := certOut.Close(); err != nil {
		return errors.Errorf("error closing cert.pem: %s", err)
	}

	return nil
}

// pemFileToASN1 opens a file and reads it contents and attempts to decode it as PEM.
// If we are unable to decode the file as PEM, the contents are returned with a error.
// If we are able to decode it, the first decoded PEM block is returned as ANSI bytes with no error.
func pemFileToASN1(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != io.EOF && err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return bytes, errUnableToReadPEM
	}

	return block.Bytes, nil
}

func fileToCert(filename string) (*x509.Certificate, error) {
	ans1Bytes, err := pemFileToASN1(filename)
	if err != nil && err != errUnableToReadPEM {
		return nil, err
	}

	cert, err := x509.ParseCertificate(ans1Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func fileToPrivateKey(filename string, passphrase []byte) (crypto.Signer, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := file.Close(); err != nil {
			panic(err)
		}
	}()

	bytes, err := ioutil.ReadAll(file)
	if err != io.EOF && err != nil {
		return nil, err
	}

	ans1Bytes := bytes

	block, _ := pem.Decode(bytes)
	if block != nil {
		ans1Bytes = block.Bytes

		if x509.IsEncryptedPEMBlock(block) {
			if len(passphrase) == 0 {
				return nil, errKeyEncrypted
			}

			ans1Bytes, err = x509.DecryptPEMBlock(block, passphrase)
			if err != nil {
				return nil, err
			}
		}
	}

	if key, err := x509.ParsePKCS1PrivateKey(ans1Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(ans1Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(ans1Bytes); err == nil {
		switch pkey := key.(type) {
		case *rsa.PrivateKey:
			return pkey, nil
		case *ecdsa.PrivateKey:
			return pkey, nil
		case *ed25519.PrivateKey:
			return pkey, nil
		}

		return nil, fmt.Errorf("Unsupported private key type '%T'", key)
	}

	return nil, errPrivateKeyUnparsable
}

func generateECPrivateKey(keysize int) (*ecdsa.PrivateKey, error) {
	var ecCurve elliptic.Curve

	switch keysize {
	case 224:
		ecCurve = elliptic.P224()
	case 256:
		ecCurve = elliptic.P256()
	case 384:
		ecCurve = elliptic.P384()
	case 521:
		ecCurve = elliptic.P521()
	default:
		return nil, errors.Errorf("%d is not a valid key size, Allowed values: 224, 256, 384 and 521\n", keysize)
	}

	return ecdsa.GenerateKey(ecCurve, rand.Reader)
}

func generateRSAPriveKey(keysize int) (*rsa.PrivateKey, error) {
	allowed := false
	for _, allowedBits := range []int{1024, 2048, 4096, 8192} {
		if keysize == allowedBits {
			allowed = true
			break
		}
	}

	if !allowed {
		return nil, errors.Errorf("%d is not a valid key size Allowed values: 1024, 2048, 4096, 8192\n", keysize)
	}

	return rsa.GenerateKey(rand.Reader, keysize)
}

func generateEDPrivateKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}
