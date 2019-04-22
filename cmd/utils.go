package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

// ecKeyToFile serializes the EC key and writes it to a file
func ecKeyToFile(filename string, key *ecdsa.PrivateKey, passphrase []byte, encryptionAlgorithm x509.PEMCipher) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return errors.Errorf("Unable to marshal ECDSA private key: %v", err)
	}

	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}

	if len(passphrase) > 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", b, passphrase, encryptionAlgorithm)
		if err != nil {
			return err
		}
	}

	if err := pem.Encode(file, block); err != nil {
		return err
	}

	return nil
}

// rsaKeyToFile serializes the EC key and writes it to a file
func rsaKeyToFile(filename string, key *rsa.PrivateKey, passphrase []byte, encryptionAlgorithm x509.PEMCipher) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	b := x509.MarshalPKCS1PrivateKey(key)

	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}

	if len(passphrase) > 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", b, passphrase, encryptionAlgorithm)
		if err != nil {
			return err
		}
	}

	if err := pem.Encode(file, block); err != nil {
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

func pemFileToCert(filename string) (*x509.Certificate, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != io.EOF && err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("Can't read PEM data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	if err := file.Close(); err != nil {
		return nil, err
	}

	return cert, nil
}

func pemFileToKey(filename string, passphrase []byte) (interface{}, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != io.EOF && err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("Can't read PEM data")
	}

	derBytes := block.Bytes

	if x509.IsEncryptedPEMBlock(block) {
		if len(passphrase) == 0 {
			return nil, errors.New("Key file is encrypted but no passphrase provided")
		}

		derBytes, err = x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, err
		}
	}

	var key interface{}

	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(derBytes)
	} else if block.Type == "EC PRIVATE KEY" {
		key, err = x509.ParseECPrivateKey(derBytes)
	} else {
		return nil, errors.Errorf("Unknown private key type: %s", block.Type)
	}

	if err != nil {
		return nil, err
	}

	if err := file.Close(); err != nil {
		return nil, err
	}

	return key, nil
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
