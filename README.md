# TLSTool

TLSTool is a cli tool to easily generate x.509 certificates which can be used for TLS connections without configuration files or having to setup a full PKI infrastructure.

This tool is an alternative to openssl for creating X.509 certificates. The main difference being that all features of TLSTool can be used without configuration files. TLSTool is not as feature rich as openssl but has most functionality required for the average user.

## Installation

Using Go tools:
`go get -u github.com/dylandreimerink/tlstool`

## Usage

```shell
Usage:
  tlstool [flags]

Flags:
Private key flags:
      --ec-key-size int     The bit size of the EC key. Allowed values: 224, 256, 384 and 521 (default 256)
      --key-output string   The path and filename where the key will be writen to (default "certificate.key")
      --key-type string     The type of private key to be generated. Can be RSA or EC (default "RSA")
      --rsa-key-size int    The bit size of the RSA key. Allowed values: 1024, 2048, 4096, 8192 (default 4096)

Certificate flags:
      --cert-output string               The path and filename where the certificate will be writen to (default "certificate.crt")
      --crl-distribution-point strings   A URI where a CRL can be requested
      --is-ca                            If set a CA certificate will be created, meaning it can sign other certificates
      --issuing-cert-uri strings         A URI where the issuing certificate can be downloaded from
      --max-path-length int              The maximum size of the subtree of this certificate. https://stackoverflow.com/questions/6616470/certificates-basic-constraints-path-length (default -1)
      --ocsp-server strings              The OCSP URI for this certificate. https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol
      --parent-cert string               The path to the parent certificate which will be used to sign the generated certificate
      --parent-key string                The path to the private key of the certificate which will be used to sign the generated certificate
      --valid-for int                    For how many days the certificate is valid (default 1825)
      --valid-from string                The date and time after which the certificate is valid (default "13:43:15 22-04-2019")

Certificate subject flags:
      --common-name string             The common name of the certificate
      --country strings                The country(s) of the subject of the certificate
      --locality strings               The locality(s) of the subject of the certificate
      --organization strings           The organization(s) of the subject of the certificate
      --organizational-unit strings    The organizational units(s) of the subject of the certificate
      --postal-code strings            The postal code(s) of the subject of the certificate
      --province strings               The province(s) of the subject of the certificate
      --street-address strings         The street address(s) of the subject of the certificate
      --subject-serial-number string   The serial number of the subject of the certificate

Certificate usage flags:
      --domain strings   Domain names allowed to use the generated certificate
      --email strings    Email addresses allowed to use the generated certificate
      --ip ipSlice       IP addresses allowed to use the generated certificate (default [])
      --uri strings      URI's allowed to use the generated certificate

Key usage flags:
      --key-usage-cert-sign            Use when the subject public key is used to verify a signature on certificates. This extension can be used only in CA certificates.
      --key-usage-content-commitment   Use when the public key is used to verify digital signatures used to provide a non-repudiation service. Non-repudiation protects against the signing entity falsely denying some action (excluding certificate or CRL signing).
      --key-usage-crl-sign             Use when the subject public key is to verify a signature on revocation information, such as a CRL.
      --key-usage-data-encipherment    Use when the public key is used for encrypting user data, other than cryptographic keys.
      --key-usage-decipher-only        Use only when key agreement is also enabled. This enables the public key to be used only for deciphering data while performing key agreement.
      --key-usage-digital-signature    Use when the public key is used with a digital signature mechanism to support security services other than non-repudiation, certificate signing, or CRL signing. A digital signature is often used for entity authentication and data origin authentication with integrity.
      --key-usage-encipher-only        Use only when key agreement is also enabled. This enables the public key to be used only for enciphering data while performing key agreement.
      --key-usage-key-agreement        Use when the sender and receiver of the public key need to derive the key without using encryption. This key can then can be used to encrypt messages between the sender and receiver. Key agreement is typically used with Diffie-Hellman ciphers.
      --key-usage-key-encipherment     Use when a certificate will be used with a protocol that encrypts keys. An example is S/MIME enveloping, where a fast (symmetric) key is encrypted with the public key from the certificate. SSL protocol also performs key encipherment.

Extended key usage flags:
      --ext-key-usage-any
      --ext-key-usage-client-auth
      --ext-key-usage-code-signing
      --ext-key-usage-email-protection
      --ext-key-usage-ipsec-end-system
      --ext-key-usage-ipsec-tunnel
      --ext-key-usage-ipsec-user
      --ext-key-usage-microsoft-commercial-code-signing
      --ext-key-usage-microsoft-kernel-code-signing
      --ext-key-usage-microsoft-server-gated-crypto
      --ext-key-usage-netscape-server-gated-crypto
      --ext-key-usage-ocsp-signing
      --ext-key-usage-server-auth
      --ext-key-usage-time-stamping
```

## Wishlist

- [ ] Support for encrypted private keys
- [ ] Interactive wizard for cert and key generation
- [ ] Security warnings (when using small bit sizes for example)
- [ ] Mistake warnings (generating certificates without common names for example)
- [ ] CSR generation (creating new ones and converting existing certificates)
- [ ] CSR signing
- [ ] Certificate inspection command (Showing the human readable certificate)