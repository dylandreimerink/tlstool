# TLSTool

TLSTool is a cli tool to work with X.509 certificates, X.509 certificate singing requests, and private keys. TLSTool is not intended to replace PKI tooling like [OpenSSL](https://www.openssl.org/) and [CFSSL](https://github.com/cloudflare/cfssl). TLSTool is meant to be a more user friendly tool to quickly perform common actions with certificates like generating self signed certificates.

Tools like [OpenSSL](https://www.openssl.org/) and [CFSSL](https://github.com/cloudflare/cfssl) often require you to setup a special environment and/or configuration, which makes sense for actual certificate authorities, but not for one-shot certificates. TLSTool strives to provides all functionality in a user-friendly but less automated way.

## Index

* [Installation](#installation)
  * [Pre-built version](#pre-built-version)
  * [Latest version](#latest-version)
* [Usage](#usage)
  * [Generate a private key](#usage---generate-a-private-key)
  * [Generate a X.509 certificate](#usage---generate-a-x509-certificate)
  * [Show TLSTool version info](#usage---show-tlstool-version)
* [Wishlist](#wishlist)

## Installation

### Pre-built version

1. The latest binaries can be downloaded at https://github.com/dylandreimerink/tlstool/releases. Download the pre-compiled binary suitable for your platform.
2. Locate a suitable directory for your binary, this is dependant on your platform.
    * For Linux and MacOS place the binary in one of the directories found in the output of the `echo $PATH` command. `/usr/local/bin` is recommended.
    * For Windows place the binary in one of the directories found in the `%PATH%` variable. However this may vary depending on the terminal you are using.
3. Make sure the binary has execute permissions if it doesn't have them already
4. Check the installed version by executing `tlstool version`

### Latest version

Requires golang to be set up.
Run `go get -u github.com/dylandreimerink/tlstool`

## Usage

TLSTool has a number of sub-commands that execute specific actions. Every sub-command is interactive by default and will guide users through the process.

Every command has a help section which can be accessed with the `-h` or `--help` flags. By specifying the `--no-interactive` flag, interactive mode is disabled, this is useful when calling TLSTool from scripts.

### Usage - Generate a private key

The `tlstool gen key` command generates a private key ready to be used for X.509 certificate generation and TLS.

Features:

* Can generate [EC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)(Elliptic-curve), [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))(Rivest–Shamir–Adleman), and [ED](https://en.wikipedia.org/wiki/EdDSA)(Edwards-curve) private keys
* Multiple key sizes available, RSA(1024, 2048, 4096, and 8192 bits) and EC(224, 256, 384, and 521 bits)
* Output format can be PEM or DER
* Password encryption for PEM outputs

<details><summary>Flags</summary>

```
Usage:
  tlstool gen key [flags]

Aliases:
  key, private-key

Flags:
  -c, --encryption-cipher string   The cipher used to encrypt the private key (allowed: DES, 3DES, AES128, AES192, AES256(default)) (default "AES256")
  -h, --help                       help for key
  -f, --key-format string          The format of the key on disk(PEM or DER)
  -s, --key-size int               The size of the key in bits. (RSA: 1024, 2048(default), 4096, 8192) (EC: 224, 256(default), 384, 521) (ED: 32(default))
  -t, --key-type string            The type of private key to generated (allowed: RSA(default), EC, ED)
  -o, --output string              Path where the private key will be written to.
  -p, --passphrase string          The passphrase used to encrypt the private key

Global Flags:
      --not-interactive   Disable interactive mode
```

</details>

### Usage - Generate a X.509 certificate

The `tlstool gen cert` generates a X.509 certificate from a existing private key.

Features:

* Outputs a PEM or DER certificate
* Accepts EC, RSA or ED private keys in DER and PEM format
* Can self-sign or sign with a parent certificate
* Has presets for server, client, root-ca, and intermediate-ca certificates
* Supports most common X.509 attributes(Subject, SAN, basic key usage, and extended key usage)

<details><summary>Flags</summary>

```
Usage:
  tlstool gen cert [flags]

Aliases:
  cert, certificate

Flags:
  -e, --ext-usage stringArray                     The allowed extended uses of the certificate.
                                                  Allowed values: (
                                                      'any'               - This certificate may be used for for multiple extended usage, applications should not reject this certificate if is has to many usages
                                                      'server-auth'       - This certificate may be used for TLS WWW server authentication
                                                      'client-auth'       - This certificate may be used for TLS WWW client authentication
                                                      'code-signing'      - This certificate may be used to sign executable code
                                                      'email-protection'  - This certificate may be used to sign emails
                                                      'time-stamping'     - This certificate may be used to bind a hash of a object to a time
                                                      'ocsp-signing'      - This certificate may be used sign OSCP responses
                                                      'x.x.x.x.x.x.x.x.x' - Specify any OID you want to add to the extended-key-usage of the certificate
                                                  )
  -h, --help                                      help for cert
      --is-ca                                     This certificate may be used as a CA
      --max-path-length int                       The maximum length of the certificate chain below this certificate (default -1)
      --not-after string                          The date and time after which this certificate is no longer valid (hh:mm:ss dd:mm:yyyy)
      --not-before string                         The date and time after which the certificate is valid (hh:mm:ss dd:mm:yyyy) (default "now")
      --valid-for duration                        The amount of time the certificate is valid for since valid-after ([xxd][xxh][xxm][xxs], 1d2h3m3s, 120m)
  -o, --output string                             Path where the certificate will be written to.
      --parent-certificate string                 The path to the certificate which will sign this new certificate
      --parent-private-key string                 The path to the private key of the parent certificate
      --parent-private-key-password string        The password (if any) of the private key of the parent certificate
  -p, --preset string                             The preset to use, sane defaults per certificate type.
                                                  Allowed values: (
                                                      'none'                    - No default values, all up to you
                                                      'server-leaf-certificate' - Leaf certificate for use as a server certificate
                                                      'client-leaf-certificate' - Leaf certificate for use as a client certificate
                                                      'root-ca'                 - Root certificate authority certificate
                                                      'intermediate-ca'         - Intermediate certificate authority
                                                  )
  -k, --private-key string                        The path of the private key used to generate the certificate
  -P, --private-key-password string               The password (if any) of the private key
      --san-domain strings                        Subject alternative name - domain names allowed to use the generated certificate
      --san-email strings                         Subject alternative name - email addresses allowed to use the generated certificate
      --san-ip ipSlice                            Subject alternative name - IP addresses allowed to use the generated certificate (default [])
      --san-uri strings                           Subject alternative name - URIs allowed to use the generated certificate
      --serial-number int                         The serial number of the certificate, random by default (default -1)
      --subject-common-name string                The common name field of the subject
      --subject-country stringArray               The county field of the subject
      --subject-locality stringArray              The locality field of the subject
      --subject-organization stringArray          The organization field of the subject
      --subject-organizational-unit stringArray   The organizational unit field of the subject
      --subject-postal-code stringArray           The postal code field of the subject
      --subject-provice stringArray               The province unit field of the subject
      --subject-serial-number string              The serial number field of the subject
      --subject-street-address stringArray        The street address field of the subject
  -u, --usage stringArray                         The allowed uses of the certificate.
                                                  Allowed values: (
                                                      'digital-signature'  - This certificate may be used to create digital signatures other than signing X.509 certs and CRLs
                                                      'content-commitment' - This certificate may be used to created digital signatures for the purposes of non-repudiation(preventing data change) on data other than X.509 certs and CRLs
                                                      'key-encipherment'   - This certificate may be used to encrypt private keys like during the transport of symmetric keys of a TLS Cipher
                                                      'data-encipherment'  - This certificate may be used to encrypt data directly
                                                      'key-agreement'      - This certificate may be used for key agreement (only use by DH public keys)
                                                      'cert-sign'          - This certificate may be used to sign other X.509 certificates
                                                      'crl-sign'           - This certificate may be used to sign CRls (certificate revocation lists)
                                                      'encipher-only'      - This certificate may be used, only to encipher data during key agreement
                                                      'decipher-only'      - This certificate may be used, only to decipher data during key agreement
                                                  )

Global Flags:
      --not-interactive   Disable interactive mode
```

</details>

### Usage - Show TLSTool version

The `tlstool version` command will output the version number of TLSTool in [semver](https://semver.org/) format.
When specifying the `-v` or `--verbose` flag the commit hash and Golang version use to build the binary are also output.

<!-- 
## Examples

TODO -->

## Wishlist

This a list of features or tasks to be added to the project. Sort of a lose backlog/roadmap.

* [ ] Custom OIDs/extentions when generating certificates
* [ ] Security warnings (when using small keys for example)
* [ ] Mistake warnings (generating certificates without common names for example)
* [ ] CSR generation (creating new ones and converting existing certificates)
* [ ] CSR signing
* [X] Inspection command (Showing the human readable certificate, private key, or CSR)
  * Add CSR support to show command
  * Add support for unparsed extentions to show command
* [ ] Format converter (From PEM to DER, Bundle certs in a chain, Unpack/repack pkcs12 archives, ect.)
* [ ] Distribution via package managers
