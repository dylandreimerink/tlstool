# TLSTool

TLSTool is a cli tool to work with X.509 certificates, X.509 certificate singing requests, and private keys. TLSTool is not intended to replace PKI tooling like OpenSSL. TLSTool is meant to be a more user friendly tool to quickly perform common actions with certificates like generating self signed certificates.

Tools like OpenSSL often require you to setup a special environment and configuration, which makes sense for actual certificate authorities. TLSTool provides all functionality without configuration and with optional interactivity.

## Installation

### Stable version

1. The latest binaries can be downloaded at https://github.com/dylandreimerink/tlstool/releases. Download the pre-compiled binary suitable for your platform.
2. Locate a suitable directory for your binary, this is dependant on your platform.
    * For Linux and MacOS place the binary in one of the directories found in the output of the `echo $PATH` command. `/usr/local/bin` is recommended.
    * For Windows place the biary in one of the directories found in the `%PATH%` variable. However this may vary depending on the terminal you are using.
3. Make sure the binary has execute permissions if it doesn't have them already
4. Check the installed version by executing `tlstool version`

### Latest version

Requires golang to be set up.
Run `go get -u github.com/dylandreimerink/tlstool`

## Usage

TODO

## Examples

TODO

## Wishlist

* [ ] Security warnings (when using small bit sizes for example)
* [ ] Mistake warnings (generating certificates without common names for example)
* [ ] CSR generation (creating new ones and converting existing certificates)
* [ ] CSR signing
* [ ] Certificate inspection command (Showing the human readable certificate)
