#!/bin/bash

VERSION="0.0.2"

go get github.com/mitchellh/gox

mkdir -p release

rm -f release/*

CGO_ENABLED=0 gox -output="release/{{.Dir}}_$VERSION_{{.OS}}_{{.Arch}}"