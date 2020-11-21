#!/bin/bash

VERSION="0.0.3"
GIT_COMMIT=$(git rev-list -1 HEAD)
GOLANG_VERSION=$(go version | cut -d' ' -f3 -)

go get -u github.com/mitchellh/gox

mkdir -p release

rm -f release/*

gox \
    -osarch="!darwin/386" \
    -ldflags "-X main.TlsToolVersion='$VERSION' \
    -X main.TlsToolCommitHash='$GIT_COMMIT' \
    -X main.TlsToolGolangBuildVersion='$GOLANG_VERSION'" \
    -tags "netgo" \
    -output="release/{{.Dir}}_$VERSION_{{.OS}}_{{.Arch}}"