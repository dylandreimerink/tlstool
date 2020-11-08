#!/bin/bash

VERSION="0.0.3"
GIT_COMMIT=$(git rev-list -1 HEAD)
GOLANG_VERSION=$(go version | cut -d' ' -f3 -)

go get -u github.com/mitchellh/gox

mkdir -p release

rm -f release/*

CGO_ENABLED=0 gox \
    -osarch="!darwin/386" \ # 32-bit darwin is no longer supported in go1.15 https://golang.org/doc/go1.15#darwin
    -output="release/{{.Dir}}_$VERSION_{{.OS}}_{{.Arch}}" \
    -ldflags "-X main.TlsToolVersion=$VERSION" \
    -ldflags "-X main.TlsToolCommitHash=$GIT_COMMIT" \
    -ldflags "-X main.TlsToolGolangBuildVersion=$GOLANG_VERSION"