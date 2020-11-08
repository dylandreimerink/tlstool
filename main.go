package main

import (
	"github.com/dylandreimerink/tlstool/cmd"
)

var (
	TlsToolVersion            = "unknown (not a released version)"
	TlsToolCommitHash         = "unknown (not a released version)"
	TlsToolGolangBuildVersion = "unknown (not a released version)"
)

func main() {
	// Inject linker-time set global version variables
	cmd.TlsToolVersion = TlsToolVersion
	cmd.TlsToolCommitHash = TlsToolCommitHash
	cmd.TlsToolGolangBuildVersion = TlsToolGolangBuildVersion

	cmd.Execute()
}
