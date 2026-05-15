package main

import "fmt"

// version and commit are set at build time via ldflags.
var (
	version = ""
	commit  = ""
)

func versionString() string {
	if version == "" {
		return "spnego-proxy version (devel)"
	}
	if commit == "" {
		return fmt.Sprintf("spnego-proxy version %s", version)
	}
	short := commit
	if len(short) > 7 {
		short = short[:7]
	}
	return fmt.Sprintf("spnego-proxy version %s (commit %s)", version, short)
}
