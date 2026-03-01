package main

import "testing"

func TestVersionStringDevel(t *testing.T) {
	origVersion, origCommit := version, commit
	t.Cleanup(func() { version, commit = origVersion, origCommit })

	version = ""
	commit = ""
	got := versionString()
	want := "spnego-proxy version (devel)"
	if got != want {
		t.Errorf("versionString() = %q, want %q", got, want)
	}
}

func TestVersionStringWithVersion(t *testing.T) {
	origVersion, origCommit := version, commit
	t.Cleanup(func() { version, commit = origVersion, origCommit })

	version = "v0.1.0"
	commit = ""
	got := versionString()
	want := "spnego-proxy version v0.1.0"
	if got != want {
		t.Errorf("versionString() = %q, want %q", got, want)
	}
}

func TestVersionStringFull(t *testing.T) {
	origVersion, origCommit := version, commit
	t.Cleanup(func() { version, commit = origVersion, origCommit })

	version = "v0.1.0"
	commit = "abc1234def5678"
	got := versionString()
	want := "spnego-proxy version v0.1.0 (commit abc1234)"
	if got != want {
		t.Errorf("versionString() = %q, want %q", got, want)
	}
}

func TestVersionStringShortCommit(t *testing.T) {
	origVersion, origCommit := version, commit
	t.Cleanup(func() { version, commit = origVersion, origCommit })

	version = "v0.1.0"
	commit = "abc"
	got := versionString()
	want := "spnego-proxy version v0.1.0 (commit abc)"
	if got != want {
		t.Errorf("versionString() = %q, want %q", got, want)
	}
}
